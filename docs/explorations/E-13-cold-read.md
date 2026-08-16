# E-13 — Cold read: kernel data model + control plane + whole design

**Status: Complete. Feeds: 13, 14, 05, 06, 02, 03, 11.**
**Author: exploration agent E-13 (fresh-eyes adversarial read). Date: 2026-08-16.**

## Question

Docs 13 (kernel data model) and 14 (control plane & lifecycle) are the newest
and least-reviewed. Read the entire doc set cold, adversarially: what is
missing, wrong, self-contradictory, unstated-but-load-bearing, or
over-engineered relative to the first deployment? Do not re-report E-01/E-02/
E-03/E-06 findings.

## Method

Full read of docs README + 00–14 in order; skim of E-01 (full threat catalog
IDs), E-02, E-03, E-06 to establish what is already covered. Analysis is
model-checking by hand: for each entity and lifecycle transition in 13/14, ask
"who can write it, what references it, what happens when it's deleted/renamed/
revoked mid-use, and which invariant is supposed to survive that." Cross-doc
consistency pass on every "Decided" claim. No code exists yet; everything here
is a doc-level finding.

Deduplication note: E-01 already owns key concentration (DB-3), mapping-rule
scope containment (K-1), tier-gate-in-serializer (K-2), path prefix/trailing-
slash bugs (K-4), restore rollback (ST-1). Findings below are either new or a
*specific hole in* those controls that survives them as specified.

---

## Findings (ranked)

### F1 — Principals have no identity other than their path: rename is identity
death, delete+recreate is identity resurrection — **HIGH** (top finding)

**What's wrong.** Doc 13: `Principal { id: path … }`. The path *is* the
identity. Every reference in the model — `Binding.subject_ref`,
`Group.members[].principal_ref`, `MappingRule.produces`, `Binding.grantor`,
audit provenance, SPIFFE IDs, KV consumer identities — is therefore a
reference to a *location in the tree*. Two consequences, both unaddressed:

1. **Rename / re-parent is unmodeled.** Move a service between clusters, fix a
   typo in a person's path, reorganize `/fleet` — nothing in 13 or 14 says
   what happens. Either every referencing object must be rewritten atomically
   in one reconcile (unstated), or references dangle. Meanwhile credentials
   already minted carry the old SPIFFE ID until TTL, and the audit trail for
   one real-world identity splits into two unlinkable principals. Doc 11 has
   re-parenting *of a domain* as a first-class ceremony; re-pathing *a
   principal* — a far more common operation — has no home at all.
2. **Delete + recreate at the same path = silent privilege inheritance.** A
   new principal created at `/people/bob` (new hire, same username;
   reconciler-driven delete+add, which is exactly what a git rename produces)
   inherits every binding, group membership, and mapping rule that still
   targets that path. This is the precise failure class SIDs (never-reused,
   AD), Zanzibar tuple IDs, and k8s UIDs exist to prevent. ST-1's tombstones
   protect against *restore* resurrecting state; nothing protects against
   *live* path reuse resurrecting authority.

**Concrete scenario.** Delegated admin of `/clusters/lab` deletes workload
principal `/clusters/lab/apps/runner` (bindings elsewhere reference it as a
group member). Weeks later anyone able to create principals under that path
recreates it — and the stale group membership and any binding by
`subject_ref` light up again. No write to any authorization object occurred;
no narrows check fires; audit shows only a principal create.

**Fix.** Give every entity a stable, never-reused internal ID (UUID or
domain-scoped serial); the path becomes a unique, mutable *name* attribute.
All internal references (bindings, memberships, mapping-rule `produces`,
grantor, audit) bind to the ID; the path is resolved at issuance for scope
math and SPIFFE serialization. Deleting a principal tombstones the ID;
recreating the path mints a new ID, and dangling ID references are inert by
construction. Specify rename as a first-class, audited operation (and decide:
do outstanding credentials for the old path get killed at next renewal?
Answer should be yes — renewal re-resolves path from ID). This is a ~10-line
change to doc 13 now and a schema migration nightmare after the first
vertical slice.

### F2 — Group-membership writes are an ungoverned privilege-escalation
channel; delegation-only-narrows has a group-shaped hole — **HIGH**

**What's wrong.** The narrows invariant (05/13, property-tested per 10) is:
*no sequence of grants by admin-of-S yields a credential valid outside S*.
It is enforced on Binding writes and MappingRule writes (K-1). But
**membership writes are also grant writes**, and no doc says who may edit a
group's member list or what constraint applies. A group is "a Principal of
kind=group" living at some path; its *bindings* may be at completely
different scopes.

**Concrete scenario.** Group `/clusters/lab/oncall` is created by the lab
admin. Later, `mcarey` (root admin) binds that group to `secrets-reader` at
`/` because on-call needs broad read during incidents. From that moment, the
lab admin — who can presumably edit members of a group in their own subtree —
can add any principal to the group and thereby grant scope-`/` rights. No
Binding write occurred; the narrows check as specified never runs. This is
the AD "control of a nested group = control of everything it's ever been
granted" trap, which doc 13's "four graphs" section correctly diagnoses in AD
and then reintroduces via `kind=group`.

**Fix (pick one, state it in 13).** Options in increasing strictness:
(a) membership writes are authorization-bearing writes requiring authority
over **every scope the group is currently bound at** (correct, needs a
reverse index binding→group, and makes some bindings freeze a group's
editors); (b) binding a group at scope S is only legal if the group's path is
at or below S's *editor* boundary — i.e. you may only bind groups whose
membership is controlled by admins at-or-above the binding scope (cheap
write-time check, kills the cross-subtree group reuse pattern);
(c) memberships carry the grantor + narrows check exactly like bindings, and
the effective grant of (member M via group G bound at S) is checked at
issuance as if grantor(membership) had granted M the role at S directly. (c)
is most consistent with "re-checked at issuance" and needs no new machinery.
Whatever the answer, the 10 property test must be extended: *no sequence of
grants **and membership edits** by admin-of-S yields a credential valid
outside S*. Right now the flagship invariant is tested against half the
write surface.

### F3 — Tier lives on the Binding, so a second binding is a tier downgrade:
K-2 re-enters through the data model — **HIGH**

**What's wrong.** Doc 06 (Decided): freshness tier is selected "per role (at
scope)" and tier-3 embedding is "structurally impossible." Doc 13:
`Binding.conditions` carries "tier (06)". These compose badly: if tier is a
per-binding condition and grants are additive-only, then two bindings for the
same role at overlapping scope with different tiers must union — and the
union of {tier-3} and {tier-1} is tier-1. A delegated admin of S who is
allowed to create bindings for role R below S can create a *second, tier-1*
binding for a role that security policy intended to be tier-3, and the
central tier gate (which per 06 filters based on the role's tier) has no
single authoritative place to read the tier from. K-2 closed the serializer
bypass; the data model reopens the gate's *input*.

**Concrete scenario.** `vault-admin` is bound tier-4 at `/`. Lab admin is
delegated `/clusters/lab` and legitimately allowed to bind roles there. They
bind `vault-admin` at `/clusters/lab` with `conditions: {tier: 1}`. At
issuance for a principal in lab scope, the kernel sees an additive grant with
no step-up condition. If the mint path takes the most-permissive applicable
binding, the tier-4 protection is gone for that subtree — silently, via a
write that passes the narrows check (it *is* at or below S).

**Fix.** Tier (and any security-floor condition) must be a property of the
**role**, not the binding — add it to `Role` or introduce a `RolePolicy`
object owned at the role's definition scope, writable only by the role's
owner. Bindings may *raise* requirements (extra amr, shorter TTL), never
lower them: conditions compose by **strictest-wins**, stated explicitly in 13
next to "grants are additive only" (rights are additive; *constraints on a
given role are not*). Add a named property test: *no binding write can lower
the effective tier of any role anywhere.* Doc 05's open question "do roles
carry structured attributes" is actually already answered by 06 — the tier is
a role attribute — and should be closed accordingly.

### F4 — Grantor lifecycle is unspecified: what does "re-checked at issuance"
check, and what happens to a revoked admin's grants? — **HIGH**

**What's wrong.** Every authorization write records `grantor` and is
"enforced at write time *and* re-checked at issuance" (13, 05, 04). Re-checked
against *what*? Two readings, both with sharp edges, and no doc picks one:

- **Current authority**: at each mint, verify grantor still holds admin at
  the binding's scope. Then removing one delegated admin (offboarding,
  compromise response) instantly invalidates every binding/mapping they ever
  authored — a cascading availability event with no plan/dry-run (the
  reconciler diff shows one binding removed, not the hundred grants that die
  with it). Also transitively recursive: the grantor's own authority came
  from a binding with a grantor…
- **Write-time authority**: the check is a historical fact; then a compromised
  delegated admin's planted grants **survive their revocation** — the ESC4
  persistence pattern, and precisely the case where you most need cleanup.

**Fix.** State the semantics in 13. Recommended: write-time validity is
authoritative for the binding's *existence* (no cascade), plus a required
operational affordance: revoking any principal's admin binding produces an
audit-driven report/quarantine list of every extant object they authored
(`grantor` index), for human review — and a `--revoke-grants` cascade option
for the compromise case. Also specify: what happens to `grantor` when the
grantor principal is deleted (with F1's stable IDs: reference stays valid,
resolves to tombstone — fine; without them it dangles). And define whether
the issuance-time re-check re-validates *scope containment only* (cheap,
stateless — recommended and probably what was meant) vs grantor authority;
today's text lets a reader assume either.

### F5 — Global tree or per-domain trees? The docs support both readings, and
the narrows check differs under each — **HIGH**

**What's wrong.** Doc 05: "`mcarey` holds `infra-admin` at `/`" — one global
tree. Doc 02/04: principals are `spiffe://<trust-domain>/<path>` — paths are
per-trust-domain namespaces. Doc 13: roles are "namespaced to a domain," the
child "stores only its own subtree" and *imports* parent references — per-
domain trees with explicit stitching. Doc 14: "a domain's declared config
cannot grant scope above the domain" — implying domains occupy positions in
one shared tree with a boundary. Never stated: what does scope `/` **mean**
inside child domain `home`? Is it the domain root (so the root-domain admin
has *no* authority in `home` unless `home` imports a binding), or the org
root (so `home` cannot even represent it, per 14's rule)? When `mcarey` (a
`/people/*` principal — in *which* domain's tree?) authenticates to the
`home` domain to reconcile config, which tree does the narrows check walk?

**Why it matters.** The two readings give different security properties: a
global tree makes parent authority *implicit* (contradicting 13's "imports
what it chooses to honor"); per-domain trees make 05's flagship example
literally inexpressible without the import machinery, which is deferred to
E-12. Every property test in 10 needs to know which model it's testing.
This is a classic designers-can't-see-it gap: each doc is locally coherent
because each author held one model in mind.

**Fix.** One paragraph in 13, normative: (proposed) *each domain owns one
rooted tree; `/` is domain-relative; cross-domain authority exists only as an
imported, signed parent-slice reference (subordinate mode) or federation
artifact (peer); doc 05's example means "infra-admin at `/` of the `home`
domain."* Then fix 05's wording, and state what the plan-time check in 14
does when a config references a path that is above the domain (reject) vs in
a peer domain (must resolve via TrustLink).

### F6 — Genesis leaves the root key in the Raft log and generation-0
backups; genesis crash semantics undefined — **HIGH**

**What's wrong.** Doc 14: genesis mode has the "root key live in-process."
Doc 03: mutations are barrier-encrypted before `raft.Apply`, the Raft log IS
the WAL, and backup segments ship continuously (~10 s). Nobody states where
the genesis root key *persists*. Two failure modes:

1. **If it's written to state (any bucket)**, it entered the Raft log and the
   backup stream. Generations are immutable, create-only objects in S3/GCS/
   NFS. "Seal genesis, enter operational" can delete the live copy, but every
   backup of generation 0 contains the domain root key (barrier-encrypted —
   but the barrier key is exactly what an RCE or seal compromise yields, and
   "root is offline" is then permanently false in the DR chain). The
   transition ceremony must force a **generation break + verified destruction
   of pre-seal generations**, or the root must never touch the store at all.
2. **If it's memory-only**, then a genesis-node crash before the sealing
   ceremony loses the domain root — annoying but recoverable only by
   restarting genesis, which is fine *if stated*; but then "mint first
   intermediate + first admin" must all be idempotently re-runnable, and any
   child that already pinned the lost root must be re-bootstrapped.

Doc 14 says "the risk is lingering in genesis posture" — true, but the
*mechanical* risk above is different and unmentioned. Related unstated item:
the **first admin bootstrap** — before any WebAuthn credential or mapping
rule exists, what evidence authorizes the CLI performing genesis? (Local
process identity / filesystem access, presumably — say so, because it defines
the genesis trust boundary: anyone who can run the binary against the empty
data dir at that moment owns the domain forever.)

**Fix.** Doc 14 must specify: root keypair generated where (ideally: in the
ceremony tool, never persisted to the FSM; only the root *cert* and the first
intermediate enter state); what survives a genesis crash; and that
operational-mode entry verifies "no root private material in store or in any
retained backup generation" as a checked postcondition, not a hope. Ties to
E-09 (seal ceremonies) — add it to that mission's brief.

### F7 — The reconciler cannot enforce delegation-narrows without
authenticated authorship, and TrustLink writes escape the narrows model
entirely — **HIGH**

**What's wrong.** Doc 14 (Decided): "a delegated admin's commits cannot
exceed their subtree — checked at plan time." Plan-time enforcement requires
knowing **which principal authored which part of the diff**. Git commits are
not authenticated identities; a GitOps pipe delivers a repo state, not a
principal. Options — signed commits mapped to principals, per-subtree repos
with per-repo deploy credentials, or "the reconciler runs as the API caller
and the whole diff is checked against *that* principal" — have very different
properties, and none is chosen. Under the last (most likely) reading, a
shared config repo means every merge is effectively applied with the
*applier's* authority — so the narrows check protects nothing about
delegation *within* the repo; repo write access becomes the real (and
invisible) authorization boundary.

Sharper version: **TrustLinks and mapping rules are in the declarative
surface** (14). A TrustLink write (add a peer anchor, change a child's mode)
is scope-*above*-everything — no subtree containment can authorize it, so the
reconciler needs a distinct rule ("trust-graph writes require domain-owner +
step-up") that no doc states. Net effect today: **compromise of the config
repo (or its CI deploy credential) = trust-anchor injection + arbitrary
mapping rules**, i.e. the repo is a tier-0 asset, unlisted in doc 01's asset
inventory.

Secondary gaps, same family: plan/apply TOCTOU (plan validated against state
X, applied over state Y — require optimistic concurrency on a state serial);
imperative-vs-declarative writes (can an admin create a binding via API? does
the reconciler prune it as drift? JIT activations are exempt as runtime state
— but *bindings* created by break-glass ceremonies are desired-state-shaped
and will be fought by the reconciler unless a policy exists); and
**deletion cascade** (removing a principal from git: do their live sessions
die immediately or at next renewal? do bindings referencing them fail plan,
or tombstone?).

**Fix.** Doc 14 needs an "authorship & authority" section: how a diff is
attributed to principals, what authority the apply runs with, the special
rule for trust-graph writes (owner + tier-4 recommended), the concurrency
token, and the drift policy for imperative writes. Add the config repo / its
deploy credential to doc 01's assets. None of this is exotic — but every line
of it is currently assumed.

### F8 — The KV authorization mapping — the actual success criterion — is
specified nowhere — **MED-HIGH**

**What's wrong.** The charter's success criterion is "ESO reads a secret."
Chase that end-to-end through the docs: ESO logs in via `k8s-sa` (04, solid),
becomes principal `/clusters/svc/apps/eso`, holds `secrets-reader` at
`/clusters/svc/` (05's example). Then it calls the Vault dialect for
`cluster-svc/apps/litellm`. Now: (a) how do **KV secret paths map into the
resource tree** — is a secret a node at `/clusters/svc/…`? is the Vault-mount
path prefix (E-06 delegation record "KV mount prefixes") the same namespace
as principal paths, with the same canonicalization? (b) what does
`secrets-reader` *mean* — which role names does the KV dialect honor, and
where is role→(get/put/list/delete/destroy/metadata) defined? Doc 05's narrow
waist says every RP owns its own role→permission mapping and Signet's own
dialects are RPs "of the same kernel check" — so the KV dialect has a config
mapping roles to KV verbs *somewhere*, and that somewhere appears in no doc,
not even as an open question. (c) is that mapping declarative (14) or dialect
config? (d) can a binding scope a role to a *sub*-path of a secret tree
(per-app secrets isolation — the thing the homelab actually does today with
per-app OpenBao paths)?

This is the emperor's-clothes observation in miniature: the doc set specifies
PQC composite root signatures and CONIKS options in detail, but the read-path
authorization for the very first secret is four unanswered questions.

**Fix.** A short "KV dialect authorization" section (07 or 13): secrets are
tree nodes (recommended — scope machinery applies for free, and per-subtree
DEKs in 11 already assume subtree structure); reserved well-known roles
(`kv-reader`, `kv-writer`, `kv-admin`) with fixed verb sets in v1 (narrow
waist preserved: they're Signet-dialect-owned mappings, same as Grafana
owning `infra-admin → Admin`); Vault mount/path prefix → tree path mapping
defined next to the E-06 compat table.

### F9 — The runtime half of the model is unmodeled: no Activation, Session,
or IssuedCredential entities; activation-vs-eligibility revocation semantics
implicit — **MED-HIGH**

**What's wrong.** Doc 13 declares desired-vs-runtime the load-bearing split,
then models only the desired half. The runtime objects the design *depends
on* have no schema: **Session** (what fields — sender-binding key ref, amr,
auth_time, upstream verifier, kill flag?), **Activation** (requester, which
binding, approver(s), step-up evidence, expiry, revocation), **issued-
credential / opaque-ref records** (tier-3 introspection *requires* a lookup
store; RFC 7662 responses need it; AG-3's DPoP `jti` replay cache is another
runtime store), **join-token single-use records**, **bundle epoch counters**
(FED-1 requires persisted monotonic state — desired or runtime?). These all
live in the FSM (03 says "sessions/leases as bbolt buckets") but the "kernel
data model" doc that "every property test asserts against" doesn't contain
them, so the property tests for JIT/PAM cannot be written from the docs.

Specific unstated semantics that must be pinned (each is a classic bug):
- **Activation duration vs role-TTL**: is an activation a grant window
  (e.g. 1 h) within which 15-min role creds renew, or a single short-TTL
  credential? If a window: does each renewal inside it re-check the
  *underlying binding still exists*? (It must — else deleting the eligibility
  doesn't stop an in-flight activation until the window ends. State: renewal
  re-validates activation record AND its binding; either vanishing kills at
  next renewal; plus a server-side activation-kill that also revokes the
  session-side path, mirroring session kill.)
- **Activation cap at `not_after`**: activation expiry and every credential
  minted under it must be clamped to the binding's/membership's `not_after`
  (JIT-on-JIT). One sentence, prevents the "eligible until Friday, activated
  Thursday 23:59 for 4 h" leak.
- **Approval race**: eligibility modified between request and approval —
  grant must re-validate the binding at *grant* time, not request time.
- **Step-up transaction binding**: the tier-4 WebAuthn assertion for an
  activation must be bound to *that* activation request (challenge carries
  request hash), or a prompt-fatigued user's touch for activation A is
  relayed to approve activation B. E-01 AT-5 covers WebAuthn hygiene
  generally; per-transaction binding for activations/approvals is new
  surface — say it in 14's "JIT activation API shape" open question so it
  can't be forgotten.

**Fix.** Add a "Runtime entities" section to 13 (schemas for Session,
Activation, IssuedCredentialRef, JoinTokenUse, BundleEpoch), plus the four
semantic rules above. Doc 14's open questions on activation API/approvals
remain legitimately open — but the *revocation semantics* must not be, since
they're the security half.

### F10 — MappingRule conflict semantics: two rules, one evidence, two
principals — **MED**

Doc 04/13 give MappingRule a matcher and a produced principal, and K-1 scopes
what it may produce. Unstated: what happens when **multiple rules match the
same evidence**? First-match implies rule *ordering*, which implies a total
order across rules written by different delegated admins — an escalation
surface of its own (whoever sorts earlier wins; classic firewall-rule
politics) and nondeterministic under reconciliation unless ordering is
explicit. All-match implies one evidence → multiple candidate principals —
then which session? **Recommended**: unique-match-or-fail-closed (ambiguity
is an error at plan time when statically detectable, and at login otherwise,
loudly audited). Also: `evidence_matcher` with "claims… pattern" —
constrain the matcher language now (exact-match on enumerated fields;
no regex in v1) or it becomes a policy engine through the back door — the
same ABAC-creep vector doc 13 worries about for `attributes`, but on the
*authentication* path where bugs are worse. Related deliberate-deferral that
should be recorded as such: no templated rules in v1 (one rule per fleet
host is fine at homelab scale; when templating arrives, the K-1 check must
validate the template's *range*, not an instance — write that sentence in 04
now so it's inherited later).

### F11 — Path canonicalization is asserted, not defined — **MED (cheap fix)**

E-01 K-4 fixed substring/prefix and trailing-slash. Still undefined: the
**character set and normalization rules** for path components. Unicode
(NFC vs NFD — macOS filesystems hand you NFD; `/people/andré` in two
encodings is two principals and one displayed name), case sensitivity
(`/Clusters` vs `/clusters` — Go's x509 constraint code had exactly this bug
class, CVE-2026-33810 cited in E-01), empty components (`//`), `.`/`..`
segments, length/depth caps (a 10k-component path in a claim), and SPIFFE
compatibility (doc 04 requires every principal path to serialize as a SPIFFE
ID — the SPIFFE spec's path grammar is `[a-zA-Z0-9._-]` per segment, no
empty segments, no `.`/`..`; if Signet doesn't adopt an equal-or-stricter
grammar, some principals will be unrepresentable in the X.509 dialect and
comparisons may disagree between the kernel and the SPIFFE layer).
**Fix**: adopt SPIFFE's segment grammar (lowercase-only recommended) as the
*kernel* path grammar, reject everything else at write time, one normative
paragraph in 13. Kills unicode confusables, case bugs, and dialect mismatch
in one move.

### F12 — Additive-only: right call, but name the boundary story — **LOW-MED**

"Admin everywhere except this subtree" is inexpressible; so is a compliance
wall ("nothing outside `/hr` may ever read `/secrets/hr`, regardless of
future bindings at `/`"). k8s RBAC proves additive-only is livable, and the
docs' local-reasoning argument is correct — this is a defensible Decided.
But two things should be written down: (a) the recommended pattern (bind at
the siblings you mean, accept that new siblings under a broad grant are
included — note this is *fail-open on tree growth* for broad grants, the one
real cost); (b) explicitly reject (or defer with rationale) the
"inheritance-barrier node" alternative (AD block-inheritance, GCP's absent
equivalent) — someone will propose it in an issue within a month of open-
sourcing, and the answer belongs in 05's Reconsideration section, not a
maintainer's memory. Also state that the *escape hatch* for the HR case is
domain topology: a separate (sub)domain is the deny boundary the model does
offer.

### F13 — Write-volume story contradicts itself quietly — **MED at scale,
LOW for homelab**

E-03 chose bbolt partly on "a no-write-volume system." But: every issuance is
an append to the parent-auditable issuance log (02), every policy decision is
an audit event (11), sessions/activations/jti-replay entries are FSM writes,
and 06 makes ~15-min renewal of *every workload credential* the propagation
mechanism. At homelab scale (a few hundred principals) this is trivially
fine. At the org scale docs 02/13 design for (delegated admins, PIM,
federation), the write rate is `principals × dialects / 15 min` × (issuance
log + audit + session churn) through a single-writer Raft apply loop on
"Celeron-class" targets — the scaling cliff is real and unacknowledged.
**Fix**: one honest paragraph in 03: the design point is O(1k) principals per
domain; the intended scale-out axis is *more domains*, not bigger ones (this
is arguably the architecture's actual answer — say it); and the issuance/
audit log needs a retention/compaction policy (currently unbounded growth in
state.db — the parent reviews ~30 days at renewal, so that's the natural
floor; nothing says so).

### F14 — Small cross-doc contradictions & drift — **LOW (housekeeping)**

- **05 vs 13**: 05's open questions "role nesting? deny? role attributes?"
  are all now answered by 13 (flat roles, additive-only restated as decided,
  and — per F3 — tier-as-role-attribute should close the third). 05 was not
  updated; a cold reader can't tell which doc wins. Update 05's status/open
  list to point at 13.
- **02 vs 14 trust config**: 02 says a node's trust config is a minimal
  file and "everything else is derived, not configured"; 14 puts trust links
  in the declarative reconciled surface. Both can be true (node-local
  bootstrap file vs domain-level trust *graph*) but the boundary is nowhere
  drawn — and F7's TrustLink-authority question lives exactly on that line.
- **Role names at shared RPs**: roles are domain-namespaced (13) but the
  serialized claim is a bare label (`groups: [infra-admin]`). An RP trusting
  two Signet domains (or Signet + anything else) must scope its role→
  permission map per issuer, or `infra-admin` from the `aws` child grants
  Grafana-admin issued for `home`. This is the DB-2 "config boundary" doing
  authorization work again — one sentence in 05's narrow-waist section
  ("RP mappings MUST be per-issuer") and it's handled.
- **README index** lists 13/14 as Draft — correct — but 14 contains four
  "(Decided)" headings; per the status legend those are Reconsideration-
  gated. Either the doc is Draft (headings overstate) or the decisions are
  real (index understates). Pick one; it matters for whether this report's
  F3/F7 require formal reconsideration cases.

### F15 — Right-sized or over-engineered? Verdict: right-sized skeleton,
over-specified periphery, under-specified core — **assessment, not a defect**

The honest emperor's-clothes answer: **no, a materially simpler design would
not meet the stated requirements** — the requirements themselves (charter)
include SSO + PKI + Vault-compat + partition tolerance, and the chosen core
(one binary, one Raft group, bbolt, ~15 Vault routes, OIDC, SSH CA, RBAC
tree) is close to the minimum honest implementation of that. E-06's compat
line and 08's "k8s needs no agent" are genuinely restrained. The sequencing
in 14 (MVP vertical slice on `home` single-node before any fabric) is the
right guard.

But the *attention distribution* is inverted relative to the first
deployment, and that's where drift risk lives:

- **Deliberately deferred and fine**: SAML, sovereign-mode hardenings
  (self-certifying names, KT logs, FROST), PQC composite roots (design-room
  only), SCIM/LDAP, OS logon. All correctly gated.
- **Over-weighted for v1**: the four-domain fabric (root + home/aws/gcp with
  a sovereign conversion) is a federation *test rig* the homelab does not
  need — today one OpenBao serves everything; keep it in the plan but resist
  building it before ESO-reads-a-secret ships. JIT/PAM ("falls out of the
  model" is true for the *data model*; the activation API + step-up + 
  approvals is a real subsystem with, per F9, its hardest semantics still
  unwritten) has zero v1 consumers in a one-human homelab. Tiers 3/4
  likewise have no homelab RP that will introspect or step-up except
  Signet's own admin API — which is the right first (and only) v1 consumer;
  say that, and don't build RFC 9470 client machinery in v1.
- **Under-weighted for v1** (the actual gaps this report exists for): KV
  authorization mapping (F8), principal identity/rename/delete (F1), group
  write governance (F2), reconciler authorship (F7) — all of which sit
  directly on the ESO-reads-a-secret and admin-does-a-thing paths.

---

## Top issues that should change a doc before implementation

1. **F1 → doc 13**: stable internal IDs; path = mutable name; delete/rename
   semantics. (Schema-level; painful to retrofit.)
2. **F3 → docs 13 + 06 + 05**: tier is a Role/RolePolicy attribute;
   conditions compose strictest-wins; new named property test.
3. **F2 → docs 13 + 05 + 10**: membership writes are grant writes; pick the
   enforcement rule; extend the flagship property test to membership edits.
4. **F5 → doc 13**: one normative paragraph — per-domain trees,
   domain-relative `/`, cross-domain authority only by explicit import;
   align 05's example.
5. **F7 → docs 14 + 01**: authorship & authority section for the reconciler;
   TrustLink write rule; config repo added to asset inventory.
6. **F6 → docs 14 + 11/E-09 brief**: genesis root-key persistence rule,
   crash semantics, generation-0 backup destruction as a checked
   postcondition.
7. **F4 → doc 13**: grantor re-check semantics (recommend: write-time
   authority + scope-containment at issuance + revoked-admin grant-review
   tooling).
8. **F8 → doc 07 or 13**: KV path↔tree mapping + reserved KV roles — this
   one blocks the vertical slice directly.
9. **F9 → docs 13 + 14**: runtime entity schemas + the four activation
   semantic rules (renewal re-checks binding; clamp to not_after; approve-
   time re-validation; transaction-bound step-up).
10. **F11 → doc 13**: adopt the SPIFFE path grammar as the kernel path
    grammar. Cheapest fix with the highest bug-class kill ratio in this list.

Nothing found is **design-breaking**: no finding invalidates the kernel
shape, the storage bet, the dialect strategy, or the trust topology. F1–F7
are all specification holes that become expensive after the first schema and
reconciler code exist — which is exactly the window we're in.

## What's solid (calibration)

- The **session/role split + renewal-as-policy-eval** (06) is genuinely
  elegant; it makes revocation, JIT expiry, and grant propagation one
  mechanism, and the docs never overclaim it (TTL windows are stated).
- **Issuer-side enforcement as the spine** (post-E-01/E-02 corrections) is
  honest and consistently applied; the DB-1 sovereignty correction is written
  with rare candor for a design doc.
- **E-06's compat line** is a model of evidence-based scoping; the bug-compat
  traps → named conformance fixtures pipeline (10) is exactly right.
- **Storage/backup design** (03) is coherent end-to-end; NFS-target-only,
  anti-rollback tombstones, and the barrier layering hold up under this read.
- **Desired-vs-runtime split** (13/14) is the correct cut — the gaps found
  (F9) are about it being *incomplete*, not wrong; "sudo never requires a git
  push" is the right north star.
- **Four-graphs separation** (13) correctly diagnoses the AD failure and the
  cross-domain reference model (explicit, signed, non-transitive imports) is
  the right antidote — F2/F5 are holes *in* it, not arguments against it.

## Confidence

**High** on F1–F9 as genuine specification gaps: each is grounded in a
concrete reading of the current text and a named failure scenario, and each
maps to a known bug class in prior art (SID reuse, AD group nesting, ESC4
persistence, PIM activation semantics, GitOps authorship). **Medium** on the
severity ordering between F5/F6/F7 — plausibly the designers hold consistent
unwritten answers (especially F5); the finding is then "unwritten," not
"wrong," and the fix is still one paragraph each. **Medium** on F13's cliff
placement (no measurements; homelab-safe regardless). F15's verdict would
change if the first deployment's scope grows (e.g., real multi-org
federation earlier than planned) — then the "over-weighted" items graduate
to on-path. What would most change this report: a decided answer to F5 that
contradicts my proposed reading — several downstream findings (F7 authority
walk, F2 option-space) would need re-derivation against the global-tree
model.
