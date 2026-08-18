# 13 — Kernel data model

**Status: Draft** (designed 2026-08-16; hardened by cold-read E-13; pending
first-vertical-slice validation)
Cold-read: [explorations/E-13-cold-read.md](explorations/E-13-cold-read.md)

The kernel is what every dialect serializes over and every property test
asserts against — so it is specified here concretely, not hand-waved.

## Four graphs, not one (the AD lesson)

Active Directory conflates four distinct structures into one replicated
directory with automatic transitive trust — which is precisely why a *forest*,
not a *domain*, becomes AD's security boundary. Signet keeps them separate so
the **domain** stays the blast-radius boundary (charter / E-01):

1. **Resource tree** — the hierarchical namespace (`/clusters/svc/apps/eso`)
   where roles bind and scope is defined.
2. **Principal set** — the identities that can hold credentials.
3. **Authorization set** — role definitions + bindings.
4. **Trust graph** — which domains trust which, and how (02).

## One tree per domain; `/` is domain-relative (E-13 F5, normative)

**Each domain owns exactly one rooted resource tree.** `/` means *that
domain's* root. `mcarey holds infra-admin at /` means "at `/` of the `home`
domain." Cross-domain authority does **not** exist implicitly: it exists only
as an **imported, signed parent-slice reference** (subordinate mode) or a
**federation artifact** (peer mode) — see "Cross-domain references" below. A
declared config referencing a path *above* its domain is rejected at plan time
(14); a reference into a *peer* domain must resolve via a TrustLink.

## Identity is stable; path is a mutable name (E-13 F1, normative)

Every entity has a **stable, never-reused internal ID** (domain-scoped
serial/UUID). The **path is a unique, mutable *name*** attribute, not the
identity. All internal references (bindings, memberships, mapping-rule outputs,
grantor, audit provenance) bind to the **ID**; the path is resolved at issuance
for scope math and SPIFFE serialization. Consequences, all required:

- **Rename / re-parent** is a first-class audited operation: change the name,
  ID and all references are untouched. Outstanding credentials carry the old
  SPIFFE ID until TTL; renewal re-resolves path from ID, so a rename **kills
  old-path credentials at next renewal** (state this; it's the correct answer).
- **Delete + recreate at the same path mints a NEW ID.** Stale references to
  the deleted ID are inert by construction — no silent privilege resurrection
  (the SID-reuse / k8s-UID bug class). Deletion tombstones the ID.

## Path grammar (E-13 F11, normative)

Kernel paths adopt the **SPIFFE segment grammar** — segments of
`[a-z0-9._-]`, no empty segments, no `.`/`..`, bounded depth/length — so every
principal serializes losslessly to a SPIFFE ID in the X.509 dialect and the
kernel and SPIFFE layers can never disagree. Lowercase-only. Everything else is
rejected at write time. This kills unicode-confusable (NFC/NFD), case
(`/Clusters` vs `/clusters`), and empty-component (`//`) bugs in one move.
Comparison remains **component-wise prefix**, never substring
(`/clusters/lab` ≠ `/clusters/lab-2`); grants are **additive only** (below).

## Entities (desired state)

```
Principal   { id: stable-id                # never reused
              path: name                   # /people/mcarey — mutable, unique
              kind                         # human|service|machine|workload|group|domain
              home_domain
              credential_refs              # attestation anchors / keys
              attributes }                 # non-authoritative metadata ONLY (see ABAC note)

Group       # a Principal of kind=group; MEMBERSHIP is a grant write (F2)
            { members: [ { principal_ref: id, grantor, not_before?, not_after? } ] }

Role        { name; domain; description
              policy_ref }                 # -> RolePolicy (security floor lives HERE, not on bindings)

RolePolicy  { role
              min_tier                     # 1..4 freshness floor (06) — a ROLE attribute (F3)
              required_amr?                # e.g. hardware factor
              max_ttl?                     # ceiling
              owner_scope }                # writable only by the role's owner

Binding     { subject_ref: id             # Principal or Group (may be cross-domain import)
              role
              scope: path                  # binds here, inherits DOWNWARD
              add_conditions               # may only RAISE requirements (strictest-wins, F3)
              grantor: id                  # subject to delegation-narrows
              not_before?, not_after?      # time-bound => JIT
              activation_required? }       # true => eligible-not-active (PAM)

MappingRule { verifier; evidence_matcher   # exact-match on enumerated claims; NO regex in v1 (F10)
              produces: principal_ref
              grantor; constraints }       # scoped to author's subtree (E-01 K-1)

TrustLink   { kind: parent|child|peer; target_domain
              mode: subordinate|sovereign; anchors/cross_cert }
```

## Grants, constraints, and the tier floor (E-13 F3, normative)

- **Rights are additive** (union of applicable bindings) — preserves local
  reasoning; no first-class deny.
- **Constraints on a role are NOT additive — strictest-wins.** The freshness
  tier and other security floors live on **RolePolicy** (a role attribute),
  writable only by the role's owner. A Binding's `add_conditions` may only
  *raise* requirements (more amr, shorter TTL), never lower them. So a
  second, weaker binding for a tier-4 role **cannot** downgrade it — closing
  the K-2 gate's data-model input. Named property test: *no binding or
  membership write can lower the effective tier/floor of any role anywhere.*

## Delegation-only-narrows covers ALL grant writes (E-13 F2, normative)

Bindings, mapping rules, **and group-membership edits** are authorization-
bearing writes. The invariant — *no sequence of grants **and membership edits**
by admin-of-S yields a credential valid outside S* — is enforced on all three.
Concretely for membership (the AD nested-group trap): the effective grant of
*(member M via group G bound at scope S)* is re-checked at issuance **as if
`grantor(membership)` had granted M the role at S directly** — so adding a
member to a group that someone else bound at `/` requires authority at `/`,
not merely at the group's own path. The flagship property test (10) is
extended to membership edits.

## Grantor lifecycle (E-13 F4, normative)

- **Write-time authority is authoritative for a binding's existence** — no
  cascade: revoking a delegated admin does *not* silently invalidate every
  grant they made (that would be an unplanned availability event).
- **Issuance-time re-check validates scope-containment only** (cheap,
  stateless) — not live grantor authority.
- **Revoking an admin produces a `grantor`-indexed review/quarantine report**
  of every object they authored, for human review, plus a `--revoke-grants`
  cascade for the compromise (ESC4-persistence) case.

## Cross-domain references: explicit, signed — never transitive

Offered **only in subordinate mode**, as **reference, not replication or
automatic transitive trust**: the child stores only its own subtree; a binding
may reference a parent principal/role/group, resolved against a **cached,
signed slice of the parent's graph** (offline-capable). The child imports what
it chooses; a compromised `aws` child cannot assert rights up at `home` or
sideways at `gcp`. Sovereign children import nothing implicitly (they federate
as peers, 02). Slice format + staleness policy → E-12.

## JIT / PAM fall out of the model — no new machinery

Every ~15-min renewal re-evaluates policy (06), so:

- **JIT / time-bounded** — `not_after` on a Binding **or** a Group membership
  (both). The grant stops being minted after T; no sweep.
- **Role-sudo / PAM (eligible-vs-active)** — `activation_required: true` makes
  a principal *eligible* without *holding* the role; activation is a **runtime
  request** granted only with step-up + optional approval (Azure-PIM split).

**Narrow waist preserved:** membership and eligibility resolve **server-side
into the flat role-claim set at issuance**; the RP sees only
`groups: [infra-admin]`. The issuance log records the resolved set **and the
why** (binding / activation / approval).

## Runtime entities (E-13 F9 — the other half of the model)

Dynamic state; **never declarative** (not in git). Lives in the FSM (03).

```
Session          { principal_ref: id; sender_binding_key_ref; amr; auth_time;
                   upstream_verifier; expiry; killed? }
Activation       { requester: id; binding_ref; approver_refs; stepup_evidence;
                   expiry; killed? }            # PAM activation record
IssuedCredRef    { opaque_ref; principal_ref; role_set; tier; expiry }  # tier-3 introspection lookup
JoinTokenUse     { token_id; used_at; bound_principal }                 # single-use enforcement
BundleEpoch      { domain; epoch; issued_at }                           # FED-1 monotonic state
DPoPReplay       { jti; exp }                                           # AG-3 replay cache
```

**Activation semantics (each a classic bug if unstated):**
1. An activation is a **grant window**; each 15-min renewal inside it
   **re-validates the activation record AND the underlying binding** — either
   vanishing kills at next renewal. A server-side activation-kill also revokes
   the session-side path (mirrors session kill).
2. Activation expiry and every credential minted under it are **clamped to the
   binding's/membership's `not_after`** (JIT-on-JIT — no "eligible until
   Friday, activated Thursday 23:59 for 4h" leak).
3. **Approval re-validates the binding at grant time**, not request time
   (approval-race safe).
4. The **step-up assertion is bound to that specific activation/approval**
   (challenge carries the request hash) — no relayed-touch approval of a
   different request (extends E-01 AT-5 to activations).

### Built: activation API (2026-08-17, milestone 5b)

`internal/kernel/activation.go`; `signet pam eligible | activate | pending |
approve | deny | kill`; proven in `test/pam/run.sh`.

The four semantics above are enforced **inside `Apply`**, not in a caller that
could be bypassed, and each has a test named after the failure it prevents:

- **Eligibility is not possession.** `HasAuthority` skips a binding with
  `activation_required` unless a live activation references it, and re-checks on
  every call — so an activation expiring or being killed ends the access at the
  next renewal with nothing to sweep.
- **JIT-on-JIT.** Expiry is `min(requested, MaxActivationSec, binding.NotAfter)`.
- **Approval re-validates at grant time.** If eligibility lapsed or was removed
  while the request sat in the queue, approving *denies* it and records why.
- **Nobody approves their own request** — including a domain admin who could
  otherwise grant it outright. Approving is a form of granting, so an approver
  must additionally hold `admin` at the binding's scope, and the same principal
  cannot supply two of the approvals `min_approvers` requires.

Two smaller decisions worth recording:

**Activations cannot be stacked.** One live or pending activation per binding.
Without that, a requester could open overlapping windows and hold the authority
continuously while every individual record looked bounded.

**Step-up is judged from facts carried in the Op**, not looked up during
`Apply` — `Apply` is pure, so it cannot go and read a session, and every replica
must reach the same verdict. The requester's session supplies its own `amr` and
`auth_time` at propose time; the caller cannot assert them.

**Honest limit on step-up.** What is enforced today is *which* authentication
methods the session carries and *how recently* it authenticated. That is real
and worth having, but it is not the challenge-bound assertion docs/13 semantic 4
describes: there is no hardware authenticator yet, so nothing signs a challenge
carrying the request hash. The structure is in place for one to slot in; until
it does, a relayed-touch approval of a *different* request is not prevented by
cryptography here. Gated on E-05 and the agent.

## KV dialect authorization (E-13 F8 — the actual v1 success path)

The first success criterion is "ESO reads a secret," so it is specified:

- **Secrets are nodes in the resource tree** — the Vault mount/path prefix maps
  to a tree path (`secrets-home-solcore-dot-net/cluster-svc/apps/litellm` →
  `/clusters/svc/secrets/apps/litellm`, exact mapping tabled next to the E-06
  compat spec in 07). Scope machinery and per-subtree DEKs (11) then apply for
  free, including per-app sub-path isolation (what the homelab does today).
- **Reserved, Signet-dialect-owned roles** with fixed verb sets in v1:
  `kv-reader` (get/list), `kv-writer` (+put), `kv-admin` (+delete/destroy/
  metadata). Narrow waist intact — these are the dialect's own role→permission
  mapping, exactly as Grafana owns `infra-admin → Admin`. A binding scopes one
  of these at a secrets sub-path.

## Notes / deliberate deferrals

- **ABAC containment**: `attributes` is non-authoritative metadata *only* —
  policy stays data (bindings), never attribute expressions, or ABAC creep
  swallows the model. `evidence_matcher` is exact-match on enumerated fields,
  **no regex in v1** (same creep, worse — it's on the auth path). Templated
  mapping rules deferred; when added, K-1 must validate the template's *range*,
  not an instance (recorded in 04).
- **MappingRule conflict** (F10): **unique-match-or-fail-closed** — ambiguity
  is an error at plan time when statically detectable, else at login, loudly
  audited. No rule ordering (avoids firewall-rule politics).
- **Additive-only boundary story** (F12): "admin everywhere except X" is
  inexpressible by design; the escape hatch is **domain topology** (a separate
  subdomain is the deny boundary). The AD block-inheritance alternative is
  rejected — recorded in 05's Reconsideration.
- Group-of-groups allowed but resolution stays flat + acyclic/bounded-depth at
  issuance (confirm termination).
