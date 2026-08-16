# E-14 — Reduction review of the MVP plan (doc 15)

**Mission:** reduction review · **Feeds:** doc 15 (primary), 09, 10 · **Date:** 2026-08-16
**Status: Complete**
**Reviewer stance:** hostile to sprawl and premature structure. Single question:
*can doc 15 be smaller without losing the goal?*

## Question

Doc 15 proposes ~8 internal packages, 4 dependencies, and an in-scope list
(Raft, barrier+seal, RolePolicy, versioned KV, k8s-SA attest, Vault-KV dialect,
genesis with root keypair, audit emission) to reach one goal: **ESO reads a
secret from Signet unmodified** on a single node. Which of that is the goal's
actual skeleton, and which is next-milestone scope wearing an MVP badge?

## Method

Read doc 15 against the wire evidence in E-06 (the exact calls ESO makes,
from pinned source), the data model (13), lifecycle (14), storage decisions
(03), dialect roadmap (07), and E-13. For every in-scope item and package:
*does the ESO read path execute this code?* If not, it must justify itself as
cheap-now/migration-hell-later — and that claim gets checked, not granted.

The controlling fact, from E-06 F2: ESO's entire surface for this slice is
**four routes** — `POST /v1/auth/kubernetes/login`, `GET /v1/auth/token/
lookup-self`, `PUT /v1/auth/token/revoke-self` (may 204 no-op), `GET
/v1/{mount}/data/{path}`. No metadata reads, no versions param (homelab
`remoteRef {key, property}`), no list, no `sys/*`. Everything in the plan
should be measured against how little that is.

---

## Reductions, ranked

### R1 — Collapse 8 packages to 4 (+cmd). Merge `op`, `seal`, `audit`; fold `consensus` into `store`. — **do it**

Package boundaries in Go earn their keep by *enforcing an import direction
someone might violate*. The design has exactly three load-bearing rules
(doc 09): dialects import the kernel, never storage; the kernel imports
nothing above storage; nothing imports a dialect. Enforcing those needs
**{kernel, store, attest, dialect/vaultkv}** — four packages — plus `cmd`.
The other splits enforce nothing a file boundary doesn't:

- **`op` → `kernel/op.go`.** The Op union is the kernel's write vocabulary;
  the kernel defines it, store/consensus imports kernel to decode it. No
  cycle, no package. A separate `op` package is taxonomy dressed as
  architecture.
- **`seal` → `store/seal.go`.** One interface, one passphrase implementation.
  Doc 15's own principle — "interfaces exist only where behavior actually
  varies" — condemns this split: nothing varies until TPM/KMS arrive
  (hardening milestone). Keep the small `Seal` interface as a *type*; give it
  a package when the second implementation exists, not before.
- **`audit` → one event type + one append inside `FSM.Apply`.** The MVP audit
  story is literally "the emission call site exists" — that is ~30 lines and
  one bbolt bucket. A package for one type and one function is the exact
  sprawl pattern this review exists to kill. (Keep the call site — see
  "What NOT to cut.")
- **`consensus` + `store` → one `store` package.** The FSM glue is thin and
  is meaningless without the bbolt state it applies to; doc 03 already treats
  raft.db + state.db as one storage story with one engine. Split later if the
  FSM file grows past taste — splitting a Go package is mechanical; the
  premature split is the direction that costs.

`attest` stays its own package: it has a genuinely different dependency shape
(network JWKS fetch, JWT parse — the fuzz target) and a real interface seam
(verifiers multiply in milestone 3). `dialect/vaultkv` stays: kernel-blind
dialects are the architecture's one non-negotiable boundary; police it from
commit one.

**Saved:** structure ceremony, import churn, 4 packages of doc.godoc surface.
**Risk:** none real. **Genuine reduction.** Re-split `seal`/`consensus` when a
second impl or multi-node work arrives — *cut for MVP, revisit on evidence*.

### R2 — Cut RolePolicy (and the tier-floor property test) from the MVP kernel. — **do it**

The slice has: one workload principal (ESO's SA via mapping), a handful of
genesis-declared bindings, and three dialect-owned role *names*
(`kv-reader/writer/admin`) whose verb sets are hardcoded in the dialect
(13 F8 — by design). RolePolicy exists to carry `min_tier`, `required_amr`,
`max_ttl` — **freshness tiers, step-up, and TTL ceilings are all machinery
the plan itself defers to the OIDC/SSH milestone.** The MVP session is a
single-tier opaque token; there is no tier to floor, no amr to require. The
plan's own testing list gives the game away: "tier-floor-cannot-be-lowered"
is a property test for code the slice never executes — a test suite for
milestone 3 smuggled into milestone 1.

MVP kernel entities: `Principal {id, path, kind}`, `Binding {subject_id,
role, scope, grantor_id}`, `Session {token_hash → principal_id, expiry}`,
secret nodes. Role = a name string checked by scope-walk. That's the whole
authorization model ESO's read exercises.

**Saved:** one entity + its Op + strictest-wins composition logic + its tests.
**Risk:** low. The semantics are already fully specified in 13 F3; adding the
entity later is additive (new Op type, new bucket) — with stable IDs and the
Op-sourced store there is no migration, just new writes. **Cut for MVP, not
forever** — RolePolicy arrives with the first tiered dialect (milestone 3).

Same knife, same cut: the plan's "delegation-narrows (bindings + membership)"
property tests. Groups are on the plan's own deferred list; membership tests
re-import them through the test plan. MVP keeps **scope-walk correctness**
property tests (component-wise prefix, grammar rejection — genuinely
exercised) and the trivial narrows check genesis config needs ("config cannot
grant above the domain" — near-vacuous on a single domain, fine). Membership
narrows tests land with groups.

### R3 — Cut KV version *history*; keep a per-secret monotonic version counter. — **do it**

E-06 upgraded "KV version history" to a kernel storage requirement — for
**full Tier A** (CAS, soft-delete, destroy, `metadata.current_version`).
The MVP routes need none of it: ESO's `GET .../data/{path}` parses `data.data`
and ignores metadata; homelab ESO sends no `?version=N`; the metadata,
delete/undelete/destroy, and list routes are not in the MVP surface. Even the
stretch (`bao kv get`) only *prints* whatever metadata appears.

The honest middle: store `{value, version: uint64, created_time}` per secret
node, bump the counter on `PutSecret`, retain only the latest value. The wire
envelope is then already the KVv2 shape (`data.data` + `data.metadata.
version`), so Tier A's history/CAS lands in milestone 2 as a storage-layer
extension behind an unchanged dialect envelope — not a wire migration.

**Saved:** the majority of E-06's "real work" estimate (800–1200 LoC of KVv2
semantics collapses to ~200), plus metadata bucket schema.
**Risk:** milestone 2 reshapes the secret bucket (single value → version
list). Bounded: snapshot-defined FSM state makes this an FSM code change +
snapshot version bump, and pre-milestone-2 domains are dev domains.
**Cut for MVP only** — history is Tier A and required for the `bao`/consumer
milestone.

### R4 — Cut the root CA keypair from MVP genesis; serve TLS from an externally supplied cert. — **do it, with eyes open**

Nothing in the slice consumes an internally issued certificate. There is no
PKI route (pki/sign is milestone 2), no node-join mTLS (single node), no
SVID dialect. The only certificate in the slice is the server's own TLS cert,
which ESO pins client-side (`caBundle`) — it is equally happy pinning a cert
minted by `openssl`, or by the existing homelab CA. The in-tool root keypair,
the never-persist-to-FSM rule, and the "no root material in any backup
generation" postcondition (14/F6) are all real requirements — **of the PKI
milestone.** They rode into the MVP on F6's (justified) scariness, not on the
slice's needs. This is the plan's clearest case of prudence-shaped creep.

MVP genesis = init store → load declarative config (principals/bindings/
k8s-trust) → done. `--tls-cert/--tls-key` flags on `serve`.

**Saved:** X.509 issuance code, ceremony idempotence machinery, the checked
postcondition, assured-issuance (charter #6) verifier — none exercised.
**Risk:** moderate-low. The genesis ceremony gets extended (not rebuilt) in
milestone 2; the risk is designing root-handling under delivery pressure
later — mitigated because F6/doc 14 already specify it completely. The MVP
"domain" is a dev domain either way; the real `home` root should be minted
when pki/sign lands, not before. **Cut for MVP, mandatory for milestone 2.**

### R5 — Sequence the slice: curl, then ESO-via-token-auth, then k8s-SA login. `attest` lands last. — **do it (ordering, not scope)**

Two checkpoints inside the slice, neither throwaway:

1. **Curl checkpoint (~day 2–3):** `signet genesis` + `signet kv put` +
   `curl -H "X-Vault-Token: …" /v1/{mount}/data/foo`. Proves the entire spine
   — Op → Raft → FSM.Apply → barrier → bbolt → session lookup → dialect
   envelope — in a few hundred lines, before any JWT exists.
2. **ESO-unmodified via token auth (mid-slice):** E-06 F2 row "auth_token.go"
   — ESO's token auth does *zero* login calls; the token goes straight into
   `X-Vault-Token` and is validated via lookup-self. So real ESO in kind reads
   a real secret **with no attestation code written at all**. This is not
   goal-gaming: token auth is free Tier A surface, and every line persists.
3. **k8s-SA login last:** the JWKS/JWT verifier drops in as the final
   package; the goal line ("via k8s-SA attestation") is crossed when it does.

**Saved:** no code — but it converts "everything integrates at the end" into
three independently green states, and isolates the fuzz-heavy JWT work from
the plumbing work. The strongest de-risk available at zero scope cost.

### R6 — Barrier: keep the envelope, demote the ceremony. — **half-cut**

Tempting to call the barrier a second-commit item, and for the first *week*
it is (see R5 checkpoint 1 — plaintext is fine until real secrets exist).
But the barrier sits exactly on the one write path (encrypt before
`raft.Apply`, decrypt in `FSM.Apply` — doc 03, **Decided**): retrofitting it
touches the spine everywhere and invalidates any persisted state. With stdlib
AEAD + a passphrase KDF it is ~150 lines. Keep it **in the MVP**, but as
`store/seal.go` (R1) with exactly one key-derivation path and no unseal
API/UX — `--passphrase-file`, nothing else. The pluggable-seal *surface* is
hardening-milestone scope.

### R7 — Honest dependency accounting. — **fix the claim**

"4 dependencies" counts direct imports. `hashicorp/raft` pulls `go-hclog`,
`go-msgpack/v2`, `go-metrics` transitively; `raft-boltdb/v2` adds its own
glue. The budget-conscious framing should say: **3 direct deps (raft,
raft-boltdb, bbolt) + ~4 transitive via hashicorp, stdlib for everything
else.** Still excellent — but the doc should not undercount, because the
dependency budget (09) is a governance line that only works if the accounting
is real. Could the *first slice* be 1 dep (bbolt)? Only by faking Raft — see
the verdict below: no.

---

## The Raft verdict

**Real single-node hashicorp/raft, day one. The plan is right — un-hedged.**

Three reasons, in strength order:

1. **Doc 03 is Decided that the Raft log IS the WAL** — the backup format,
   restore path, and barrier layering are all defined as Raft-entry
   operations. A bbolt-behind-a-Proposer slice would validate a write spine
   the project has *already decided not to ship*. The MVP's whole value is
   proving the real spine; a faked proposer proves a fake one.
2. **The constraint that cannot be retrofitted is not the interface, it's the
   discipline:** `FSM.Apply` must be deterministic, idempotent under replay,
   and free of wall-clock/IO/randomness. That discipline is precisely what
   erodes when code accretes against an in-process proposer ("just check the
   clock here, just fetch JWKS there"). Single-voter Raft enforces it from
   commit one, and `kill -9` + restart gives log-replay corruption testing
   for free — the highest-value test a storage spine can have, at zero extra
   code.
3. **The cost is genuinely small.** `BootstrapCluster` single-voter is ~50
   lines of setup; the library is the most battle-tested component in the
   entire stack (Vault/Consul/rqlite lineage). The savings from faking it are
   roughly two days and one direct dep, repaid with interest the week
   milestone 2+ touches consensus.

The reduction that IS available: **zero membership machinery.** No non-voters,
no join, no transport TLS, no promotion tooling — `BootstrapCluster`, FSM
Apply/Snapshot/Restore, raft-boltdb log, file snapshot store, loopback
transport. If any cluster-join code appears in the MVP diff, that's the creep.

(One guard, per reason 2: `FSM.Apply` takes no context, no clock, no network.
Expiry comparisons happen at *read* time against the session record's stored
expiry; attestation verification happens *before* propose, and the Op carries
its verdict. Write that as a review rule now — it's the honest-FSM property
Raft is being kept to enforce.)

## Smallest-viable-slice recommendation

**ESO-unmodified is the right first target — do not shrink the target;
shrink the path to it.** A curl-only "MVP" would prove plumbing but retire
none of the real risk: the bug-compat traps (ttl-as-JSON-number,
`expire_time` key presence, `404 {"errors":[]}`) are exactly where E-06 found
the panics live, and only real ESO in kind exercises them. But the path
should pass through the two checkpoints in R5 — curl at day 2–3, ESO-via-
token-auth mid-slice, k8s-SA last — so the plumbing, the dialect envelope,
and the attestation verifier each turn green independently.

The reduced slice, in full:

- **4 packages + cmd**: `kernel` (op types, principals/bindings/sessions/
  secrets, scope-walk, path grammar, stable IDs), `store` (raft glue, FSM,
  bbolt, barrier+passphrase seal, audit bucket), `attest` (k8s-SA JWKS
  verifier), `dialect/vaultkv` (4 routes + envelope; stretch adds mounts-
  preflight + sys/health).
- **4 routes** (stretch: 6). **3 direct deps.** No RolePolicy, no groups, no
  version history (counter only), no internal CA, no seal plugins, no
  membership Raft code.
- Tests: scope-walk properties, path-grammar rejection, FSM replay
  (kill/restart), SA-JWT + Vault-JSON fuzz, E-06 conformance fixtures against
  real ESO in kind.

Estimated effect: roughly **half** the plan's implied code, with the goal
line, the architecture's structural property (one write path), and every
Decided storage decision fully exercised.

## What NOT to cut (calibration — these earned their place)

- **Stable IDs + SPIFFE path grammar (E-13 F1/F11).** Both are exercised by
  the slice (bindings reference principals; every secret/principal path is
  validated), both are ~tens of lines now, and both are schema-migration hell
  later. The plan's "cheap now" claim checks out. Keep.
- **The one-write-path Op architecture.** This is the anti-sprawl property
  itself; it is what makes every deferral above *additive* instead of a
  migration. Keep, and protect it (FSM purity rule above).
- **Real Raft.** Verdict above.
- **Barrier encryption of Op payloads.** On the spine; retrofit touches
  everything. Keep the envelope (R6), defer the ceremony surface.
- **Audit emission from `FSM.Apply`.** One call site by construction; costs
  ~30 lines to keep, and deferring it forfeits the "call sites exist from day
  one" property that makes hash-chaining a drop-in later. Keep the call, kill
  the package.
- **E-06 conformance fixtures against real ESO in kind.** This *is* the goal
  measurement; the fixtures are worth more than the dialect code they test.
- **Fuzzing the SA-JWT and Vault-JSON parsers.** The only untrusted-input
  parsers in the slice, both on the auth path. Cheap with Go native fuzzing.
- **The `dialect/vaultkv` package boundary.** The kernel-blind-dialect rule is
  the charter's principle 5; boundaries you intend to enforce forever get
  drawn on day one.

## Confidence

**High** on R1, R2, R5, R7 — each is checked directly against the E-06 call
inventory or the plan's own deferral list; the slice provably never executes
the cut code. **High** on the Raft verdict — it follows from doc 03's Decided
status plus the replay-discipline argument; it would flip only if doc 03
reopened. **Medium-high** on R3 — the "version counter now, history later"
seam is clean at the wire layer but the milestone-2 bucket reshape is real
work being scheduled, not deleted; if milestone 2 follows within weeks, doing
history up front is defensible. **Medium** on R4 — the cut is sound on
strict slice-scope grounds, but it moves the project's most safety-critical
ceremony (root handling) later; if the team would rather exercise F6 while
attention is fresh, keeping a minimal root ceremony is a legitimate
overrule — it is the *only* recommendation here where "false economy" is a
live argument. What would change this report: ESO or the homelab SecretStore
CRs turning out to use `metadataPolicy: Fetch` or versioned reads (promotes
R3's metadata route back into scope — grep the cluster-* repos' SecretStore
manifests before freeze), or a decision to mint the real `home` domain root
from the MVP binary (kills R4).
