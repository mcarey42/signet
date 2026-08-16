# E-15 — Elegance review: MVP plan & project structure

**Status: Complete** (review of 15-mvp-plan.md as drafted 2026-08; no design
docs edited)

## Question

Is the MVP plan the *right shape* — will it be a pleasure or a friction to
build and extend? Not "is it small" (separately reviewed). Specifically: does
the one-write-path (Op → Raft → FSM.Apply) model actually hold up under
request/response and consistency pressure; are the package seams right; does
the KV-online-only MVP generalize to the offline (OIDC/SSH) dialects without
tear-out; what should the kernel service API look like.

## Method

Close read of 15 (target), 09, 13, 06, 02, 03, 07, 00, README. Each claim in
15 was pressure-tested against (a) how hashicorp/raft's FSM contract actually
behaves (ApplyFuture, replay, restore), (b) the lifecycle model in 06 and the
runtime entities in 13 F9, (c) the mint-path requirements in 06 K-2 and
charter principles 5/6, and (d) what the doc-03 backup/restore design does to
anything that lives in FSM.Apply.

---

## The one-write-path analysis (the crux)

**Verdict: sound, genuinely elegant, and battle-tested in shape** — it is the
Vault/Consul/rqlite pattern, and choosing real single-voter Raft makes the
boundary honest. But the plan as written leaves **three contracts unstated**,
and one of them ("audit event emission from the one write path") is subtly
wrong as phrased. All three are cheap to fix now and expensive to retrofit.

### 1. Request/response over the log: solved, but only with a determinism rule

The worry "how does fire-and-forget-then-apply return a value?" has a standard
answer: `hashicorp/raft.Apply()` returns an `ApplyFuture`; on the leader,
`future.Response()` yields whatever `FSM.Apply` returned for that entry. So
"propose an Op, get a result" is natural — `CreateSession` can flow through
the log and hand back a result. **This is not the strain point.**

The real strain point is **nondeterminism inside Apply**. `FSM.Apply` runs
again on every log replay: crash recovery, snapshot+segment restore (03
explicitly replays backup segments "through the normal FSM.Apply path"), and
on every follower once multi-node exists. If Apply calls `rand` (token bytes,
key material) or `time.Now()` (issued-at, expiry), replay produces *different
state* than the original run — a restored node would hold sessions whose
tokens match nothing ever issued, and TTLs computed from restore-time clocks.

**The contract to write down (normative, day one):**

> **All nondeterminism is resolved at propose time and carried in the Op.**
> The proposer (kernel, on the leader) generates random material and reads the
> clock; the Op carries them as data. `FSM.Apply(op, state)` is a pure
> function — same Op + same prior state ⇒ same next state, every time, on
> every node, in every decade.

Corollary for `CreateSession` specifically, which also fixes a secret-hygiene
wart: the proposer generates the token, puts **only its hash** in the Op,
proposes, waits for the future, and returns the token *it already holds* to
the caller. The raw bearer token never enters the Raft log, the FSM, the
snapshot, or a backup segment (they're barrier-encrypted anyway per 03, but
hash-only means even an unsealed backup can't replay a live token). Lookup is
`hash(presented) == stored`. Apply's return value is reserved for computed
facts (assigned version numbers, rejection errors), not secrets.

### 2. "Audit emission from the write path" is the wrong mechanism — audit must be FSM *state*, not a side effect

If audit events are *emitted* (side effect) from inside FSM.Apply, then:

- **restore double-emits** every historical event (03's replay path),
- crash-recovery replay re-emits the tail since the last snapshot,
- multi-node (milestone 4) emits N copies, one per voter.

The elegant fix keeps the one-write-path property and is *stronger* than a
hook: **the audit record is part of the state transition.** `Apply` writes the
audit record into an `audit` bucket **in the same bbolt transaction** as the
mutation, keyed by `(raft term, index)`. Idempotent under replay by
construction (same key, same bytes), atomic with the change it describes (a
mutation without its audit record is impossible, not merely unlikely), and it
directly satisfies "consistency, audit, and encryption enforced in one place."
External delivery (syslog, anchoring — deferred to hardening anyway) becomes a
separate *tailer* of the audit bucket that tracks a delivered-index watermark
— exactly the shape external anchoring (11) will want. This is a
repackaging of `internal/audit`, not a new component: audit defines the event
type (leaf package), the kernel applier writes it, a future tailer exports it.

**Classification: wrong shape as phrased, fix now** — it's one sentence in the
plan and it changes where the audit call site lives.

### 3. Where validation lives: split it across the propose/apply line deliberately

"Propose an Op" hides a classic fork: validate-then-log (Apply is a blind
write) vs log-then-validate (Apply can reject). Blind-apply has a TOCTOU
window — two concurrent proposals each validated against the same pre-state
can interleave in the log and jointly violate an invariant that each
individually respected (exactly the shape of the F3 tier-floor and F2
delegation-narrows invariants, and of KV CAS). Since Apply is the serialized
single writer, **state-dependent invariants checked inside Apply are
serializable for free** — this is the single biggest structural gift of the
one-write-path and the plan should claim it explicitly:

- **At propose time (leader, may be slow/nondeterministic):** attestation
  verification (JWKS, signatures), token generation, clock reads, policy
  evaluation for authorization of the *request*.
- **Inside Apply (deterministic, fast, serialized):** path-grammar checks, KV
  CAS version check, tier-floor-cannot-be-lowered, delegation-narrows,
  referential checks (binding subject exists, not tombstoned). Apply returns a
  typed rejection through the future — a *rejected Op is a no-op entry*, which
  is fine (Raft logs intent, state carries truth).

This split also makes the flagship property tests fall out naturally (see
Testability below). One consequence worth stating in the plan: timestamps ride
in Ops (proposer's = leader's clock), which is precisely 03's
"TTLs are leader-clock-relative" — the two docs agree once this is explicit.

### Minor strains, none structural

- **Consistent reads**: single-node MVP makes every read leader-local; 03
  already reserves leader-lease/read-index for multi-node. No change needed.
- **Session expiry**: no sweeper needed — lazy expiry on lookup (consistent
  with 13's "no sweep" philosophy), plus an occasional compaction Op later.
- **Op codec durability**: the log and backup segments are replayed across
  software versions *forever*. The codec needs a version/type tag per Op,
  never-reused tags, and a snapshot+replay-across-a-schema-change test **in
  the MVP test suite**, not later. Cheap now; a corrupted-history problem
  later.

---

## Boundary / seam findings

The eight packages are substantially the right seams. Findings in order of
importance:

**F-B1 (fix now): the kernel↔consensus dependency needs its interface named.**
The kernel must propose Ops but must not import hashicorp/raft; the FSM must
call kernel apply logic but consensus must not become the home of business
rules. The clean DAG:

```
op        ← leaf: Op types + codec (vocabulary only, no apply logic)
audit     ← leaf: event type
store     ← bbolt + barrier; exposes a typed Tx
kernel    ← imports op, audit, store, attest; defines Proposer port;
            exports Apply(tx, op) for the FSM
consensus ← imports kernel + op; FSM.Apply → kernel.Apply; implements Proposer
cmd       ← wires the loop closed
```

`type Proposer interface { Propose(ctx, op.Op) (op.Result, error) }`, defined
kernel-side, implemented by consensus, injected in `cmd/signet`. No cycle, and
the fake-proposer temptation the plan rightly rejects for slice-zero remains
available *for kernel unit tests* (an in-process Proposer that calls
kernel.Apply directly is a legitimate test double once the real FSM keeps the
interface honest).

**F-B2 (keep): op as a leaf package is correct.** The codec belongs with the
types, not with consensus — audit tooling, backup restore verification, and
future debugging CLIs all want to decode Ops without touching Raft. Keep
apply *semantics* out of it (they're kernel), or the leaf grows roots.

**F-B3 (keep): sessions in kernel is right.** Sessions are the runtime half of
the data model (13 F9), dialect-blind by construction (principal ref, amr,
auth_time, expiry — nothing Vault-shaped). A separate `session` package would
be ceremony.

**F-B4 (keep, with one guard): no interface between kernel and store.** The
plan's "interfaces only where behavior varies" is the right instinct and store
is 1:1 with the kernel forever (bbolt is Decided, 03). One guard: keep
**policy evaluation** free of `store.Tx` — evaluate over an in-memory graph
view (loaded structs or a tiny read interface). This is for testability (see
below), not adapter purity.

**F-B5 (minor polish): `attest` interface placement.** Hexagonal says the
kernel defines the port. Either kernel defines `Verifier` and
`attest/k8ssa` implements, or `attest` holds the interface with per-verifier
subpackages. Both fine; pick one and don't let the dialect ever see a
verifier — the dialect hands the kernel *raw evidence + verifier name*, the
kernel runs verification (otherwise a dialect bug becomes an auth bypass).

**F-B6 (small missing seam): `sys/health` is not a kernel question.** It
reports seal/initialized/Raft status — server plumbing, not identity. The
vaultkv dialect needs a second, tiny dependency: a `Status()` provider wired
from cmd/consensus/seal. Name it so nobody "solves" it by teaching the kernel
about sealing states.

**F-B7 (note, no action): 09 and 15 disagree** (09: `kernel/{graph,policy,
keys,attest,issue}` sub-split, top-level `dialects/`; 15: flat `kernel`,
`dialect/`). 15's flat reduction is right at this size — split kernel along
09's lines only when it hurts. 09 should eventually be updated to match; the
one 09 name worth preserving on purpose is **`issue`** (see extensibility).

**F-B8 (verdict on hexagonal): not cargo-culted.** The adapters (seal, attest,
dialect, future backup targets and serializers) are exactly the axes where
behavior actually varies per the roadmap. The plan already disclaims
interfaces-as-ceremony inside the kernel. This is hexagonal used as a load
diagram, not a religion.

---

## Proposed kernel service API sketch

The rule that keeps everything clean: **dialects call kernel methods; only the
kernel constructs and proposes Ops.** Dialects proposing Ops themselves would
put storage vocabulary and invariant responsibility in dialect hands — a
straight violation of principle 5 and of "one place enforces." Equally
important: **authorization lives inside the kernel method, not as a separate
call the dialect could forget.**

```go
// internal/kernel — the dialect-facing surface. Concrete type, not an
// interface (nothing varies); ports (Proposer, attest.Verifier, seal.Seal)
// are injected.

type Kernel struct { /* proposer, store, verifiers, clock, rand */ }

// --- Authentication (attestation → session). MVP.
// Dialect passes RAW evidence; kernel selects & runs the verifier.
type Evidence struct {
    Verifier string   // "k8s-sa"
    Material []byte   // the SA JWT, unparsed
    Audience string
}
type Session struct {
    ID           op.ID
    Principal    op.ID
    AMR          []string
    AuthTime     time.Time
    Expiry       time.Time
    // SenderBindingKeyRef *op.ID — nullable field exists day one (13 F9)
}
func (k *Kernel) Login(ctx context.Context, ev Evidence) (Session, Token, error)
func (k *Kernel) LookupSession(ctx context.Context, tok Token) (Session, error)

// --- Resource access (online dialects: authz evaluated per use). MVP.
// Verb vocabulary is kernel-owned; the DIALECT owns the mapping from its
// wire surface to (verb, tree path) — e.g. Vault mount/path → /clusters/…,
// kv-reader → {get,list} (13 F8). The kernel authorizes inside each call.
func (k *Kernel) GetSecret(ctx, tok Token, path Path, version int) (SecretVersion, error)
func (k *Kernel) PutSecret(ctx, tok Token, path Path, data map[string][]byte, cas *int) (int, error)
func (k *Kernel) ListSecrets(ctx, tok Token, prefix Path) ([]string, error)
// (delete/destroy/metadata follow the same shape)

// --- Admin plane (genesis tool, declarative config load, future GitOps). MVP.
func (k *Kernel) PutPrincipal(ctx, actor AuthZ, p PrincipalSpec) (op.ID, error)
func (k *Kernel) PutBinding(ctx, actor AuthZ, b BindingSpec) (op.ID, error)
// … each constructs one Op; delegation-narrows / tier-floor enforced in Apply.

// --- The one decision path (06: issue → claims → filter → serialize).
// NOT built in MVP; the NAME is reserved so Login/GetSecret are never
// mistaken for the general shape. Arrives with OIDC/SSH.
func (k *Kernel) Issue(ctx, tok Token, req IssueRequest) (Credential, error)

type IssueRequest struct {
    Dialect  string        // selects a registered serializer
    Audience string
    Scope    Path
    TTL      time.Duration // clamped by RolePolicy.max_ttl
}

// Offline dialects register a serializer/verifier PAIR (principles 5 + 6):
type Serializer interface {
    // Claims is already tier-filtered; tier-3 roles are opaque-ref-only
    // values the serializer physically cannot expand (06 K-2).
    Serialize(c FilteredClaims, s SignHandle) (Credential, error)
    // Independent re-verification against issuer constraints, run by the
    // kernel AFTER Serialize and BEFORE release (charter principle 6).
    Verify(cred Credential, constraints IssueConstraints) error
}
// SignHandle signs exactly one payload for exactly one issuance; the key
// never crosses the boundary. Dialects never touch keys (principle 5).
```

Notes on the shape:

- `Login` and `Issue` are the two lifecycle steps of 06 (attest→session,
  session→role-credential). The MVP builds only the first — that is a
  *prefix* of the final API, not a divergent fork, **provided `Issue` is the
  declared future name** and nobody grows `Login` options to cover minting.
- For **online** dialects the session token *is* the credential — policy is
  evaluated per use, fresher than any 15-minute renewal. Role credentials
  exist *only* for offline dialects. This sentence belongs in 06 or 15; it
  dissolves the apparent session-vs-IssuedCredRef ambiguity in the MVP.
- The `Serializer` pair is how "dialects call kernel" survives the offline
  era without inverting: the transport half of a dialect calls `Issue`; the
  format half is a callback *inside* the mint path, sandwiched between the
  tier filter and the verify-after-sign gate. K-2's "no serializer can expand
  a tier-3 role" becomes a type-level property of `FilteredClaims`.

---

## Extensibility-to-offline-dialects analysis

**Overall: the MVP absorbs OIDC/SSH cleanly. There is no hidden fork in the
API** (Login/Issue are sequential lifecycle stages, not alternatives), and the
Op vocabulary grows additively (`CreateActivation`, `PutMappingRule`, new
entities in 13 F9 are new tags, zero rework). The places where the MVP could
silently bake in a wrong assumption, each with its cheap prophylactic:

1. **`seal` must not become the home of signing keys.** Seal = barrier
   (data-at-rest); signing keys (session-signing, intermediate CA, per 06
   "keys separated by function, rotate independently" and the KRBTGT
   double-rotation dance) are FSM state under the barrier plus a signer
   service. That's 09's `keys` package. Don't build it in MVP — but write one
   line in 15 saying signing keys will be `keys`/`keyring`, not `seal`, so
   nobody grafts `Sign()` onto the Seal interface in month three. The genesis
   ceremony already gets this right (root generated in-tool, never persisted).
2. **Session fields from day one.** `amr`, `auth_time`, `upstream_verifier`,
   nullable `sender_binding_key_ref` — all specified in 13 F9, all nearly
   free now, all a log-compatible-migration headache later. The plan implies
   this; make it explicit in the MVP session schema.
3. **RolePolicy.min_tier exists in MVP data** (the tier-floor property test is
   already in MVP scope) even though the K-2 mint gate arrives with `Issue`.
   Good — the enforcement point plugs into a field that already exists.
4. **Op codec versioning** (repeated from above because this is where it
   bites): the offline milestone will change/extend entities while old log
   segments and backups still exist. Version tags + a cross-version replay
   test in MVP, or the multi-domain milestone inherits an archaeology problem.
5. **The agent renewal loop** (offline milestone) is just another kernel-API
   consumer plus `internal/wire`; nothing in the MVP layout obstructs it.
6. **Verify-after-sign has no MVP call site** (nothing is signed) — that's
   acceptable; the seam arrives with `Issue` and the Serializer pair, which
   is exactly where principle 6 says it lives. No scaffolding needed now.

Nothing here is a tear-out. Items 1–4 are one-line plan amendments; the
structure itself already generalizes.

---

## Testability

The shape actively helps, with one guard:

- **Model-based testing falls out of the one-write-path**: generate random Op
  sequences, run them through the *real* `kernel.Apply` over a throwaway
  store, assert F2/F3 invariants on the resulting state. Because Apply is
  deterministic and serialized, this is the textbook setup — arguably the
  single biggest testing payoff of the architecture, and worth a sentence in
  10/15. Putting the invariant checks *inside* Apply (F-strain 3 above) is
  what makes "no write sequence can lower a floor / escape a scope" a direct
  property of the tested function rather than of scattered call sites.
- **Scope-walk / narrows / tier-floor** stay pleasant iff policy eval is a
  pure function over an in-memory graph view (F-B4 guard). If eval demands a
  live bbolt tx, every property test drags a store fixture.
- **E-06 conformance fixtures**: run the vaultkv handlers against a *real*
  in-process single-node kernel (bootstrap is a few lines — the plan's own
  argument for real Raft pays off here) instead of a mocked kernel; keep
  kind+ESO as the integration tier. The bug-compat traps (ttl-as-number,
  `options.version` string, `404 {"errors":[]}`, `GET ?list=true`) are pure
  handler-serialization tests — leaf-testable.
- **Fuzzing** SA-JWT and Vault-JSON parsers: both live in leaf-ish packages
  (attest, dialect) with no store dependency. Natural.

---

## What's elegant (keep)

1. **One write path with real single-voter Raft.** The plan's own argument is
   correct: a faked proposer risks a wrong interface rebuilt later, and
   snapshot/restore is needed for backups regardless. The Vault/Consul
   lineage proves the shape at exactly this scale.
2. **Reduction by breadth, not by faking the core.** Deferring machinery
   *with the dialects it serves* (offline creds with OIDC/SSH, agents with
   workstations, federation with multi-domain) is the right cut line — each
   deferred item has a natural arrival vehicle, so nothing deferred is
   homeless.
3. **KV-as-online-dialect as the forcing insight.** Opaque tokens +
   server-side lookup exercise the full spine (attest → session → policy →
   storage → seal → audit) with zero signing machinery. This is the best
   single decision in the plan.
4. **op as the leaf vocabulary package**; interfaces only at genuine variance
   points; no kernel-store interface ceremony; sessions in kernel; stable IDs
   + SPIFFE grammar from day one.
5. **Naming is honest and Go-idiomatic.** `op` is terse but precise (it is
   *the* domain noun); `seal`/`store`/`attest` carry their Vault/industry
   meanings; `kernel` is unusual but is the project's own load-bearing term.
   Two polish items only: `consensus` could be `fsm` (that's what it
   contains; "raft" would collide with the import path) — either is fine;
   and pick singular `dialect/` (15) over plural `dialects/` (09)
   consistently.

## The fix-now list (all cheap, all structural)

| # | Finding | Class |
|---|---|---|
| 1 | State the determinism contract: nondeterminism resolved at propose time, carried in the Op; Apply is pure | wrong-if-unstated, fix now |
| 2 | Audit records are FSM state written in the same tx, keyed by (term,index) — not side-effect emission (replay/restore double-emit otherwise) | wrong shape as phrased, fix now |
| 3 | Session tokens: hash-in-Op, raw token returned proposer-side, never in log/state | fix now (free) |
| 4 | Declare the propose-time vs apply-time validation split; state-dependent invariants (F2/F3, CAS) live in Apply | fix now |
| 5 | Name the `Proposer` port (kernel-defined, consensus-implemented) to fix the dependency direction | fix now |
| 6 | Op codec: versioned tags + cross-version replay test in MVP | fix now |
| 7 | Reserve `Issue` as the future mint-path name; note session-token-is-the-credential for online dialects | one-line amendment |
| 8 | Note that signing keys will be `keys`, not `seal`; `sys/health` wired from server status, not kernel | one-line amendments |
| 9 | Policy eval over an in-memory graph view (test ergonomics) | minor polish |

## Confidence

**High** on the one-write-path verdict and the determinism/audit-replay
findings — these follow directly from hashicorp/raft's documented FSM
contract plus 03's own restore-replays-through-Apply decision, and the fixes
are the patterns Vault itself uses. **High** on the API sketch's Login/Issue
split (it is a restatement of 06's decided session/role factoring).
**Medium-high** on the Serializer-pair mechanism for offline dialects — the
shape is right (it is the only way to satisfy principles 5 and 6 and K-2
simultaneously), but its details should be validated when the OIDC milestone
is designed, not treated as decided now. No finding here requires reopening
any Decided doc; every fix lands as amendments to 15 (and eventually
reconciling 09 with 15's layout).
