# 15 — MVP vertical slice: plan, layout, structure

**Status: Draft** (hardened by reduction review E-14 + elegance review E-15,
2026-08-16)

## Goal (charter success criterion, one consumer)

A single-node `home` domain where **External Secrets Operator reads a secret
from Signet, unmodified**, via the Vault-KV dialect + k8s-SA attestation.
Stretch (cheap): `bao kv get` works (adds CLI mount-preflight + `sys/health`,
which inframonitor parses). Verified against the homelab: all 22 ExternalSecrets
use plain `remoteRef {key, property}` — no versioned or metadata reads.

## The reduction that shapes everything: KV is an *online* dialect

The Vault-KV dialect uses **opaque bearer tokens with server-side lookup** — no
offline verification. So the MVP exercises the full kernel spine (identity,
policy, attestation, KV, storage, seal, audit) while needing **none** of the
offline-credential machinery. That machinery is deferred *with the dialects it
serves*, so nothing deferred is homeless:

| Deferred | Arrives with |
|---|---|
| Signing keys, JOSE, offline credentials, freshness tiers, sender-binding | OIDC + SSH dialects (`keys` pkg — *not* `seal`) |
| Workstation/host agents | (k8s needs no agent — E-08) |
| Federation, trust bundles, multi-domain, sovereign mode, composite/PQC roots | multi-domain milestone |
| Full GitOps reconciler, JIT/PAM activation, groups | control-plane milestone |
| **Internal CA / root keypair / pki-sign / node-mTLS** | PKI milestone 2 (F6 root ceremony fully specified in 14, minted then) |
| TPM/KMS/Shamir seal, per-subtree DEKs, external audit anchoring, CRL | hardening milestone |

## The elegant core: one write path (E-15 — sound, with 4 contracts stated)

Every mutation is an **`Op`** (tagged union) **proposed through Raft**; the
`raft.FSM.Apply` decodes it and applies it to one bbolt transaction. Request/
response works via `raft.ApplyFuture.Response()` (the leader returns what Apply
computed). **One write path** ⇒ consistency, audit, and encryption each
enforced in one place. Four contracts make this correct (all cheap now,
expensive to retrofit — E-15):

1. **Determinism (normative).** `FSM.Apply(op, state)` is a **pure function** —
   same Op + prior state ⇒ same next state, on every node, in every decade.
   Apply reads **no clock, no rand, no network, no `context`**. All
   nondeterminism is resolved at **propose time** and carried in the Op
   (timestamps = leader clock, matching 03's "TTLs are leader-clock-relative").
   Required because 03's restore **replays backup segments through Apply**.
2. **Tokens: hash-in-Op.** The proposer generates the bearer token, puts **only
   its hash** in the Op, and returns the raw token it already holds via the
   future. The raw token never enters the log, FSM, snapshot, or backup. Lookup
   is `hash(presented) == stored`.
3. **Audit is FSM *state*, not a side-effect.** Apply writes the audit record
   into the `audit` bucket **in the same bbolt tx**, keyed by `(term, index)` —
   idempotent under replay, atomic with the mutation. (A side-effect "emit"
   would double-emit on every restore/replay and N× per voter later.) External
   delivery/anchoring becomes a later *tailer* tracking a delivered-index
   watermark — the shape 11 wants.
4. **Validation split.** *Propose-time* (leader, may be slow/nondeterministic):
   attestation, token gen, clock reads, request authorization. *Inside Apply*
   (deterministic, serialized — serializable for free): path-grammar, KV CAS,
   tier-floor, delegation-narrows, referential checks. Apply returns a typed
   rejection through the future; a rejected Op is a no-op log entry.

## Package layout (reduced — 6 internal + cmd, 3 direct deps)

Reconciling E-14 (merge aggressively) with E-15 (the DAG forbids two merges):

```
signet/
  cmd/signet/            # serve | genesis | kv (put/get) — wires the loop closed
  internal/
    op/                  # LEAF: Op tagged union + VERSIONED codec. No apply logic.
    store/               # bbolt state + raft-boltdb log + barrier + file-seal
                         #   + audit bucket. Exposes a typed Tx. Imports ~nothing.
    kernel/              # principals/bindings/sessions/secrets, policy eval,
                         #   Proposer PORT, Apply(tx,op). Imports op, store, attest.
    fsm/                 # raft.FSM: decode op -> kernel.Apply(tx); Snapshot/Restore;
                         #   implements Proposer. Imports kernel, op, store.
    attest/              # Verifier port + k8s-SA verifier (JWKS/JWT — fuzz target)
    dialect/vaultkv/     # Vault-compat HTTP handlers (4 routes; stretch +2)
```

Why not 4 packages (E-14's target): `seal` and `audit` **do** merge into
`store` (nothing varies yet). But **`op` stays a leaf** — the codec is
replayed across software versions forever, so it earns versioned tags + its own
cross-version replay test — and **`fsm` cannot merge into `store`**: the FSM
calls `kernel.Apply` and `kernel` imports `store`, so folding the FSM into
`store` creates an import cycle. E-15 caught this; the two surviving seams each
have a hard reason, not taste.

**The `Proposer` port** (kernel-defined, fsm-implemented, injected in cmd) is
how the kernel proposes Ops without importing raft:
`type Proposer interface { Propose(ctx, op.Op) (op.Result, error) }`. A test
double (in-process Proposer calling `kernel.Apply` directly) makes kernel unit
tests trivial — the real FSM keeps the interface honest.

**Dependencies (honest count):** 3 direct (`hashicorp/raft`, `raft-boltdb/v2`,
`bbolt`) + ~4 transitive via hashicorp (`go-hclog`, `go-msgpack/v2`,
`go-metrics`, glue); stdlib for crypto/TLS/x509/JSON/HTTP. The doc-09 budget
holds — stated honestly.

## Kernel service API (E-15 — dialects call kernel; only kernel proposes Ops)

Keeps the kernel dialect-blind (principle 5); authorization lives *inside* each
method, never as a call a dialect could forget.

```go
// Authentication (attestation -> session). MVP. Dialect passes RAW evidence;
// kernel selects & runs the verifier (a dialect must never see a Verifier —
// else a dialect bug is an auth bypass).
func (k *Kernel) Login(ctx, ev Evidence) (Session, Token, error)
func (k *Kernel) LookupSession(ctx, tok Token) (Session, error)
// Session carries {id, principal, amr, auth_time, expiry, senderBindingRef?}
// — the 13-F9 fields exist DAY ONE (nullable), so offline dialects need no
// session-schema migration later.

// Resource access (online: authz per use — fresher than any renewal). MVP.
// The DIALECT owns wire->(-verb, tree path) mapping; kernel authorizes.
func (k *Kernel) GetSecret(ctx, tok, path, version) (SecretVersion, error)
func (k *Kernel) PutSecret(ctx, tok, path, data, cas *int) (int, error)

// Admin plane (genesis, config load, future GitOps). MVP.
func (k *Kernel) PutPrincipal(ctx, actor, spec) (op.ID, error)
func (k *Kernel) PutBinding(ctx, actor, spec) (op.ID, error)

// The general mint path (06: issue->claims->filter->serialize). NOT built in
// MVP; the NAME is reserved so Login/GetSecret are never mistaken for it.
// Arrives with OIDC/SSH; offline dialects register a Serialize/Verify PAIR
// (principle 6 verify-after-sign), keys via a SignHandle that never crosses
// the boundary (principle 5).
func (k *Kernel) Issue(ctx, tok, req IssueRequest) (Credential, error)
```

For **online** dialects the session token *is* the credential (no `Issue`);
role credentials exist only for offline dialects. `Login` and `Issue` are the
two sequential lifecycle steps of doc 06 — the MVP API is a **prefix** of the
final one, not a fork.

## In scope (MVP) — reduced

- **Real single-node hashicorp/raft** (E-14/E-15 agree, un-hedged): the Raft
  log is the WAL/backup substrate (03, Decided), and `FSM.Apply` replay
  discipline is the one thing you can't retrofit. `kill -9` + restart gives
  log-replay corruption testing for free. **Zero membership machinery** —
  `BootstrapCluster` single-voter, FSM Apply/Snapshot/Restore, raft-boltdb log,
  file snapshot store, loopback transport. Any join/promotion code in the MVP
  diff is creep.
- **Barrier encryption** on the write path (encrypt before `raft.Apply`,
  decrypt in Apply) — on the spine, can't retrofit — with the **simplest seal**
  (`--passphrase-file`, stdlib AEAD + KDF, ~150 lines). No unseal API/UX.
- **Kernel**: principals, bindings, sessions (opaque tokens), secrets. Scope
  = component-wise prefix; **stable IDs + SPIFFE path grammar day one** (E-13
  F1/F11 — exercised by the slice, migration-hell later). Policy eval is a
  **pure function over an in-memory graph view** (not a live `store.Tx`) for
  test ergonomics.
- **KV: latest-value + monotonic version counter** (no history). Wire envelope
  is already KVv2-shaped (`data.data` + `data.metadata.version`), so Tier A
  history/CAS lands in milestone 2 behind an unchanged dialect. Reserved roles
  `kv-reader/writer/admin` (verb sets hardcoded in dialect); secret paths are
  tree nodes.
- **k8s-SA attestation**: pinned issuer + JWKS + required Signet audience.
- **Vault-KV dialect**: `POST /v1/auth/kubernetes/login`,
  `GET /v1/auth/token/lookup-self`, `PUT /v1/auth/token/revoke-self` (may 204),
  `GET /v1/{mount}/data/{path}`. Stretch +`sys/internal/ui/mounts` +
  `sys/health` (the latter wired from a server-side `Status()` provider, **not**
  the kernel — sealing/raft status isn't an identity question).
- **Genesis**: init store → load declarative config → done. **No root
  keypair**; TLS via `--tls-cert/--tls-key` (ESO pins it client-side anyway).
- **Audit records** written from Apply as state (contract 3).

## Cut from MVP (all additive-later — Op-sourced store ⇒ no migration)

- **RolePolicy + tier machinery** — no tiers/amr/TTL-ceilings in an online
  slice. Role = a name checked by scope-walk. Reintroduced with the first
  tiered (offline) dialect; because the store is Op-sourced, adding the entity
  is new Ops, not a migration.
- **KV version history / metadata / list / delete routes** — not in ESO's
  surface (verified). Counter only.
- **Groups, JIT/PAM, membership-narrows tests** — deferred with groups; MVP
  keeps scope-walk + path-grammar property tests + the near-vacuous
  single-domain narrows check.
- **Internal CA / signing / verify-after-sign call site** — nothing is signed
  in the slice. **Decision flag**: this moves the safety-critical root ceremony
  (F6) to milestone 2. Sound because the MVP domain is a dev domain and the
  real `home` root should be minted when `pki/sign` lands. *Overrule if you'd
  rather exercise the F6 root ceremony while attention is fresh* — the one cut
  where "false economy" is a live argument.

## Build sequence (E-14 R5 — 3 independently-green states, no throwaway)

1. **Curl checkpoint** (~day 2–3): `genesis` + `kv put` + `curl -H X-Vault-Token
   … /v1/{mount}/data/foo`. Proves the whole spine (Op → Raft → Apply → barrier
   → bbolt → session lookup → envelope) before any JWT exists.
2. **ESO-unmodified via token auth** (mid-slice): ESO token auth does **zero**
   login calls (E-06) — the token goes straight into `X-Vault-Token`. Real ESO
   in kind reads a real secret with **no attestation code written yet**. Free
   Tier A surface; every line persists.
3. **k8s-SA login last**: the JWKS/JWT verifier drops in as the final package;
   the goal line ("via k8s-SA attestation") is crossed when it does.

## Testing (MVP)

- **Model-based property tests**: random Op sequences through the *real*
  `kernel.Apply` over a throwaway store, asserting scope-walk correctness and
  path-grammar rejection (invariants checked *inside* Apply ⇒ they're
  properties of the tested function). F2/F3 membership/tier tests arrive with
  their features.
- **Op-codec cross-version replay test** — snapshot + replay across a simulated
  schema change. In MVP, not later (durable-log archaeology otherwise).
- **FSM replay** (`kill -9` + restart) corruption test — free with real Raft.
- **E-06 conformance fixtures** against a *real in-process single-node kernel*
  (bootstrap is a few lines) for the bug-compat traps (ttl-as-number,
  `options.version` string, `404 {"errors":[]}`, `GET ?list=true`), + kind+ESO
  as the integration tier, + real `bao kv get` for the stretch.
- **Fuzz** the SA-JWT and Vault-JSON parsers (leaf packages, no store dep).

## Milestones after the slice (orientation, not scope)

1. **Slice**: ESO reads a secret (this doc).
2. **Consumers**: full Vault Tier A (KV history/CAS, `bao` CLI, inframonitor
   health) + cert-manager `pki/sign` — brings the internal CA + F6 root ceremony.
3. **Offline dialects**: OIDC + SSH CA — brings `keys`, signing/JOSE, the
   freshness ladder, `Issue`, verify-after-sign, and the agent.
4. **Multi-domain**: root + home/aws/gcp, federation, sovereign-mode test.
5. **Hardening**: real seals, external audit anchoring, JIT/PAM, GitOps.
