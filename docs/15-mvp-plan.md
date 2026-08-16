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

1. **Determinism *and* idempotence (normative).** `FSM.Apply(op, state)` is a
   **pure function** — same Op + prior state ⇒ same next state, on every node,
   in every decade. Apply reads **no clock, no rand, no network, no `context`**;
   all nondeterminism is resolved at **propose time** and carried in the Op
   (timestamps = leader clock, matching 03's "TTLs are leader-clock-relative").
   Required because 03's restore **replays backup segments through Apply**.
   **Separately**, because Signet's state is durable while Raft replays
   committed entries from the last snapshot on restart, Apply must be
   **idempotent under replay**: an applied-index watermark is persisted in the
   same transaction as each mutation, and entries at or below it are skipped.
   Determinism alone does not give this — a version counter is deterministic
   and still drifts if replayed onto its own result. (Found by the first
   checkpoint; see the build sequence below.)
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

1. ✅ **Curl checkpoint — DONE (2026-08-16).** `genesis` + `kv put` + `curl -H
   X-Vault-Token … /v1/{mount}/data/foo` works end to end. The whole spine is
   proven: Op → Raft → Apply → barrier → bbolt → session lookup → envelope.
   Scaffold: 6 packages, 3 direct deps, **12 MB binary**, tests green
   (determinism-under-replay, delegation-narrows property test, CAS, the E-06
   bug-compat fixtures, restart-safety). Verified out-of-band: no plaintext
   secret in `state.db` or `raft.db`, and no raw bearer token anywhere on disk.

   **One real bug found by the checkpoint, worth recording:** a secret's version
   went 1 → 2 across a restart. Apply was deterministic but not *idempotent*:
   Raft replays committed entries from the last snapshot on restart, and because
   Signet's state is durable (unlike an in-memory FSM), replayed entries applied
   a second time on top of their own results. Anything accumulating would drift
   on every restart. Fixed by persisting an applied-index watermark in the same
   transaction as each mutation and skipping entries at or below it — the
   standard durable-FSM guard. Now regression-tested across repeated restarts.
   *Determinism and idempotence are separate properties; docs/15 contract 1
   only named the first.*
2. ✅ **ESO-unmodified via token auth — DONE (2026-08-16).** Real External
   Secrets Operator **v2.9.0** (upstream Helm chart, unmodified) in a real kind
   cluster reads a real secret from Signet — with **no attestation code
   written**, exactly as E-06 predicted (ESO's token auth makes zero login
   calls). Signet runs in-cluster from an **11.6 MB scratch image**; genesis
   runs as an init container and emits bootstrap tokens.

   Four behaviors verified against the real client, using the homelab's own
   `remoteRef: {key, property}` manifest shape:
   - **In scope** → `SecretSynced`; the Kubernetes Secret materializes with the
     right values.
   - **Out of scope** → refused. ESO reports `Code: 403 … permission denied` —
     scoped RBAC bounds a real consumer.
   - **Absent** → refused *differently*: ESO reports its own `"Secret does not
     exist"`, proving the `404 {"errors":[]}` shape is interpreted as "absent,
     not an error" rather than as an API failure. The two negative cases being
     semantically distinct is the real evidence the compat line is right.
   - **Live rotation** → a write to Signet propagates to the Kubernetes Secret
     in ~10s; **session revocation** (`revoke-self`) immediately breaks
     subsequent syncs.

   Captured as `test/kind/run.sh` (one command, idempotent) — the seed of the
   conformance harness in doc 10 / mission E-10.

   Two reproducibility lessons worth keeping: the domain lives in an emptyDir,
   so the script replaces the pod to start from a fresh domain (a stale genesis
   log otherwise yields revoked tokens); and a `SecretStore` **caches its
   readiness**, so one left over from a previous domain stays NotReady against
   tokens that no longer exist — the consumer namespace is recreated each run.
3. ✅ **k8s-SA login — DONE (2026-08-16). THE MVP GOAL LINE IS CROSSED.**
   ESO now authenticates as its **own Kubernetes workload identity**: no token,
   no shared secret anywhere in the manifests. It asks Kubernetes for a
   short-lived ServiceAccount token with audience `signet`, posts it to
   `/v1/auth/kubernetes/login`, and receives a session — the same flow it uses
   against Vault, which is why it works unmodified.

   `internal/attest` implements JWS verification on the **standard library
   only** (RS256/ES256, JWKS parsing) — no JWT dependency on the auth path.
   Verified failure modes, each a real attack: `alg=none`, alg confusion (RSA
   public key as an HMAC secret), wrong/absent audience, wrong issuer, expired,
   no expiry, tampered payload, unpinned signing key, `sub` disagreeing with
   the `kubernetes.io` claim, and a non-ServiceAccount subject.

   Three properties worth recording:
   - **Attestation and authorization are separate steps.** A second, real
     ServiceAccount in the same namespace (`impostor`) is correctly attested
     and still refused, because the mapping rule names accounts exactly.
   - **A session never outlives its evidence.** The mapping asked for a 900s
     TTL; the issued lease came back as 600s, clamped to the SA token's own
     expiry.
   - **Mapping rules are authorization-bearing writes.** A subtree admin cannot
     map an identity onto a principal outside their subtree, and cannot
     register a trust anchor at all (domain-wide authority) — the ESC1 shape
     reached through authentication config rather than through a grant.
     Property-tested.

   Keys are **pinned out of band** (fetched from the cluster's OIDC discovery
   endpoint into a mounted file), never discovered from a request — E-01 AT-1/
   AT-2. `test/kind/run.sh` covers the whole thing end to end.

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
2. ✅ **Consumers — DONE (2026-08-16).** Full Vault Tier A plus the internal CA.
   - **KV v2 complete**: version history, versioned reads, metadata, list,
     soft delete / undelete / destroy, CAS and `cas_required`, `max_versions`
     trimming. Verified against **bao v2.5.5**, the CLI this homelab uses.
   - **PKI**: `pki/sign/{role}`, `ca/pem`, `ca_chain`. **cert-manager v1.19**
     in kind obtains certificates from Signet, authenticating as its own
     Kubernetes workload — and the result verifies under **openssl**, an
     independent TLS stack.
   - **The F6 root ceremony is real**: the root key is generated in the
     ceremony, signs exactly one intermediate, and is written to a file outside
     the data directory. Verified empirically that it appears nowhere in
     `state.db` or `raft.db`. Genesis is idempotent — a domain that already has
     an authority keeps it, since a second root would orphan everything issued
     under the first.
   - **Verify-after-sign (charter principle 6) is implemented and tested**:
     every certificate is re-parsed from its own bytes and re-checked — chain,
     CA bit, TTL, and every SAN — through a separate code path before release.
     Tests forge the certificates a buggy builder would emit (wrong domain,
     over-long TTL, CA bit set, no SANs) and confirm the gate refuses them.

   **Second compat bug found by a real client** (E-06 surveyed only ESO's
   routes): the `bao` CLI sends version numbers as JSON **strings**. Go's
   decoder reports the type error but has already appended a zero, so "undelete
   version 1" silently became "act on version 0" — a no-op that returned 204.
   A destructive-adjacent call that quietly does nothing while reporting
   success is the worst available failure, so the decoder now accepts both
   forms and rejects anything else.
3. **Offline dialects**: OIDC + SSH CA — brings `keys`, signing/JOSE, the
   freshness ladder, `Issue`, verify-after-sign, and the agent.
4. **Multi-domain**: root + home/aws/gcp, federation, sovereign-mode test.
5. **Hardening**: real seals, external audit anchoring, JIT/PAM, GitOps.
