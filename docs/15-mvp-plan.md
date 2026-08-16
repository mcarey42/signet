# 15 — MVP vertical slice: plan, layout, structure

**Status: Draft** (for elegance + reduction review before code)

## Goal (the charter success criterion, one consumer)

A single-node `home` domain where **External Secrets Operator reads a secret
from Signet, unmodified**, via the Vault-KV dialect + k8s-SA attestation.
Stretch (cheap): `bao kv get -mount=… <path>` works too (adds the CLI mount
preflight + `sys/health`, which inframonitor already parses — E-06).

## The reduction that shapes everything: KV is an *online* dialect

The Vault-KV dialect uses **opaque bearer tokens with server-side lookup** — no
offline verification. So the MVP exercises the full kernel spine (identity,
policy, attestation, KV, storage, seal, audit) while needing **none** of the
offline-credential machinery. That machinery is deferred *with the dialects it
serves*:

| Deferred | Arrives with |
|---|---|
| Signing keys, JOSE, offline credentials, freshness tiers 2–4, sender-binding | OIDC + SSH dialects |
| Workstation/host agents | (k8s needs no agent — E-08) |
| Federation, trust bundles, multi-domain, sovereign mode, composite/PQC roots | multi-domain milestone |
| Full GitOps reconciler, JIT/PAM activation, groups | control-plane milestone |
| TPM/KMS/Shamir seal, per-subtree DEKs, external audit anchoring, CRL | hardening milestone |
| OIDC, SSH CA, ACME, SAML | dialect roadmap (07) |

## In scope (MVP)

- **Single-node Raft + bbolt** (real hashicorp/raft single-voter — not faked;
  it forces the FSM boundary honest and exercises snapshot/restore we need for
  backups anyway).
- **Barrier encryption** (whole-store) with the **simplest seal** (passphrase/
  file-derived key) behind the pluggable `Seal` interface. Per-subtree DEKs
  deferred.
- **Kernel**: principals, bindings, RolePolicy, scope-walk policy eval, KV
  (versioned), sessions (opaque tokens). Stable IDs + SPIFFE path grammar from
  day one (E-13 F1/F11 — cheap now, migration hell later).
- **k8s-SA attestation verifier**: pinned issuer + JWKS + required Signet
  audience (E-01 AT-1).
- **Vault-KV dialect**: `POST /v1/auth/kubernetes/login`,
  `GET /v1/auth/token/lookup-self`, `GET /v1/{mount}/data/{path}`; + CLI
  preflight (`sys/internal/ui/mounts`) + `sys/health` for the stretch. Reserved
  roles `kv-reader/writer/admin`; secret paths are tree nodes (E-13 F8).
- **Genesis ceremony**: root keypair generated in the tool, **never persisted
  to the FSM** (E-13 F6); minimal declarative config load (principals/bindings/
  k8s-trust) + `signet kv put`.
- **Audit event emission from the one write path** (hash-chain/anchoring
  deferred, but the emission call sites exist from day one).

## The elegant core: exactly one write path

Every mutation is an **`Op`** (tagged union: `PutPrincipal`, `PutBinding`,
`PutSecret`, `CreateSession`, …) **proposed through Raft**. `FSM.Apply` decodes
it and applies it to one bbolt transaction, emitting an audit event, under the
barrier. **One write path** ⇒ consistency, audit, and encryption are each
enforced in exactly one place, by construction — this is the structural
property that prevents sprawl. Reads go through a query API against a bbolt
read-tx snapshot (no writes, naturally consistent).

Hexagonal: the **kernel is the core** (dialect-blind, transport-blind, per
charter principle 5); **store, seal, attestation-verifier, and dialect are
adapters** behind interfaces. Interfaces exist *only where behavior actually
varies* — not as internal-to-kernel ceremony.

## Package layout (reduced — ~8 packages, 4 dependencies)

```
signet/
  cmd/signet/            # one binary: serve | genesis | kv (put/get)
  internal/
    op/                  # Op tagged union + codec — the write vocabulary
    consensus/           # hashicorp/raft glue: FSM Apply/Snapshot/Restore
    store/               # bbolt state + raft-boltdb log + barrier encryption
    seal/                # Seal interface + passphrase/file seal (MVP)
    kernel/              # principals, bindings, rolepolicy, kv, policy eval, sessions
    attest/              # Verifier interface + k8s-SA verifier
    dialect/vaultkv/     # Vault-compat HTTP handlers (ESO path + preflight + health)
    audit/               # audit event type + store-backed sink
  docs/ …
```

**Dependencies (whole MVP)**: `hashicorp/raft`, `raft-boltdb/v2`, `bbolt`, Go
stdlib (crypto/TLS/x509/JSON/HTTP). Nothing else. Confirms the doc-09 budget.

## The one open fork

**Real single-node Raft vs a faked in-process proposer for slice-zero.**
Recommendation: **real Raft.** hashicorp/raft single-voter bootstrap is a few
lines, it keeps the `FSM.Apply` boundary honest (a faked proposer risks a
wrong interface we rebuild later), and it gives us snapshot/restore — which the
backup design (03) needs regardless. The reduction lives in the *breadth*
(no OIDC/SSH/agents/federation), not in faking the consensus core.

## Testing (MVP)

- Kernel unit + **property tests**: scope-walk correctness, delegation-narrows
  (bindings + membership), tier-floor-cannot-be-lowered (E-13 F3).
- **E-06 conformance fixtures** against **real ESO in kind** (the bug-compat
  traps: ttl-as-number, `options.version` string, `404 {"errors":[]}`,
  `GET ?list=true`), + real `bao kv get` for the stretch.
- **Fuzz** the SA-JWT and Vault-JSON parsers.

## Milestones after the slice (for orientation, not scope)

1. **Slice**: ESO reads a secret (this doc).
2. **Consumers**: `bao` CLI + inframonitor health + cert-manager `pki/sign`.
3. **Offline dialects**: OIDC (kubectl/Grafana/ArgoCD) + SSH CA — brings the
   signing/JOSE/freshness/agent machinery online.
4. **Multi-domain**: root + home/aws/gcp, federation, sovereign-mode test.
5. **Hardening**: real seals, external audit anchoring, JIT/PAM, GitOps.
