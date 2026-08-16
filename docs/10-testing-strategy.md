# 10 — Testing strategy

**Status: Draft**

## Layers

1. **Unit tests** — full scope, table-driven, per module. Kernel issuance
   paths at near-total coverage; a signing bug is a security bug.
2. **Property-based tests** — policy evaluation is the flagship target:
   invariants like *delegation only narrows* ("no sequence of grants by a
   delegated admin of subtree S yields a credential valid outside S"),
   *additivity* (removing a binding never adds rights), *tier-3 exclusion*
   (no offline credential ever carries an online-only role). Named
   security tests from E-01: **mapping-rule scope containment** (a rule by
   admin-of-S never produces a principal above S — the ESC1 guard, K-1);
   **central tier-gate across all + future dialects** (K-2);
   **verifier audience/issuer isolation** (evidence for one verifier can't be
   replayed into another, AT-0); **bundle-epoch monotonicity + fail-closed
   staleness** (FED-1); **restore epoch-regression rejection** (ST-1);
   **clock-skew bounds** (TIME-1). A **cross-verifier name-constraint suite**
   (the E-02 15-case matrix through Go, OpenSSL, LibreSSL, pyca, rustls-webpki)
   runs on every issuance-profile change.
3. **Fuzzing** — every parser that touches untrusted bytes: ASN.1/X.509 paths
   (where CA CVEs live), JWT/JOSE handling, ACME JSON, SSH cert decoding,
   attestation evidence (SA tokens, TPM quotes). Go native fuzzing in CI,
   corpus checked in.
4. **Consistency/partition tests** — Jepsen-style harness on the store:
   linearizability within a domain under partitions, crash-restart, disk-full;
   federation convergence (bundle updates, revocations) under partition and
   reorder. Deterministic-sim first (in-process network shim), real-network
   second.
5. **Interop conformance matrix** — the release gate. Real clients against
   every release, in CI (kind + containers). The Vault-dialect pack pins the
   E-06 bug-compat traps as named fixtures: lookup-self `ttl` as JSON number,
   preflight `options.version` as string `"2"`, `expire_time` key presence,
   `404 {"errors":[]}` for missing secrets, `GET ?list=true` routing, and
   `sys/health` body booleans (inframonitor asserts them). Pin the consumer
   versions tested.
   - External Secrets Operator ← Vault-KV dialect
   - cert-manager ← ACME dialect (v1.x)
   - `kubectl` OIDC + real k8s API server ← OIDC
   - Grafana / ArgoCD / Harbor SSO ← OIDC (headless browser login flow)
   - Real `sshd`/`ssh` ← SSH CA dialect
   - k8s SA token attestation ← real projected tokens from kind
6. **Ladder end-to-end tests** — stolen-cache is inert (sender-binding),
   step-up round trip, introspection-required path, revocation propagation
   ≤ one role-TTL.

## Principles

- Interop tests use **real client software, never mocks of clients** — the
  ecosystem's behavior is the spec.
- Every security invariant claimed in docs 02/05/06 must map to a named test.
- The OS-logon shim lab (v2+) is a separate, snapshot-revertable VM matrix —
  logon-path bugs must never be discoverable in production.

## Open questions

- Jepsen proper vs a purpose-built deterministic simulator (FoundationDB
  style). Leaning: deterministic sim in-repo + occasional real Jepsen runs.
- Conformance suites: run the official OIDC certification suite locally?
  (Mission E-08 scopes this.)
