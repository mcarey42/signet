# 16 — Implementation status

**Updated: 2026-08-16**

The design documents describe where Signet is going. This one records where it
actually is, so a reader can tell the difference without reading the code. Every
"works" below means *verified against real client software*, not against a test
double — the distinction has earned its keep: every consequential bug this
project has hit was found by running a real client, never by a test I wrote.

## What works today

| Capability | Proven by |
|---|---|
| **Secrets** — full Vault KV v2: versions, metadata, list, soft delete / undelete / destroy, CAS, `max_versions` | External Secrets Operator v2.9.0 and the `bao` CLI v2.5.5, unmodified |
| **Workload identity** — Kubernetes ServiceAccount attestation | ESO authenticating as its own workload, no shared secret anywhere |
| **Certificates** — internal CA, `pki/sign`, published chain | cert-manager v1.19 obtaining certificates; `openssl` verifying them |
| **SSO** — OIDC discovery, JWKS, RFC 8693 token exchange | `kubectl` against a real Kubernetes API server, RBAC on Signet roles |
| **SSH** — OpenSSH certificate authority | A real `sshd` accepting a Signet certificate, no `authorized_keys` |
| **Scoped RBAC** — component-wise scopes, delegation-only-narrows | Property tests over randomized tree shapes |
| **Freshness tiers** — online-only roles structurally unembeddable offline | Property tests, including a serializer that tries to invent a role |
| **At-rest protection** — barrier + seal-held envelopes | No plaintext key material in the store, log, or backups |
| **Hardware seal** — PKCS#11 wrap/unwrap | SoftHSM; the domain refuses to start without the token |
| **Hardware-held CA** — root and intermediate generated in the token | The token refuses to export them; certificates still verify |
| **Seal rotation** — file seal → HSM, or HSM key → successor | A live domain rotated with every credential still valid |

## What is deliberately absent

Not oversights — each is scheduled with the milestone that needs it (docs/15):

- **Multi-node domains.** One voter, no join, no promotion, no network
  transport. Growing a domain is milestone 4; keeping the code absent is
  deliberate, because what is not there cannot be half-right.
- **Federation and sovereign mode.** Trust bundles, cross-certification, and
  the sovereign-child cryptography in docs/02 are designed but unbuilt.
- **The agent.** Workstation and host modes (docs/08) do not exist. Kubernetes
  needs no agent, which is why the MVP could skip it.
- **JIT/PAM activation.** The data model supports it (docs/13); the activation
  API and approval flow do not exist.
- **GitOps reconciler.** Genesis loads declarative config once; there is no
  continuous reconciliation, drift detection, or plan/apply.
- **Anchored audit.** Audit records are FSM state, hash-chaining and external
  anchoring are not yet built.
- **Backups.** The format is designed (docs/03) but no backup ships yet.
- **SAML, ACME, WebAuthn, TPM and cloud-KMS seals.**

## Building

```
make test         # unit and integration tests
make build        # static, pure-Go, no cgo
make test-hsm     # provisions a SoftHSM token, runs the seal tests against it
make build-hsm    # adds PKCS#11 support (requires cgo)
./test/kind/run.sh  # ESO + cert-manager against a real cluster
```

The default binary is static and pure-Go. PKCS#11 links a vendor C library, so
it lives behind a build tag — and a binary built *without* the tag **refuses** a
configured hardware seal rather than falling back, because a domain that
believes its keys are in an HSM and is wrong is worse off than one that will not
start.

## Bugs found by running real software

Kept as a record of where the value came from:

1. **Applied-index replay drift.** Raft replays committed entries on restart;
   because Signet's state is durable, a secret's version climbed on every
   restart. Determinism and idempotence are separate properties.
2. **`bao` sends version numbers as JSON strings.** Go's decoder appends a zero
   on the type error, so "undelete version 1" silently became "act on version
   0" — a destructive-adjacent call that returned success and did nothing.
3. **Kubernetes accepts only RS256 by default.** ES256 tokens were rejected
   outright, so token keys now default to the algorithm every consumer takes
   unconfigured.
4. **PKCS#11 `C_Initialize` is per-process.** Holding two seals at once — which
   is exactly what a rotation does — failed until modules were shared and
   reference-counted.
5. **Verify-after-sign caught our own design bug.** The CA excludes all IP
   ranges by default, which made it unable to issue its own `127.0.0.1` serving
   certificate. The certificate was signed, failed its independent check, and
   was withheld rather than returned.
