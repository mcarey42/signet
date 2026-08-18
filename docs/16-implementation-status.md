# 16 — Implementation status

**Updated: 2026-08-17**

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
| **Split CA ceremonies** — one offline root certifying many per-node issuers | Two nodes of different custody (file seal, PKCS#11) under one root; each leaf chains to it |
| **Trust bundles** — root-signed anchors + issuer set + revocation + epochs | `openssl` verifying leaves against anchors a consumer fetched over HTTP and chose between |
| **Anchored audit** — hash-chained log, signed checkpoints, peer witnessing with replay | A real rollback attack (keys intact) that the local chain calls valid and the witness refuses |
| **Multi-domain fabric** — several domains federated, bundles held separately and never merged | A 4-domain fabric (org root over home + gcp, sovereign aws) refusing cross-domain impersonation from both a shared root and a separate one |

## What is deliberately absent

Not oversights — each is scheduled with the milestone that needs it (docs/15):

- **Multi-node domains.** One voter, no join, no promotion, no network
  transport. Growing a domain is milestone 4; keeping the code absent is
  deliberate, because what is not there cannot be half-right.
- **Cross-certification and the sovereign-child cryptography.** A consumer can
  federate with several domains and verify each against its own bundle
  (milestone 4c). Still unbuilt: parent↔child-root cross-certificates, the
  self-certifying-namespace and key-transparency options in docs/02, and
  *server-side* federation — a node does not yet hold or serve links to peer
  domains, so the fabric lives in the consumer's state file.
- **Converting a live domain from subordinate to sovereign.** The two modes
  both work; there is no ceremony that moves an existing domain between them
  without re-issuing its leaves.
- **Online revocation.** Revocation rides the root-signed bundle, so
  withdrawing an issuer is an offline ceremony. Short-lived leaf revocation
  would need a delegated online signing key, which does not exist.
- **The agent.** Workstation and host modes (docs/08) do not exist. Kubernetes
  needs no agent, which is why the MVP could skip it.
- **JIT/PAM activation.** The data model supports it (docs/13); the activation
  API and approval flow do not exist.
- **GitOps reconciler.** Genesis loads declarative config once; there is no
  continuous reconciliation, drift detection, or plan/apply.
- **Audit anchoring outside Signet.** Checkpoints are witnessed by peer domains
  (milestone 5a); shipping them to an object-lock bucket or transparency log,
  for a domain with no peer, is not built. Nor is scheduling — witnessing runs
  when invoked, not on a timer.
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
6. **`-node-id` silently changed Raft's identity.** It renamed the consensus
   node as well as selecting an issuer, so the node was absent from its own
   cluster configuration and could not elect itself. It hung with no output.
   Consensus identity and issuer identity are now separate, and the election
   timeout names a renamed node as the likely cause.
7. **A relative `-data-dir` resolved the seal to `/seal.key`.** `file://` plus a
   relative path parses its first segment as a *host*, so the seal silently
   pointed at the filesystem root and failed naming a file the operator had
   never mentioned. Paths are made absolute, and the URL parser rejoins host
   and path so no caller can reintroduce it.
8. **OpenSSL refuses a non-self-signed trust anchor** unless given
   `-partial_chain`; Go's `crypto/x509` accepts one. Pinning to an intermediate
   — a mode docs/02 offers deliberately — therefore works in Go and fails in
   OpenSSL for reasons unrelated to the certificates. Found by verifying real
   leaves with the real tool. Signet now warns at the point of selection rather
   than presenting the two anchor modes as equivalent.
9. **Clock-skew tolerance was silently extending every bundle's life.** Skew
   was applied to the staleness check as well as the future-dated one, so a
   bundle stayed usable for a full skew window — five minutes, as every caller
   passed — past the point it was declared stale. The unit test missed it by
   passing zero skew while no real caller did; a two-second bundle checked
   three seconds later with the real binary caught it immediately. Skew now
   applies only where clocks genuinely disagree, and the test uses the skew
   callers actually pass.
10. **A sibling domain could impersonate another under a shared root.** Every
    subordinate domain's issuer descends from the organizational root, which is
    the anchor in every sibling's bundle — so a certificate from home's issuer
    bearing a gcp identity built a genuinely valid chain to gcp's anchor as
    soon as the presenter supplied its own intermediate, which is what every
    TLS peer does. Fixed by requiring the chain to run only through issuers the
    domain published. The lesson generalizes: *building a path to an anchor is
    not proof that the anchor's owner vouched for the certificate.*
11. **A genesis config key was silently ignored.** `allowed_uri_prefixes` was
    accepted, dropped, and the resulting refusal named the PKI role rather than
    the config — so the config looked applied and was not. Unknown keys are now
    a hard error, because a quietly ignored key is indistinguishable from one
    that worked.
12. **Publishing a bundle needed the node stopped.** The first implementation
   wrote through the local store, which the running server holds — meaning a
   monthly bundle refresh would have been a monthly outage. Publishing is now
   an authorized API write, verified kernel-side against the root the node
   already chains to.
13. **The first audit e2e tested the easy attack and I nearly kept it.** Wiping
    a node and rebuilding it was caught — but by the *checkpoint key changing*,
    not by the chain, so the rewrite-detection path never ran and a genuine
    conflict was never recorded. Rewritten to roll the node back to a real
    earlier state with every key intact, which is what an attacker with the box
    would actually do. That is the run that exercises replay divergence. The
    weaker test passed; it just was not testing the thing.
