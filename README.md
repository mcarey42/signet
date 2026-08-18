# Signet

Identity, PKI, authorization, and secrets in one binary.

> **Pre-1.0. Not recommended for production.** It works, it is tested hard, and
> there are 19 known open findings listed in
> [`docs/pentest/REGISTER.md`](docs/pentest/REGISTER.md). Read that before you
> deploy anything you care about.

Signet is one kernel — authenticate a principal, evaluate policy, mint a
short-lived scoped credential — with protocol dialects layered over it as thin
serializers. A Vault-compatible KV API, an internal CA, an OIDC issuer, and an
SSH certificate authority are all the same decision expressed four ways.

It exists because running OpenBao *and* an identity provider *and* a CA means
running three sources of truth that disagree at the edges. The disagreements
are where the incidents live.

## What works today

Every row here means *verified against real client software*, not against a
test double. That distinction has earned its keep: nearly every consequential
bug in this project was found by running a real client.

| Capability | Proven by |
|---|---|
| **Secrets** — Vault KV v2: versions, metadata, CAS, soft delete/undelete/destroy | External Secrets Operator v2.9.0 and the `bao` CLI, unmodified |
| **Workload identity** — Kubernetes ServiceAccount attestation | ESO authenticating as itself, no shared secret anywhere |
| **Certificates** — internal CA, `pki/sign`, published chain | cert-manager v1.19; `openssl` verifying the results |
| **SSO** — OIDC discovery, JWKS, RFC 8693 token exchange | `kubectl` against a real Kubernetes API server |
| **SSH** — OpenSSH certificate authority | A real `sshd` accepting a Signet certificate |
| **Scoped RBAC** — component-wise scopes, delegation-only-narrows | Property tests over randomized tree shapes |
| **Privileged access** — eligible-vs-held, approval, step-up, kill | A live node refusing an authority until someone else approves |
| **Hardware custody** — PKCS#11 seal, keys generated in-token | SoftHSM2; the token refuses to export them |
| **Anchored audit** — hash chain, signed checkpoints, peer witnessing | A rollback attack the local chain calls valid and the witness refuses |
| **Trust bundles & federation** — anchors, epochs, cross-domain scoping | `openssl` verifying leaves against anchors fetched over HTTP |

## Quick start

```sh
make build
./signet genesis -data-dir ./data          # prints a root token
./signet serve   -data-dir ./data -listen 127.0.0.1:8200
```

```sh
export SIGNET_ADDR=http://127.0.0.1:8200 SIGNET_TOKEN=signet....
./signet kv put secrets/app password=hunter2
./signet kv get secrets/app
```

Vault clients work unmodified against the same endpoint:

```sh
VAULT_ADDR=$SIGNET_ADDR VAULT_TOKEN=$SIGNET_TOKEN bao kv get -mount=secrets app
```

## Design

The documents in `docs/` are the design record, written before and alongside the
code, and corrected when reality disagreed:

- [`00-charter.md`](docs/00-charter.md) — scope, non-goals, and the six decision principles
- [`01-threat-model.md`](docs/01-threat-model.md) — the STRIDE pass and what came out of it
- [`02-trust-topology.md`](docs/02-trust-topology.md) — hierarchy, anchors, and what sovereignty actually buys
- [`03-consistency-storage.md`](docs/03-consistency-storage.md) — Raft, bbolt, and the barrier
- [`13-kernel-data-model.md`](docs/13-kernel-data-model.md) — principals, bindings, scopes, JIT/PAM
- [`16-implementation-status.md`](docs/16-implementation-status.md) — what is built vs. designed, and the bugs that running real software found
- [`17-performance.md`](docs/17-performance.md) — measured numbers, and what is not yet measured

## Dependencies

Three, deliberately: `hashicorp/raft`, `raft-boltdb`, and `bbolt`, plus
`golang.org/x/crypto` for SSH and `miekg/pkcs11` behind a build tag. Everything
cryptographic is Go's standard library. Metrics, JOSE, JWKS, X.509 profiles and
the audit chain are all hand-rolled, because the alternative was a dependency
tree an authority server should not have.

## Testing

```sh
make test         # unit and integration
make test-race    # the same under the race detector
make test-trust   # trust bundles, verified with openssl
make test-fabric  # a four-domain federation, including impersonation attempts
make test-pam     # privileged access against a live node
make test-audit   # audit rewrite attacks against two real domains
make test-hsm     # PKCS#11 against SoftHSM2
```

The end-to-end suites verify with **external** tools wherever possible —
`openssl`, `sshd`, `kubectl`, `bao` — because checking our own certificates
with our own verifier proves considerably less.

## Diagnostics

Tracing is off unless switched on and costs nothing while off:

```sh
./signet serve -data-dir ./data -trace-file /tmp/signet.trace -trace-areas authz
./signet trace help    # what a trace contains, before you share one
```

**A trace records paths and identifiers, never secret values or tokens.** Paths
often carry customer or project names — read
[SECURITY.md](SECURITY.md#️-before-you-send-us-a-trace-or-a-log) before sending
one to anybody, including us.

Prometheus metrics are also off by default (`-metrics-listen`), and label by
route *pattern* rather than concrete path so they are safe to scrape.

## Status and honesty

This project publishes its own vulnerability register, including the four
criticals that were the author's own work and the two occasions where a fix
introduced the next bug. A security tool that has not been attacked is one
whose bugs are merely unknown; the register is more useful to someone
evaluating this code than a clean-looking repository would be.

## Licence

[Apache-2.0](LICENSE).
