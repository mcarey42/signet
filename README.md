# Signet

A compact, distributed authority for **identity, authentication, PKI, RBAC, and
secrets** — one Go binary, designed for sovereign hybrid infrastructure: cloud
nodes, on-prem servers, low-power hardware, and Kubernetes.

## The core idea

Kerberos, Active Directory, Vault, and Keycloak are the same abstract machine
wearing four protocol costumes:

> **Authenticate a principal → evaluate policy against an identity graph →
> mint a short-lived, scoped, cryptographically verifiable credential.**

Signet builds that machine **once** — the *kernel* (identity graph + policy
engine + key hierarchy + replicated log) — and exposes it through thin
*credential dialects*: OIDC tokens, X.509 certs (ACME), SSH certs, and a
Vault-compatible KV secrets API. A ticket, a cert, a token, and a lease are all
the same object: a signed claim of *who, what scope, until when*.

## Design pillars

- **Sovereign by construction.** Each trust domain runs its own small Raft
  group and stays fully operational while partitioned. There is no global
  database; federation between domains is the exchange of signed artifacts.
- **The hierarchy IS the PKI chain.** Parent domains delegate to children by
  issuing name-constrained intermediate CAs. Delegation, scoping, and subtree
  revocation are PKI operations every verifier enforces independently.
- **Short-lived everything.** Sessions are hours; role credentials are minutes;
  every renewal is a fresh policy evaluation. Revocation is mostly "stop
  renewing."
- **Authority without availability coupling.** Rights ride *inside* signed
  credentials (offline verification by default); online introspection and
  step-up auth exist as opt-in tiers for high-value roles.
- **Tiny and boring to operate.** One static binary (server + agent modes),
  runs on a Celeron, a t4g.small, or a k3s pod. Dependency budget: a Raft
  library, an embedded KV store, and Go's standard library crypto.

## Status

**MVP scaffold, first checkpoint green.** A single-node domain runs: genesis
initializes it, the Vault-compatible KV dialect serves reads and writes, scoped
RBAC bounds them, and state survives restart. See
[docs/15-mvp-plan.md](docs/15-mvp-plan.md) for what is deliberately deferred
(OIDC, SSH, agents, federation, internal CA) and [docs/](docs/README.md) for the
design record behind every decision.

```bash
make test && make build

# initialize a domain — prints a root token, writes a seal key
signet genesis -data-dir ./data -config genesis.json

# serve the Vault-compatible API
signet serve -data-dir ./data -listen 127.0.0.1:8200 -mount secrets

# write and read a secret
signet kv put -token "$TOKEN" -mount secrets apps/litellm master-key=sk-abc
curl -H "X-Vault-Token: $TOKEN" localhost:8200/v1/secrets/data/apps/litellm
```

`genesis.json` declares desired state — principals and the roles they hold at a
scope. Runtime state (sessions, tokens) is never declared:

```json
{
  "principals": [{"path": "/clusters/svc/apps/eso", "type": "workload"}],
  "bindings": [{"subject": "/clusters/svc/apps/eso",
                "role": "kv-reader", "scope": "/secrets/cluster-svc"}]
}
```

### Building

The toolchain needs `flock`, which this repo's NFS mount does not provide, so
the `Makefile` builds and tests from a local-disk mirror. On a normal
filesystem, plain `go build ./...` works too.

First real deployment target: a homelab currently running OpenBao + fleet PKI,
replacing the secrets/PKI layer and adding identity/SSO — then generalizing.

## License

To be decided publicly before first code: Apache-2.0 or MPL-2.0
(see [docs/12-governance.md](docs/12-governance.md)).
