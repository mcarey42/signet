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

Design phase. See [docs/](docs/README.md) for the charter, design documents,
and open questions. Nothing here is code yet — the documents are the product
right now.

First real deployment target: a homelab currently running OpenBao + fleet PKI,
replacing the secrets/PKI layer and adding identity/SSO — then generalizing.

## License

To be decided publicly before first code: Apache-2.0 or MPL-2.0
(see [docs/12-governance.md](docs/12-governance.md)).
