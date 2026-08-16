# Signet design documents

Each document is a living design record: what's decided, why, and what remains
open. Agent explorations (see [explorations/](explorations/README.md)) feed
findings back into these documents — the doc is the destination, the
exploration is the raw material.

## Status legend

| Status | Meaning |
|---|---|
| **Decided** | Settled. Reopening requires a written case in the doc's Reconsideration section. |
| **Draft** | Direction chosen, details in motion. Safe to build prototypes against. |
| **Open** | Genuinely undecided. Contains exploration prompts. |

## Index

| Doc | Topic | Status |
|---|---|---|
| [00-charter](00-charter.md) | Scope, first deployment, non-goals | Draft |
| [01-threat-model](01-threat-model.md) | Attackers, blast radius, partition requirements | Draft (E-01) |
| [02-trust-topology](02-trust-topology.md) | Kernel model, hierarchy-as-PKI, federation, trust config | Draft (E-01/E-02) |
| [03-consistency-storage](03-consistency-storage.md) | Per-domain Raft, storage engine, backups | Decided (E-03) |
| [04-identity-attestation](04-identity-attestation.md) | Principals, attestation plugins, upstream IdPs | Draft (E-01) |
| [05-authorization](05-authorization.md) | Scoped RBAC on a tree, roles as narrow waist | Draft (E-01) |
| [06-credential-lifecycle](06-credential-lifecycle.md) | Session/role split, freshness ladder, agent renewal | Draft (E-01) |
| [07-dialect-roadmap](07-dialect-roadmap.md) | OIDC, Vault-KV, SSH, ACME, SAML sequencing | Draft (E-06) |
| [08-agents-platforms](08-agents-platforms.md) | Workstation/host agents, native shims, k8s story | Draft (E-01) |
| [09-module-layout](09-module-layout.md) | Go layout, dependency budget, footprint targets | Open |
| [10-testing-strategy](10-testing-strategy.md) | Unit, property, fuzz, partition, interop matrix | Draft (E-01) |
| [11-operations](11-operations.md) | Seal/unseal, backups, packaging, observability | Open |
| [12-governance](12-governance.md) | License, disclosure, decision process | Open |

## Conventions

- Documents state **decisions first, rationale second, open questions last**.
- Every open question that warrants deep investigation gets an exploration
  mission in [explorations/README.md](explorations/README.md).
- No secrets, ever. Example configs use placeholder values.
