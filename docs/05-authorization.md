# 05 — Authorization

**Status: Draft**

## Model: scoped RBAC on a hierarchical resource tree (Decided)

- **Roles bind at a node of the tree and inherit downward.**
  `mcarey` holds `infra-admin` at `/`; `eso@cluster-svc` holds
  `secrets-reader` at `/clusters/svc/`.
- **Delegation only narrows.** A delegated admin of `/clusters/lab` can grant
  roles at or below `/clusters/lab`, never above — mirroring (and at domain
  boundaries, *enforced by*) PKI name constraints.
- **Policy is data, not code.** No Turing-complete policy language in v1.
  Bindings are rows; evaluation is a tree walk. Property-testable.
- Pure-RBAC role explosion is avoided by the scope dimension (role × subtree),
  not by adding a policy language. ReBAC/Zanzibar rejected: requires the
  global database we deliberately don't have.

## The narrow waist (Decided)

Signet is authoritative for **identity and role membership at scope** — never
for app-internal permission vocabularies.

- Signet answers: *who are you, which roles do you hold, where.*
- Each relying party owns the mapping *role → its local permissions*, in its
  own config, in its own vocabulary (Grafana: `infra-admin → Admin`;
  k8s: a `ClusterRoleBinding` for group `infra-admin`; sshd: an
  `AuthorizedPrincipalsFile` line).

Central authority without central vocabulary. Signet's own dialects (KV, CA,
admin API) are relying parties of the same kernel check — the proof the
abstraction holds.

## Delivery of rights (Decided — see 06 for the freshness ladder)

Rights ride **inside** signed short-lived credentials (OIDC `groups` claims,
SSH principals, cert SANs), evaluated at issuance. Relying parties verify
offline. Online introspection (RFC 7662) and step-up (RFC 9470) exist as
opt-in tiers — offline by default, online where the role's policy demands it.

## Mapping-rule & binding writes narrow (E-01 K-1 — v1 requirement)

Role bindings *and* attestation mapping rules (04) are authorization-bearing
writes and obey delegation-only-narrows: a delegated admin of subtree S may
only create bindings/rules producing principals and grants at or below S,
enforced at write time and re-checked at issuance. This is the ESC1
privilege-escalation class — the most likely implementation path to vertical
escalation — and is property-tested (10). Additive-only grants (no first-class
deny) preserve local reasoning.

## Per-audience claims (Decided: design room now, implement later)

At scale, tokens for different audiences should carry different role claims
(audience-scoped filtering). v1 ships a single `groups` claim; the claims
pipeline is built as *issuance → filter chain → serialize* so audience
filtering is a later filter, not a rework. **The central tier gate (06) sits
in this pipeline and the future per-audience filter must not bypass it** — a
tier-3 role must remain unexpandable into any offline token (E-01 K-2).

## Open questions

- Role definition granularity: are roles bare labels (narrow-waist purist) or
  do they carry optional structured attributes for conditional issuance rules?
- Group/role nesting: allow roles to imply roles (AD group-nesting trap) or
  keep flat? Leaning **flat** + scoped binding; nesting is where audit dies.
- Audit event schema for every policy evaluation (feeds 10/11).
- First-class "deny" bindings, or strictly additive grants? Leaning additive
  only (deny rules destroy local reasoning).
