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

Role bindings, attestation mapping rules (04), **and group-membership edits**
(E-13 F2) are authorization-bearing writes and obey delegation-only-narrows: a
delegated admin of subtree S may only create grants producing principals and
grants at or below S, enforced at write time and re-checked at issuance. For
group membership specifically, the effective grant of *(member M via group G
bound at S)* is re-checked **as if `grantor(membership)` had granted M at S
directly** — so editing a group that someone else bound at `/` requires
authority at `/`. This is the ESC1 class — the most likely path to vertical
escalation — property-tested (10) across bindings **and membership edits**.

**Roles carrying different labels at shared RPs (E-13 F14):** roles are
domain-namespaced (13) but the serialized claim is a bare label. An RP trusting
two Signet domains (or Signet + anything else) **MUST scope its role→permission
map per issuer** — else `infra-admin` from `aws` grants what `home`'s
`infra-admin` was meant to. This is the config boundary doing authorization
work (DB-2); state it wherever the narrow-waist contract is documented for RPs.

Additive-only grants (no first-class deny) preserve local reasoning; the
"admin everywhere except X" escape hatch is domain topology (13 / Reconsideration).

## Per-audience claims (Decided: design room now, implement later)

At scale, tokens for different audiences should carry different role claims
(audience-scoped filtering). v1 ships a single `groups` claim; the claims
pipeline is built as *issuance → filter chain → serialize* so audience
filtering is a later filter, not a rework. **The central tier gate (06) sits
in this pipeline and the future per-audience filter must not bypass it** — a
tier-3 role must remain unexpandable into any offline token (E-01 K-2).

## Resolved (by doc 13 / E-13)

- **Role granularity**: bare labels + a `RolePolicy` object carrying the
  security floor (tier/amr/max_ttl) — the tier had to be a role attribute, not
  a binding condition (F3). Not general structured attributes (ABAC creep).
- **Nesting**: roles stay **flat**; groups provide membership, resolved flat at
  issuance. No role-implies-role.
- **Deny**: **additive-only, decided.** "Admin everywhere except X" is
  inexpressible by design; the escape hatch is domain topology (a subdomain is
  the deny boundary). **Reconsideration**: the AD block-inheritance /
  inheritance-barrier-node alternative is explicitly rejected — it destroys
  local reasoning; do not reintroduce without a written case here.

## Open questions

- Audit event schema for every policy evaluation (feeds 10/11).
