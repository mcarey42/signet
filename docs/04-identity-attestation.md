# 04 — Identity & attestation

**Status: Draft**

## Principals

Everything that can hold a credential is a principal at a path in the tree:
humans (`/people/mcarey`), services (`/clusters/svc/apps/eso`), machines
(`/fleet/host-07`), and domains themselves. Principal IDs are expressible as
SPIFFE IDs (`spiffe://<trust-domain>/<path>`) so the X.509 dialect gets
standard workload identity for free.

## Attestation = pluggable evidence (Decided)

Enrollment and login are the same abstract operation: **present evidence,
receive a session credential**. Evidence verifiers are plugins behind one
interface — *"what principal does this evidence prove, with what strength?"*:

| Verifier | Evidence | Proves | Notes |
|---|---|---|---|
| `webauthn` | Passkey/security-key assertion | Human + hardware factor | Primary human auth |
| `oidc-upstream` | ID token from Google/etc. | Human (federated) | See below |
| `k8s-sa` | Projected ServiceAccount token | Workload on cluster X | **No agent needed on k8s** — the cluster is already an identity issuer; identical to Vault's k8s auth method, so ESO/cert-manager work unmodified |
| `tpm` | TPM 2.0 quote / DevID | Specific physical machine | Fleet hosts, workstations |
| `cloud-iid` | AWS/GCP instance identity document | Specific cloud instance | Cloud VMs |
| `join-token` | One-time human-approved token | Whatever the approver says | Universal fallback |

Each verifier maps evidence → principal via **mapping rules** stored in the
tree (e.g. *SA `eso@external-secrets` on cluster `svc` → `/clusters/svc/apps/eso`*).
Evidence strength and method ride into the session credential (`amr`,
`auth_time`) and feed conditional claims (06).

### Verifier hardening (E-01 — v1 requirements)

- **Mapping rules are authorization-bearing writes** and obey
  delegation-only-narrows: a rule authored by admin-of-S may only produce
  principals at or below S, enforced at rule-write time *and* re-checked at
  issuance (the ESC1 lesson — a field the issuer copies from a request must be
  validated against the requester's entitlements). Mapping-rule store is
  tier-3/step-up-worthy. [K-1]
- **Every JWT-shaped verifier** (`oidc-upstream`, `k8s-sa`, GCP `cloud-iid`)
  strictly pins expected issuer + JWKS (pinned/rotated, never
  requester-influenced URLs) and requires a **Signet-specific audience** no
  other system requests; the verifier is chosen by config keyed to `(issuer)`,
  never inferred from the token; mapping keyed by `(verifier, issuer, subject)`
  so the same `sub` under two issuers maps distinctly. Reject `alg=none`,
  reject symmetric algs for asymmetric issuers. [AT-0/1/2]
- **`k8s-sa`**: require `aud=signet://<domain>`, register each cluster issuer +
  pinned JWKS explicitly (no opportunistic discovery over untrusted paths),
  bind to `(cluster-issuer, namespace, SA)`, reject legacy non-expiring tokens.
  [AT-1]
- **`cloud-iid`**: require IMDSv2; GCP audience/nonce; AWS IID is TOFU-grade
  (static, locally readable) → first-seen instance-id binding + tight
  enrollment window + human approval; bind `(account, instance-id, region)`.
  [AT-3]
- **`tpm`**: fresh Signet nonce in the quote (anti-replay), EK cert chained to
  a pinned vendor CA, AK certified by EK, `ActivateCredential` PoP, human
  approval for first-seen hardware, parameter-encrypted sessions (bus-sniffing
  / TPM-reset are real). [AT-4]
- **`webauthn`**: single-use server challenges, strict origin/RP-ID binding;
  where a role needs a hardware factor, **verify attestation (AAGUID)** — a
  synced/software passkey must not inflate `amr` to "hardware"; check BE/BS
  flags, disallow synced credentials for privileged issuance. [AT-5]
- **`join-token`**: single-use, short TTL, scope committed by the approver at
  mint (not redemption), bound to the exact principal/node, out-of-band
  delivery, rate-limited. [AT-6]

## Upstream IdPs: exchange, don't cache (Decided)

"Login with Google" is just **human attestation**. Signet verifies the
upstream assertion once, at login, then mints its **own** session credential
with its **own configurable lifetime** (per-upstream: e.g. Google-attested
sessions live 12h). Roles are always evaluated locally — the upstream proves
*who you are*, never *what you may do*. We do not store or replay upstream
tokens; there is no dependency on the upstream being reachable after login.
Re-contact with the upstream happens only when the session expires (or policy
demands re-attestation).

## Open questions

- **Provisioning**: JIT-create principals on first upstream login (with what
  default placement in the tree?) vs pre-provisioned only vs SCIM sync later.
  Homelab: pre-provisioned is fine; the answer matters for org adoption.
- TPM enrollment ceremony details (EK → AK → DevID; who approves first-seen
  hardware). Mission E-04.
- Private/air-gapped k8s clusters: fetching the cluster's OIDC discovery keys
  when the issuer URL isn't reachable from signet (JWKS push? kubeconfig-based
  fetch?). Mission E-04.
- Evidence strength taxonomy: formal levels or free-form `amr` strings?
