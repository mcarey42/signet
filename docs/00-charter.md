# 00 — Charter

**Status: Draft**

## What Signet is

A single compact system providing **identity, authentication (SSO), PKI,
scoped RBAC, and secret storage** for distributed hybrid infrastructure —
sovereign-friendly: every trust domain remains fully operational while
partitioned from parents, peers, and clouds.

**Two meanings of "sovereign," kept distinct** (E-01 DB-1): *availability
sovereignty* — a domain keeps issuing and verifying while cut off from
everything — is real and is a core guarantee. *Authority sovereignty against
a superior* — being un-impersonable by your own parent — is **not** provided
by being a PKI child: a parent root can always mint a second intermediate for
a child's namespace. A domain that must be sovereign *against* a superior is
its own root and **federates as an equal** (see 02); it does not chain to a
parent. We never imply a PKI child is protected from its parent.

## What Signet is not (v1 non-goals)

- **Not an OS logon provider.** v1 agents supply credentials *to tools and
  services* (ssh, kubectl, browsers, daemons). PAM/LSA/loginwindow integration
  is deliberately deferred (see 08); it needs a dedicated test lab and its own
  release train.
- **Not a Kerberos KDC or an LDAP server** (wire protocols). Kerberos's ideas
  live in the kernel; its wire protocol does not. A read-only LDAP façade may
  come later for legacy consumers.
- **Not a general-purpose policy engine.** No Turing-complete policy language
  in v1. Policy is data: role bindings on a resource tree.
- **Not a public/WebTrust CA.** Private trust only.

## First deployment (design driver)

A homelab: 5 k3s clusters (GitOps/ArgoCD), a bare-metal fleet, macOS + Linux
workstations, AWS/GCP presence. Signet replaces **OpenBao** (KV secrets + PKI,
consumed by External Secrets Operator and fleet cert rotation) and adds
**identity/SSO** (OIDC for Grafana/ArgoCD/Harbor/kubectl, SSH certs for the
fleet). Success criterion: ESO, cert-manager, kubectl, and `ssh` all consume
Signet credentials **unmodified**, using protocols they already speak.

## Form factor

- One static **Go** server binary; also runs as `signet agent` (workstation/
  host modes). Targets: small cloud instances, Celeron-class hardware, k8s.
- OS-native agent shims (C / C++ / Obj-C) only where platform interop demands
  it, kept thin (see 08).
- Backup targets: S3, GCS, NFS/local — one snapshot+WAL interface (see 03/11).

## Decision principles

1. **Standards over invention.** If an RFC exists and fits, speak it (ACME,
   OIDC, RFC 7662, RFC 9470, SPIFFE IDs, ssh certs, Vault-KV API shape).
2. **Never hand-roll crypto primitives or consensus.** Go stdlib crypto; one
   vetted Raft library.
3. **Issuer-side enforcement.** Security properties must hold at the point we
   control (what gets minted), not depend on relying-party cooperation.
4. **Partition tolerance at the organizational level.** No feature may require
   cross-domain synchronous consensus.
5. **The kernel is dialect-blind.** Dialects serialize kernel decisions; they
   never touch storage or keys directly.
6. **Assured issuance — verify after sign.** Every credential is re-verified
   by an independent code path against the issuer's own constraints (name
   constraints, tier exclusions, TTL caps, scope) *after* minting and
   *before* release — the zlint-style post-issuance gate real CAs use. The
   verifier half never shares the builder half's assumptions. Cheap, and it
   converts whole bug classes from "mis-issued credential in the wild" into
   "issuance request failed loudly."
