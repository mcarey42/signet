# 07 — Credential dialects & roadmap

**Status: Draft**

Dialects are thin serializers over the kernel decision. Sequenced by leverage
against the first deployment (replace OpenBao, add SSO) and by risk.

## v1 — the homelab-replacing core

1. **OIDC / OAuth2 provider** (Core, discovery, PKCE, device flow RFC 8628;
   token exchange RFC 8693 later). Consumers: Grafana, ArgoCD, Harbor,
   Proxmox, kubectl OIDC. This is the identity win and the Keycloak
   replacement. First-class from day one.
2. **Vault-compatible API — the Compat Line is decided** (E-06, from pinned
   consumer source): **Tier A ≈ 15 routes, bug-compatible** — 5 auth
   (kubernetes/approle/userpass logins, `token/lookup-self`, `revoke-self`),
   7 KV v2 (data get/put+CAS, metadata get/put, list, soft-delete, destroy),
   2 sys (`sys/internal/ui/mounts/:path` — required by the `bao` CLI's
   preflight even with `-mount=`, not by ESO which does zero mount discovery;
   `sys/health` — hard-required by cert-manager's status-code branch AND by
   inframonitor which asserts `initialized`/`sealed` booleans in the body),
   1 PKI (`pki/sign/:role` — the homelab signs CSRs exclusively; `issue` is
   Tier B). Tier C with evidence: namespaces, wrapping, transit, leases,
   Enterprise consistency/412. Bug-compat traps that get conformance tests:
   lookup-self `ttl` must be a JSON *number*, mount-preflight
   `options.version` must be the JSON *string* `"2"`, `expire_time` key
   always present (null = non-expiring), missing secrets are
   `404 {"errors":[]}`, and LIST arrives as `GET ?list=true`. ~2–3k LoC of
   dialect code. Full spec: explorations/E-06-vault-compat.md.
3. **SSH certificates** (OpenSSH CA). Tiny surface, huge value: agent fetches
   short-lived certs, hosts get one `TrustedUserCAKeys` +
   `AuthorizedPrincipalsFile` line. Kills key sprawl fleet-wide.

## v1.x

4. **ACME (RFC 8555)** — cert-manager, Caddy, Traefik speak it natively;
   replaces fleet PKI rotation timers. (X.509 issuance itself exists from
   day one internally — ACME is the standard *ordering* front door.)
5. **X.509 workload identity** — SPIFFE-format SVIDs via the host agent;
   optional SPIFFE Workload API DaemonSet on k8s (08).

## Deliberately later

6. **SAML 2.0.** First-class *eventually* — it unlocks enterprise apps that
   will never speak OIDC — but it is the single most dangerous dialect to
   implement: XML-DSig canonicalization is a legendary CVE class (signature
   wrapping), and Go's stdlib has no XML-DSig, so this is either a carefully
   vetted dependency exception or a strictly scoped own implementation
   (IdP-side only, Redirect/POST bindings only, no encryption-by-default
   profiles). **Decision: SAML ships only after Mission E-07 (risk survey)
   and never blocks v1.** Homelab needs zero SAML; enterprises can bridge
   via OIDC→SAML proxies until it lands.
7. **SCIM** (provisioning inbound), **LDAP read-only façade** (legacy
   consumers), **RADIUS** (network gear) — demand-driven.

## Never (until reality forces it)

- Kerberos wire protocol, NTLM, WS-Fed. The ideas are in the kernel; the wire
  protocols are tar pits.

## Open questions

- OIDC conformance target: which certification profile (Basic + Device?) —
  Mission E-08 defines the minimal spec set that satisfies kubectl, Grafana,
  ArgoCD, Harbor, Proxmox, and Tailscale as clients.
- ~~Vault API compatibility breadth~~ **Answered by E-06**: the Tier A/B/C
  line above — approle *in* (cert-manager + ESO + fleet truenas_cert all use
  it), transit/wrapping/namespaces *out* with zero-call-site evidence.
  Consequences recorded elsewhere: Vault-dialect logins may issue short-TTL
  non-renewable service tokens — no consumer renews; lookup-self must report
  live remaining TTL (06). cert-manager can be served via `pki/sign` +
  `sys/health` *before* ACME lands, making the Vault issuer the bridge and
  ACME the successor (v1.x item 4). KV version history is a kernel storage
  requirement, not dialect state (03/09).
- Do we expose token introspection (RFC 7662) in v1 (needed for tier 3) —
  probably yes, it's small.
