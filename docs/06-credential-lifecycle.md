# 06 — Credential lifecycle

**Status: Draft**

## The split (Decided)

Two credential classes — the TGT/service-ticket, refresh/access factoring:

- **Session credential** — minted at authentication (attestation event).
  Proves *the principal is valid*: carries identity, `auth_time`, `amr`
  (method/strength). Carries **no roles**. Lifetime: hours (configurable
  per attestation source; homelab default 12h). Held by the agent,
  **sender-bound** to a key that never leaves the device (TPM / Secure
  Enclave / DPoP-style binding). **Caveat (E-01 AG-1, E-05):** "a stolen
  cache is inert" holds only where binding is hardware-backed — a software-key
  fallback (TPM-less Linux) travels with the cache, so there session TTL must
  be short and high tiers refused. Hardware binding stops key *exfiltration*,
  not key *use* by a local attacker driving the agent socket — the real
  control is socket peer-cred authz + per-use user presence (08), not
  non-exportability alone.
- **Role credentials** — minted *from* the session on demand, in whatever
  dialect the consumer speaks (OIDC token, X.509, SSH cert, KV lease).
  Carry role claims. Lifetime: minutes (default 15m; humans may get hours
  where policy allows).

**Every renewal is a fresh policy evaluation.** The agent trades the session
for new role credentials before expiry; the kernel re-reads the graph at that
moment. Grants and revocations propagate everywhere within one role-TTL, with
zero reauthentication and no invalidation protocol. Each layer refreshes at
the rate it needs: human authenticates per-half-day, policy consulted
per-quarter-hour, signatures verified per-request.

## The freshness ladder (Decided)

Enforcement lives at the **issuer** — the kernel controls what it is willing
to embed in an offline-verifiable credential. Per role (at scope), policy
selects a tier:

| Tier | Mechanism | Cost | Use |
|---|---|---|---|
| 1 Offline (default) | Role as normal claim; TTL is the freshness bound | Zero per-request | Everything, homelab |
| 2 Short-leash | Kernel caps TTL of any credential carrying this role | More renewals | Sensitive-ish roles |
| 3 Online-only | Kernel **refuses** to embed the role; token carries an opaque reference; resource must introspect (RFC 7662) | Per-use call | Crown jewels, where the resource cooperates (signet's own dialects guaranteed) |
| 4 Step-up | Exercising the role requires fresh interactive factor (`max_age` / RFC 9470); resource rejects, agent prompts (WebAuthn touch), signet re-mints with updated `auth_time` | Human tap | `ca-admin`, `vault-admin` — distinguishes "admin present now" from "process holds admin's token" |

A tier-3 claim in an offline token is *structurally impossible*, not merely
requested — security never depends on relying-party goodwill.

**Tier is a role attribute, not a binding condition (E-13 F3):** the freshness
tier lives on `RolePolicy` (13), writable only by the role's owner; bindings
may only *raise* requirements (strictest-wins), so a second weaker binding
cannot downgrade a tier-3/4 role. This gives the gate a single authoritative
input.

**Enforcement point (E-01 K-2 — v1 requirement):** the tier gate is enforced
**once, centrally, in the mint path** (issue → claims → filter → serialize);
every dialect serializes an already-filtered claim set and no serializer can
expand a tier-3 role (it carries an `opaque-ref-only` marker the serializer
physically cannot expand). A *missing* freshness/tier signal is treated as
**insufficient, never satisfied** (fail closed — real IdPs ship the
opposite failure). Named property test across all present and future dialects
+ the per-audience filter: *no offline credential ever carries an online-only
role* (10).

**Session-key rotation (E-01 DB-3 — KRBTGT lesson):** the session-signing key
is the golden-ticket key; it must be **fast-rotatable** with the
double-rotation dance so a rotation actually invalidates already-forged
sessions (natural expiry alone won't). Keys are separated by function
(intermediate CA ≠ session ≠ role ≠ KV data key) and rotate independently.
Forged-session window = session-key TTL; document the recovery ceremony (11).

## Conditional claims (Decided in principle)

Issuance rules over session metadata: *embed role R only if `amr` includes a
hardware factor*; *only within 1h of `auth_time`*. Risk-adaptive behavior as
issuance policy, not new protocol.

## Revocation

- Primary: stop renewing (TTL bounds the window; state accepted windows in 01).
- Sessions: individually killable server-side (renewal fails immediately).
- Backstop for long-lived X.509 (should be rare): CRL per intermediate;
  subtree kill = revoke the intermediate (02).

## Open questions

- Sender-binding mechanism per credential type: mTLS-bound vs DPoP-style
  proof-of-possession — and what each OS keystore supports (Mission E-05).
- Token format: JWT everywhere, or CWT/COSE for constrained consumers?
  (Biscuits/macaroons evaluated and likely rejected — offline attenuation
  duplicates what scoped issuance already gives us; confirm.)
- Renewal storm behavior: jitter, backoff, and grace overlap when a domain
  controller restarts.
- ~~Lease semantics for the KV dialect~~ **Largely answered by E-06**: no
  consumer in our set renews tokens or uses leases — Vault-dialect logins
  issue short-TTL, non-renewable service tokens (`renewable: false`,
  static lease fields); `lookup-self` must report live remaining `ttl` (JSON
  number) and `expire_time`. TTL-on-credential is enough; no lease manager
  in v1.
