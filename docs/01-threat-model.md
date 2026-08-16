# 01 — Threat model

**Status: Draft** (was Open; completed by exploration E-01, folded 2026-08-16)
Full STRIDE catalog + prior-art citations:
[explorations/E-01-threat-model.md](explorations/E-01-threat-model.md)

## Purpose

Drives every other decision: which attacker, what blast radius, what must
survive partition, and what we explicitly do not defend against. Security
properties are enforced **at the issuer** (what Signet is willing to mint),
per charter principle 3 — never dependent on relying-party goodwill.

## Assets

- Domain **root CA keys** (offline) and **online intermediate** signing keys.
- **Session-signing** and **role-signing** keys — the golden-ticket-equivalent
  keys: theft = forge any session/role credential (the Kerberos KRBTGT
  analogue).
- **Session credentials** (agent-held, sender-bound) and **role credentials**.
- The **identity graph, role bindings, and mapping rules** (integrity first;
  confidentiality too — the graph is a target map).
- The **KV secret store** contents (confidentiality + integrity).
- The **audit log** (integrity, completeness — itself a security asset).
- **Attestation trust anchors** (k8s issuer JWKS, TPM/vendor CAs, upstream IdP
  keys, cloud IID signers) and **federation bundles / pins**.
- The **seal / at-rest data key** and backups.

## Trust boundaries

Per-domain Raft group (linearizable within a domain); between domains only
signed artifacts flow (eventually consistent). The running server process is
a single trust boundary holding live signing keys + KV plaintext (see
Concentration). Each agent↔daemon IPC socket is a local trust boundary. Each
relying party verifies offline by default and is trusted only to enforce what
its own verifier enforces.

## Attacker classes

- **Stolen workstation / agent cache** — mitigated by sender-binding, *as
  strong as the platform keystore* (TPM/Secure Enclave strong; software-key
  fallback weak — then TTL is the bound). [E-05 quantifies]
- **Compromised workload** holding a valid short-lived credential — bounded by
  role-TTL; tiers 2/3/4 shrink it for sensitive roles.
- **Compromised relying party** — including one whose **clock** the attacker
  controls (extends stolen-credential life; crown jewels use online tiers).
- **Compromised child domain / malicious delegated admin** — bounded by name
  constraints *where the RP enforces them* + issuer-side path validation +
  short intermediates + scoped mapping-rule writes (per-dialect matrix in 02).
- **Compromised parent domain** — can silently re-issue a child's intermediate
  and impersonate the subtree (see DB-1 / Sovereignty).
- **Network attacker** at enrollment/bootstrap/renewal/bundle-refresh — MITM,
  bundle rollback, rogue-server renewal — mitigated by out-of-band
  fingerprints, monotonic bundle epochs with fail-closed staleness, agent
  pinning.
- **Malicious insider** with delegated admin at a subtree — bounded to that
  subtree by delegation-only-narrows in *both* bindings and mapping rules.
- **Signet server compromise (RCE)** — the concentration case: one process
  holds intermediates + signing keys + KV plaintext.
- **Attestation-confusion attacker** — replays evidence valid for one verifier
  into another; mitigated by per-verifier iss/aud/JWKS pinning + a
  Signet-specific audience.

## DESIGN-CRITICAL findings (resolved positions)

1. **"Sovereign child" under hierarchy-as-PKI is a contradiction** [CRIT].
   A parent CA can, offline, mint a second name-constrained intermediate for a
   child and impersonate its whole subtree; RPs pin the root, so the child
   cannot prevent or locally detect it (the nested-SPIRE / enterprise-CA
   property; CT/RFC 6962 exists precisely because chain validity can't tell an
   authorized-but-illegitimate re-issuance from a legitimate one). Position:
   *availability sovereignty* is real and retained; *authority sovereignty
   against a superior* is achieved **only by being one's own root and
   federating as equals**. Optional intermediate-pinning / a transparency-epoch
   log give **detection**; **co-signing** gives **prevention** at the cost of
   offline parent re-issue. Docs 00/02 corrected to say this plainly.

2. **Delegation-only-narrows depends on RP name-constraint enforcement, weak on
   URI SANs and absent for OIDC/KV** [CRIT]. Confirmed by E-02: DNS enforced
   widely, URI constraints break webpki-family verification, and OIDC/KV don't
   chain-verify at all. Position: issuer-side path validation + verify-after-
   sign + short-lived intermediates are **primary**; RP-side enforcement is
   defense-in-depth. Per-dialect boundary documented in 02.

3. **Concentration: one RCE = domain-total, and the session key is a
   golden-ticket key** [CRIT, accepted + hard-mitigated]. The live process
   holds the intermediate CA key + session/role-signing keys + KV data key; one
   memory read forges anything and decrypts everything, and offline
   verification means forgeries can't be recalled (cf. Vault CVE-2025-6000, the
   first public Vault RCE). Position: support **HSM/TPM/KMS-resident signing**
   so RCE = key *use during uptime*, not *exfiltration*; **separate keys by
   function** with independent fast rotation (KRBTGT double-rotation lesson);
   **crown-jewel secrets on tier-3**; **whole-store + KV envelope** so backups
   are inert; per-domain process isolation caps blast radius to one domain.
   Residual risk stated: in-memory keys ⇒ domain-total + offline-forgeable;
   external custody ⇒ forgeries stop at key-use revocation / process kill.

## Known tensions — resolved

1. **Concentration** → DESIGN-CRITICAL 3. HSM/TPM-resident signing is the
   recommended hardening on capable hardware.
2. **Revocation window with offline verification.** TTL = revocation latency.
   Accepted windows per class:

   | Credential class | Default window | Shrink lever |
   |---|---|---|
   | Role credential (OIDC/KV/SSH/X.509 leaf) | ≤ 15 min | tier-2 short-leash; tier-3 online ≈ 0 |
   | Session credential | hours (12h homelab); killable server-side, bites at next renewal | shorter TTL on weak-binding OS; tier-4 step-up |
   | X.509/SSH cert | cert TTL (minutes–hours) | CRL per intermediate as backstop |
   | Intermediate CA | ~90d, re-issued from offline root | decline renewal = subtree kill |

   Clock caveat: TTL bounds hold only within tolerated skew; a clock-controlled
   RP can extend a credential — crown jewels use tier-3 online (clock-independent).
3. **Parent power over children** → DESIGN-CRITICAL 1.

## v1 must-fix controls (promoted from "open questions" by E-01)

- **Scoped mapping-rule writes** — delegation-only-narrows applies to mapping
  rules too (the ESC1 analogue); enforced at write *and* re-checked at
  issuance. [K-1 → docs 04/05]
- **Central tier-gate enforcement** in the mint path; no dialect serializer can
  expand a tier-3 role; missing freshness/tier signal = insufficient (fail
  closed). [K-2 → doc 06]
- **Per-verifier iss/aud/JWKS pinning + a Signet-specific audience** on every
  JWT-shaped verifier; verifier selected by config, never inferred from the
  token. [AT-0/1/2/3 → doc 04]
- **Peer-cred IPC authorization** on agent sockets/pipes. [AG-2 → doc 08]
- **Monotonic bundle epochs + fail-closed staleness + root-SPKI pinning**;
  **restore** guarded by a monotonic epoch with revocation tombstones that
  survive restore. [FED-1, ST-1 → docs 02/03/11]
- **Hash-chained + externally-anchored audit log** — the compromised process
  must not be able to erase its tracks. [AL-1 → doc 11]
- **PCR-bound / measured-boot seal** for TPM auto-unseal; least-priv audited
  KMS. [SEAL-1 → doc 11]
- **Whole-store at-rest envelope** so backups are uniformly inert (KV
  double-enveloped on top). [ST-2 → doc 03]

## Explicitly out of scope (accepted risk)

- **Root/administrator on a machine** can impersonate any local agent principal
  — the OS owner owns the agent. Multi-user protection is against *peer* users.
- **Root-domain key compromise** is domain-existential, recoverable only by
  re-bootstrapping trust; we minimize exposure (offline, air-gapped
  ceremonies), we do not "defend" it.
- **Upstream IdP account takeover** transitively yields a Signet session;
  mitigated by requiring phishing-resistant WebAuthn for high-tier roles
  regardless of how the session was born — not by defending the upstream.

## Feeds forward

E-02 (name constraints — done, confirmed DB-2), E-04 (attestation ceremony
hardening — AT-*), E-05 (sender-binding strength per OS — AG-1), E-09 (seal
ceremonies — SEAL-1), E-12 (federation artifact format — FED-1/2).
