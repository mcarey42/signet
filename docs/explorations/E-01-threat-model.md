# E-01 — Threat model pass (STRIDE over kernel, store, attestation, agent, federation, seal)

**Status: Complete (awaiting fold-in review). Feeds: 01-threat-model.md**
**Author: exploration agent E-01. Date: 2026-08-16.**

> Findings are folded into `01-threat-model.md` after human review. This report
> is the evidence trail. A complete proposed replacement for `01-threat-model.md`
> is included as the final section.

---

## Question

Is Signet's architecture — per-domain Raft with no global DB; org hierarchy
expressed as name-constrained intermediate CAs; a session/role credential split
with sender-bound sessions held by local agents; a four-tier issuer-enforced
freshness ladder; pluggable attestation; and a Vault-shaped KV store in the same
process — sound against a motivated adversary? Specifically:

1. Are any architectural commitments **design-breaking** (unfixable without
   changing a "Decided" property)?
2. Do the three flagged tensions (concentration, revocation window, parent power
   over sovereign children) have concrete, honest resolutions?
3. What is the full STRIDE threat catalog per surface, with concrete mitigations?
4. What are the top-10 residual risks, ranked?

## Method / sources

- Close read of all 14 design docs (`00`–`12` + README + explorations register).
- STRIDE decomposition per surface: kernel (issuance path, policy eval, key
  hierarchy), store, each of the six attestation verifiers, the agent
  (workstation + host), federation (bundle exchange, bootstrap/TOFU, revocation
  transport), enrollment ceremonies, backups, seal, and time/clock.
- Prior-art mining against the most load-bearing analogues:
  - **ADCS ESC1–ESC16** certificate-template abuse (SpecterOps "Certified
    Pre-Owned" + follow-ups) — the canonical body of work on "PKI *is* the
    authorization system, and control over *what a CA will sign* is privilege
    escalation." Directly applicable to Signet mapping rules and issuance policy.
  - **Kerberos golden/silver/diamond tickets** — KRBTGT-key theft = forge any
    TGT; the exact analogue of Signet's session-signing key.
  - **HashiCorp Vault / OpenBao** seal, token, path, and k8s-auth CVEs — the
    concentration and secrets-store prior art.
  - **SPIFFE/SPIRE** node/workload attestation confusion, bundle/federation,
    nested-upstream authority — Signet's closest architectural sibling.
  - **OIDC/Keycloak/JOSE** alg-confusion, JWKS spoofing, refresh-token theft,
    DPoP/mTLS binding (RFC 9449 / RFC 8705), step-up (RFC 9470) downgrade.
  - **Cloud/TPM/WebAuthn attestation** replay and confusion.
- Confirmatory web research (name-constraint enforcement reality: Go
  `crypto/x509`, **CVE-2024-45341** URI-SAN constraint bypass via IPv6 zone IDs).

Citations are inline in the findings and collected under **Sources** at the end.

---

## Findings — the threat catalog

Notation per threat: **[ID] Title** — *Attacker position* → **Attack** →
**Impact** → **Mitigation** (or **Accepted risk** + rationale). STRIDE letter(s)
in brackets. Severity: **CRIT / HIGH / MED / LOW**.

### 0. DESIGN-BREAKING / design-critical findings (read first)

The user asked for bad ideas caught early. Three findings rise to
"change a Decided property or state the limit honestly, before code."

#### DB-1 — "Sovereign child" is a contradiction under hierarchy-as-PKI [E, S] — **CRIT / design-critical**

*Attacker position:* the **parent domain** (holds the domain root key, or any
ancestor CA), or an attacker who has compromised the parent.

*Attack:* the whole model rests on "the org tree is literally the cert chain"
(02) and relying parties pin the **root** trust anchor (a bundle carrying the
domain's root(s)). The parent issued the child a name-constrained intermediate.
But the parent's root can, at any moment and entirely offline, mint a **second**
intermediate bearing the child's *exact* name constraints
(`spiffe://child.example/…`), then issue leaf credentials anywhere inside the
child's namespace. Every verifier that trusts the root accepts these, because
they chain to the trusted root and satisfy the name constraints. The child
cannot detect this from its own Raft group (the issuance happened elsewhere) and
cannot prevent it, because RPs pin the root, not the child's specific
intermediate key. This is precisely the AD "enterprise admin / root CA
impersonates any child domain" property and the nested-SPIRE "upstream authority
can mint any downstream SVID" property. It is inherent to subordinate-CA
delegation.

*Impact:* the sovereignty claim as a *confidentiality/integrity* guarantee
against a superior is **false**. A parent (or compromised parent) can silently
impersonate any principal in any descendant subtree, mint OIDC/X.509/SSH/KV
credentials as them, and read any tier-1/tier-2 secret those credentials unlock.
"Every trust domain remains fully operational while partitioned from parents"
(00) is an **availability** property and *is* true; the docs conflate it with
sovereignty *against* the parent, which is not.

*Prior art (this is not speculative):* In **nested SPIRE**, "a compromised
UpstreamAuthority = whole-trust-domain compromise" and "SVIDs minted in a nested
configuration are valid in the **entire** trust domain, not only the scope of the
server that originated them" — the SPIFFE project documents that downstream
servers are *not* a security boundary and that isolation requires **separate
trust domains + federation**, not sub-delegation. In the CA world, TÜRKTRUST
(2013) and NIC India (2014) are concrete cases of a superior CA producing
subordinate/leaf certs that should not exist, and **Certificate Transparency
(RFC 6962)** exists precisely because chain validity **cannot** distinguish an
*authorized-but-illegitimate* re-issuance from a legitimate one — only an
external append-only log can. Blaufish (2025) further shows `pathLenConstraint`
does not stop a CA re-issuing (self-issued) CA certs. **Certifried
(CVE-2022-26923)** is the sharpest "a name field the requester influences becomes
the authorization identity" precedent.

*Mitigation / required doc change:* state the limit crisply and stop implying
otherwise.
- **Within one org**, parent-over-child power is correct and desired — the
  parent *is* more privileged; that is what the org tree means. Say so.
- **True sovereignty against a superior is only achievable via
  federation-between-equals** (02's peer model): the child is its own **root**,
  and peers/RPs pin *that* root. There is then no ancestor who can mint into its
  namespace. A "sovereign child" that chains to a parent root is a contradiction;
  offer it as **"be your own root + federate up,"** not "be a PKI child."
- Where an org wants a hierarchy but also wants *detection* of parent
  re-issuance, offer **optional child-intermediate pinning** for cooperating RPs
  (pin the child's intermediate SPKI, not just the root) and/or a
  **transparency/epoch log** of intermediates so a rogue re-issuance is
  *detectable* — but be honest that this is detection, not prevention, and that
  pinning the intermediate breaks free rotation and the "everything is derived
  from the chain" ergonomics. **Co-signing** (child + parent both sign the
  child's authoritative bundle, RP requires both) is the only *preventive*
  option and it forfeits offline/partition-tolerant re-issue by the parent — a
  deliberate trade for a genuinely adversarial parent.
- **Do not** claim protection Signet cannot deliver. The charter/02 language
  must be edited (see Impact on design docs).

#### DB-2 — Delegation-only-narrows depends on RP-side name-constraint enforcement, which is routinely weak [E, T] — **CRIT / design-critical**

*Attacker position:* a **compromised child domain** (or malicious delegated
admin who controls the child's online intermediate key).

*Attack:* "delegation only narrows — every independent verifier enforces this,
offline" (02) is only true for the **X.509/SSH** dialects, and only when the
*relying party's own verifier* enforces RFC 5280 name constraints on the SAN
type in use. For SPIFFE that means **URI SANs**, which are the worst-supported
case:
- Go `crypto/x509` only began enforcing name constraints on non-leaf certs in
  1.19, and **CVE-2024-45341** (2024) showed a URI with an IPv6 zone ID
  bypassing a URI name constraint — i.e. URI-SAN constraint checking has *shipped
  bugs in the reference stack Signet itself will use*.
- Browsers largely ignore constraints on non-DNS SAN types entirely; many TLS
  stacks (historically OpenSSL, Java, rustls varied) enforce DNS/IP/email but
  treat URI constraints inconsistently or not at all.
- **OIDC/JWT and KV dialects don't chain-verify at all**: an OIDC token is signed
  by the issuer's key and the RP validates `iss`/`aud`/signature, not a cert
  chain — name constraints are *irrelevant* to those dialects, so the "constraint
  bounds the child" protection simply does not exist for the two most important
  v1 dialects. A compromised child running its own Signet issuer signs its own
  OIDC/KV tokens with its own key; the only thing stopping those from being
  accepted elsewhere is that other RPs are configured to trust the *parent's*
  issuer, not the child's — which is a **configuration** boundary, not a
  cryptographic name-constraint boundary.

*Impact:* the blast-radius claim for a compromised child ("name constraints bound
it, verified offline by everyone") is **overstated**. For X.509/SSH it holds only
where the RP verifier is correct and current; for OIDC/KV it never held and the
boundary is instead "RPs are federated to the parent issuer, not the child."

*Prior art (the reference stack has repeatedly shipped constraint bugs, and the
SPIFFE spec itself concedes the mechanism is unreliable):*
- The **SPIFFE X509-SVID standard** states there is "a distinct **lack of support
  for URI-type name constraints in the wild**," makes them **OPTIONAL (`MAY`)**,
  and tells validators to bind an SVID's trust domain to the specific bundle it
  chained to *in application logic* rather than trust URI name constraints.
- Go `crypto/x509` constraint-enforcement CVEs, in the very stack Signet uses:
  **CVE-2024-45341** (URI SAN + IPv6 zone-ID bypasses a URI constraint —
  explicitly noted to affect SPIFFE-style private PKIs), **CVE-2025-61727**
  (wildcard SAN evades an excluded DNS constraint), **CVE-2026-33810** /
  **CVE-2026-27137** (excludedSubtrees case-sensitivity / email-constraint bugs),
  plus DoS in constraint checking (**CVE-2025-58187**, **CVE-2026-27138**) and the
  long-standing under-enforcement report golang/go **#59171**. *(Verify the exact
  fixed-version strings of the 2026 entries against pkg.go.dev/vuln before
  publishing.)*
- OpenSSL: **CVE-2021-3450** (STRICT flag overwrites the basic-constraints CA
  check → a leaf can act as an intermediate) and **CVE-2022-3602/3786** (buffer
  overflow *inside* name-constraint checking, triggered during mTLS client-cert
  validation).
- **AIKIDO-2025-10384** (SPIRE): a validator that trusts a federated peer to have
  checked its own token `exp` accepts indefinitely-valid tokens — the same class
  of "don't trust the other side to enforce your invariant."

*Mitigation:* this is exactly what mission **E-02** exists to quantify; E-01's
input to it:
- Treat RP-side name-constraint enforcement as an **assumption that frequently
  fails**, never as a load-bearing control. Keep the existing fallbacks:
  **Signet-side path validation at issuance** + **short-lived intermediates**.
- Make issuer-side enforcement primary (charter principle #3): Signet must refuse
  to *sign* anything outside a child's constraint at issuance time, so that even
  a non-enforcing RP is protected against a *Signet-mediated* issuance. This only
  protects against a compliant child; a *compromised* child's key can sign
  arbitrary leaves, and only a correct RP verifier catches that — so also
  **prefer Signet as the verifier where possible** (its own dialects) and
  document per-dialect exactly what bounds a compromised child (chain constraints
  for X.509/SSH *iff RP enforces*; issuer-federation config for OIDC/KV).
- Document the per-dialect matrix explicitly in 02/07; do not let one sentence
  ("every verifier enforces this") cover all four dialects.

#### DB-3 — One process holds live signing keys + session-signing key + KV plaintext: a single RCE is total domain compromise, and the session key is a golden-ticket key [I, E, S] — **CRIT / accepted-with-hard-mitigations**

*Attacker position:* remote code execution or memory-disclosure in the running
Signet server (a parser bug in ASN.1/JOSE/ACME/SSH-cert/attestation handling; a
dependency CVE; a side channel).

*Attack:* the running process necessarily holds, in memory, at once: (a) the
**online intermediate CA private key** (mint any X.509/SSH cert in the domain),
(b) the **session-signing key** and **role-signing key** (forge any session or
role credential — the Kerberos **KRBTGT / golden-ticket** analogue: steal the key
once, forge any principal's session offline, indefinitely, until the key rotates
or expires), and (c) the **KV data key** (decrypt every tier-1/tier-2 secret in
the store). Reading process memory once yields all three. This is the
"concentration" tension, concretely: the prize is strictly larger than any of a
standalone CA, IdP, or Vault, and one memory bug spends it all.

*Prior art (the concentration argument and the RCE it enables are both
published):* The 2025 **Cyata "Cracking the Vault"** disclosure produced
**CVE-2025-6000 — the first public Vault RCE** (a ~9-year-latent plugin-catalog
abuse giving arbitrary code execution + audit-free persistence) and
**CVE-2025-5999** (a policy-name normalization mismatch escalating admin→`root`).
Vault's own security model states it "is **not** an endpoint-detection tool that
kills a live, in-process compromise" — once unsealed, the barrier key and any
in-flight plaintext live in process memory and every authorized request is
honored until TTL/revocation. Aembit's **"Vault Fault"** analysis makes the
concentration point directly: a vault breach "exposes the entire secrets
inventory simultaneously," and CVE-2025-6000 even enabled "inverting Vault's
encryption in a ransomware-style attack." **The Signet-specific amplification:**
in split systems, an RCE in the KV engine does *not* by itself yield the CA or
IdP signing key — the process boundary is the containment. Signet removes that
boundary, so a -6000-class bug becomes **total identity-fabric compromise** (CA
key + session/role-signing key + KV DEK), not "just" secrets exposure; and a
-5999-class "reach root" bug now also reaches the signing keys.

*Impact:* domain-total. Every downstream credential and secret in that domain is
forgeable/readable for the lifetime of the exposed keys. Offline verification
*worsens* this leg: forged sessions/role-creds are accepted everywhere with no
call back to Signet, so there is nothing to "kill server-side" for a forgery.

*Mitigation (this is an accepted, inherent risk of the value proposition, but it
must be quantified and hard-mitigated, not waved away):*
- **Get signing keys out of process memory.** Support **PKCS#11 / TPM-resident /
  KMS-hosted signing** for the online intermediate, session, and role keys so RCE
  yields key *use during uptime* (bad, bounded, detectable) rather than key
  *exfiltration* (catastrophic, unbounded, offline). This is the single most
  valuable hardening and should be a first-class seal/keys option, not a v2 idea.
- **Separate keys by function** and rotate independently: CA-intermediate key ≠
  session-signing key ≠ role-signing key ≠ KV data key. One theft should not be
  all four; short-TTL intermediates + fast session-key rotation bound each.
- **KRBTGT lesson:** the session-signing key must be **fast-rotatable** (support
  the double-rotation dance so a rotation actually invalidates forged sessions),
  and it is itself a short-lived intermediate with a TTL ceiling. Document the
  forged-session window = session-key TTL, and the recovery ceremony.
- **Crown-jewel secrets on tier-3 (online-only)** so their plaintext is not
  derivable in bulk from one KV data-key read — the resource introspects per use
  (06 tier 3). Keep bulk KV enveloped so a *backup* leak is inert (03/11), but
  recognize envelope keys are in memory at runtime.
- **Shrink the parser attack surface**: fuzz every untrusted-byte parser (10
  already commits to this), minimize dependencies (09), and consider running
  attestation/dialect parsers with reduced privilege where the platform allows.
- **Per-domain process isolation** already bounds blast radius to one domain;
  keep it and never merge domains into one process to "save RAM."
- Quantify residual risk in 01: *with in-memory keys, RCE = domain-total and
  offline-forgeable; with HSM/TPM-resident keys, RCE = domain-total during uptime
  only, forgeries stop at key-use revocation / process kill.* That delta is the
  argument for making external key custody a supported, recommended default on
  capable hardware.

### 1. Kernel — issuance path, policy eval, key hierarchy

#### K-1 — Mapping-rule injection = the ESC1 analogue [T, E] — **HIGH**
*A delegated admin at subtree S, or anyone who can write evidence→principal
mapping rules.* Mapping rules live "in the tree" (04). If a delegated admin of
`/clusters/lab` can author a rule mapping *k8s SA `x` on cluster lab →
`/people/root-admin`* (a principal **above or outside** their subtree), they mint
a session for a superior principal on their own evidence — exactly ADCS **ESC1**
("I control what the certificate asserts, so I assert domain admin"). *Impact:*
vertical privilege escalation, bypassing delegation-only-narrows. *Prior art:*
the entire ADCS **ESC** corpus (SpecterOps "Certified Pre-Owned") is this bug
class — **ESC1** (enrollee-supplied SAN = any principal), **ESC4**
(write-access to a template → inject ESC1 conditions), and most exactly
**ESC13** (`msDS-OIDToGroupLink`: a certificate carrying a policy OID makes the
holder be *treated as a member of a privileged group* — "policy field carries
authorization," Signet's model almost verbatim) and **ESC15 / EKUwu**
(**CVE-2024-49019**: requester injects application-policy OIDs the CA fails to
validate, which then *override* the template's constraints at verification). The
lesson every ESC teaches: **any authorization-bearing field the issuer copies
from a request must be validated against the requester's own entitlements at
issuance, not merely against defaults.** *Mitigation:*
mapping rules are authorization-bearing writes and **must obey delegation-only-
narrows themselves**: a rule authored by admin-of-S may only produce principals
**at or below S**, enforced in the kernel at rule-write time *and* re-checked at
issuance (defense in depth). Property-test it alongside the delegation invariants
(10). Treat the mapping-rule store as a tier-3/step-up-worthy resource. This is
the single most important kernel control and mirrors why ADCS template ACLs are
the crown jewels.

#### K-2 — Freshness-ladder downgrade: tier-3 role smuggled into an offline token [E] — **HIGH**
*Attacker who can influence issuance (a bug, or a crafted claim request).* 06
claims a tier-3 claim in an offline token is "structurally impossible." That
property holds only if the **issuance filter chain** actually enforces it for
every dialect serializer. *Attack:* a serializer that copies role claims from the
session or from a request field, bypassing the tier filter, could emit a tier-3
role in a tier-1 JWT; or a per-audience filter (05, "design room now") added
later forgets the tier gate. *Impact:* crown-jewel role usable offline with no
introspection — the whole ladder defeated silently. *Mitigation:* the tier gate
must be enforced **once, centrally, in the mint path** (issue/ → claims → filter
→ serialize), never per-dialect; every dialect serializes an already-filtered
claim set. Named property test (10): *no offline credential ever carries an
online-only role*, fuzzed across all dialects and across the future per-audience
filter. Make it structurally impossible by construction: tier-3 roles carry an
`opaque-ref-only` marker the serializer physically cannot expand. *Prior art on
downgrade-by-omission:* RFC 9470 step-up is **advisory** — the RS must actually
enforce the returned requirement; real IdPs ship the failure mode where `amr`/
`acr` is simply **absent** and the enforcer defaults to "satisfied" (Entra v2
omits `amr`), and Keycloak **CVE-2026-37979** returned introspection claims
**regardless of audience**. The rule for Signet: treat a *missing* freshness/tier
signal as **insufficient, never satisfied** (fail closed), and canonicalize
method values so no semantic-mismatch downgrade.

#### K-3 — Confused-deputy / on-behalf-of issuance [E, S] — **MED**
*A relying party or dialect that can request issuance "for" another principal.*
Token-exchange (RFC 8693, roadmapped in 07) and any admin "impersonate" path are
classic confused-deputy vectors. *Impact:* privilege escalation / impersonation.
*Mitigation:* every issuance is attributed to an authenticated requester;
delegation/impersonation is an explicit, separately-authorized, audited role
(never implicit); token-exchange actor claims (`act`) preserved and scope only
narrows. Defer RFC 8693 until its own threat pass.

#### K-4 — Policy-eval scope-walk bugs [E] — **MED**
*Any principal, exploiting a tree-walk bug.* Inheritance-downward + delegation-
only-narrows are non-trivial to get right (off-by-one on path prefix, symlink-
like aliasing, trailing-slash confusion `/clusters/lab` vs `/clusters/lab-2`).
*Impact:* rights leak across sibling/parent boundaries. *Mitigation:* canonical
path handling (no substring matching — component-wise prefix only), the named
property tests already committed in 10, fuzz the path parser. Additive-only
grants (05) preserve local reasoning — keep that; reject first-class deny.

#### K-5 — DoS via expensive attestation / issuance [D] — **MED**
*Unauthenticated or low-cost remote caller.* TPM-quote verification, RSA/PQC
signature checks, and Raft leader single-writer apply are all CPU/serialization
bottlenecks; an unauthenticated attestation endpoint invites CPU exhaustion; a
renewal storm (agents reconnecting after a leader restart) self-DoSes. *Impact:*
issuance unavailability = credential starvation across the domain (though
partition-tolerance means *existing* creds keep working until TTL). *Mitigation:*
rate-limit + require cheap pre-auth before expensive verification; per-source
quotas; renewal **jitter, backoff, grace overlap** (06 already flags this — make
it a requirement); bound Raft apply cost; health endpoint distinguishes
"sealed/overloaded" from "down" (11).

#### K-6 — Key-hierarchy: online intermediate compromise vs offline root [S, E] — **HIGH**
Covered by DB-3 for the in-memory case. Additional: *root ceremony compromise* —
root is offline (good) but the **re-issue-intermediate** and **subtree-revoke**
ceremonies (11) are the moments the root key is live. *Mitigation:* root
ceremonies are air-gapped, multi-person where feasible, audited out-of-band;
root never touches the network; document PCR/quorum controls. Root compromise is
domain-existential and unrecoverable except by re-bootstrapping trust — accept
and minimize exposure. *Prior art — the golden-ticket lesson (this is why key
separation and fast rotation are requirements, not niceties):* in Kerberos,
**KRBTGT-key theft = forge any TGT** with any subject and any lifetime (golden
ticket); the standard remediation is to **rotate KRBTGT twice** to invalidate
outstanding forged tickets — natural expiry won't save you. Signet's
session-signing key **is KRBTGT**; splitting session-signing from role-signing is
genuinely stronger than Kerberos's single key, but only if renewal independently
verifies the other key and re-checks policy. **Diamond/Sapphire** tickets further
show an attacker who *re-mints or tampers a genuine* credential evades
"was-this-issued-by-us?" detection — hence the provenance-logging need in AL-1.

### 2. Store

#### ST-1 — Backup/snapshot rollback resurrects revoked state [T, E] — **HIGH**
*An operator, or an attacker with restore capability.* Restoring an older
snapshot rolls the identity graph and role bindings back to a prior epoch —
re-granting a revoked admin, un-deleting a removed mapping rule, resurrecting a
killed session. Offline verification means the resurrected grants immediately
mint valid creds. *Impact:* silent privilege resurrection; revocation undone.
*Mitigation:* monotonic **epoch/version counter** persisted and cross-checked;
revocation records are tombstones that must survive restore (never GC'd before
the credential TTLs they cover); DR runbook requires replaying revocations issued
after the snapshot; alert on epoch regression. Treat "restore" as a privileged,
audited ceremony (11), not a routine op. *Prior art:* Vault snapshots "contain all
secrets, encryption keys, and audit logs" — a snapshot is a crown-jewel artifact,
and the OAuth **refresh-token-rotation + family-reuse-detection** pattern is the
same monotonic-epoch idea applied to credentials (an old token in a rotated family
signals a fork → revoke the family).

#### ST-2 — At-rest confidentiality of the identity graph & bindings [I] — **MED**
Docs say KV is enveloped under a data key (leaked backup inert) but treat the
identity graph as *integrity > confidentiality* (01). A leaked backup therefore
discloses the **entire org structure, principals, roles, mapping rules, and
attestation anchors** — a reconnaissance goldmine and a map for targeting DB-1/
K-1. *Mitigation:* envelope the **whole store**, not just KV, so a backup leak is
uniformly inert without the seal (03 open question "whole-store vs per-tree" —
recommend **whole-store** envelope as the floor, KV double-enveloped on top).
Accept that runtime memory still holds plaintext (DB-3).

#### ST-3 — Raft log / on-disk tampering by a node operator [T] — **MED**
*An attacker with disk access to a domain node (esp. multi-node across clusters).*
Raft entries are typically not individually signed; a node with disk write can
forge applied state or replay. *Impact:* inject bindings/mappings. *Mitigation:*
data dir on local disk with strict perms; consider signed Raft snapshots / a
hash-chained apply log (ties to audit AL-1); full-disk encryption on nodes;
trust boundary = "node root is domain-trusted" — document it. NFS data dir
already forbidden (03) — keep it.

### 3. Attestation verifiers (per-verifier)

#### AT-0 — Verifier confusion: evidence for one verifier replayed to another [S] — **HIGH**
*Any holder of a JWT-shaped credential.* Four of the six verifiers accept
JWT/signed-document evidence (`oidc-upstream` JWT, `k8s-sa` JWT, `cloud-iid`:
GCP=JWT, AWS=PKCS7-signed JSON; `join-token`, `webauthn`, `tpm` differ). If
verifier selection is driven by attacker-controllable input, or if any verifier
under-validates `iss`/`aud`, a token minted for audience A (e.g. a k8s SA token,
or a Google ID token for some unrelated app) could be steered into a *different*
verifier and mapped to a more-privileged principal — a cross-method type/audience
confusion. *Impact:* attestation bypass → session for a principal the attacker
shouldn't get. *Mitigation:* each verifier **strictly pins** its expected
issuer, signing keys (JWKS with pinned/roated keys), and a **Signet-specific
audience** that no other system would request; the verifier is selected by
explicit configuration keyed to `(issuer)`, never inferred from the token; mapping
rules keyed by `(verifier, issuer, subject)` triples so the same `sub` under two
issuers maps distinctly. Reject tokens whose `aud` is not exactly Signet's. This
is a must-fix invariant, property-tested. *Prior art:* SPIRE **CVE-2021-27099**
(`aws_iid` path-normalization collapsed an attacker-controlled EC2 tag into a
*different* SPIFFE ID — the canonical "attestation confusion via normalization");
generic **JWT audience-confusion** ("treating JWTs as portable identity objects
instead of scoped assertions"); **algorithm-confusion** pre-auth account takeover
in real OIDC login code (e.g. ragflow). The systemic risk of running six
verifiers over overlapping JWT-shaped evidence is that a shared "is this JWT
valid?" helper checks *signature* but not *evidence type* — enforce
`(evidence-type, issuer, audience, expected-key-source)` as one atomic gate per
verifier, with **disjoint audiences per path**, and canonicalize-and-reject
non-normalized principal IDs at every boundary.

#### AT-1 — `k8s-sa`: audience/issuer confusion & cross-cluster replay [S] — **HIGH**
*A workload on any cluster whose issuer Signet trusts.* Projected SA tokens are
JWTs; without a required Signet audience and per-cluster issuer registration, a
token from cluster A replays as identity on cluster B, or a token minted for the
API server replays to Signet. Private-cluster JWKS fetch (04 open q) is a trust-
bootstrap problem: pulling discovery keys over an untrusted path lets an attacker
substitute keys. *Mitigation:* require `aud=signet://<domain>` on projected
tokens; register each cluster's issuer + pinned JWKS explicitly (kubeconfig-based
or pushed JWKS, pinned — not opportunistic discovery); bind mapping to
`(cluster-issuer, namespace, SA)`; reject legacy non-expiring SA tokens. *Prior
art:* Vault's k8s-auth **audience-not-enforced** bug (vault-plugin-auth-kubernetes
#175 — role `audience` was compared to itself, so a token minted for another
audience authenticated anyway); the long-lived `token_reviewer_jwt` anti-pattern
(#12951); and the cloud analogues **CVE-2020-16250/16251** (Vault AWS/GCP auth
bypass via forged `GetCallerIdentity` XML / fabricated GCE-metadata JWT) and
**CVE-2025-11621** (AWS-auth cache key omitted the account ID → cross-account
confusion). (Feeds E-04.)

#### AT-2 — `oidc-upstream`: JWT alg confusion, JWKS spoofing, upstream ATO cascade [S, T] — **HIGH**
*Network attacker on the upstream path, or an attacker who took over the user's
upstream (Google) account.* Classic JOSE pitfalls: `alg=none`, RS256↔HS256
confusion (verify with public key as HMAC secret), `kid` injection pointing at
attacker JWKS, unpinned JWKS rotation. Plus: "login with Google" means **upstream
account takeover = Signet session**. *Impact:* full impersonation. *Mitigation:*
strict allow-listed algs (no `none`, no symmetric for asymmetric issuers), pinned
issuer + JWKS, exact `iss`/`aud`/`azp`/`nonce`/`exp` validation, `at_hash` where
relevant. Exchange-don't-cache (04) is correct — keep it. Recognize upstream ATO
as an accepted transitive risk; mitigate by requiring WebAuthn (phishing-
resistant) for high-tier roles regardless of how the *session* was born
(conditional claims, 06). Fuzz the JOSE path (10). *Prior art:* Keycloak
**CVE-2026-11800** (JWT alg-confusion → forge assertions impersonating any
federated user), **CVE-2026-1486** (validates against a *disabled* IdP's key),
**CVE-2026-1180** (`jwks_uri` SSRF — fetches verification keys from an
attacker-controlled URL: **never resolve keys from requester-influenced URLs**);
the JOSE toolbox `alg:none`, RS256↔HS256, `kid` injection, `jku`/`x5u` spoofing.

#### AT-3 — `cloud-iid`: AWS/GCP instance-identity replay [S] — **HIGH**
*An attacker who obtains an instance's identity document (SSRF to metadata, log
leak, a co-tenant).* AWS IID = a static JSON + detached PKCS7 signature with weak
anti-replay; if the document leaks it can be replayed to impersonate that
instance until Signet's first-seen binding closes. IMDSv1 SSRF is the classic
exfil path; IMDSv2's hop-limit/token mitigates. GCP's identity is a short-exp
audience-bound JWT (better). *Impact:* rogue host enrolls as a real cloud
instance. *Mitigation:* require **IMDSv2**; require an **audience/nonce** where
the cloud supports it (GCP does; AWS IID doesn't — compensate with **first-seen
instance-id binding + tight enrollment window + human/one-time approval** for AWS,
i.e. treat AWS IID as TOFU-grade, not proof-grade); bind to `(account, instance-
id, region)`; short enrollment TTL. *Prior art:* IMDSv1 SSRF (Capital One, 2019)
and the fact that the AWS IID + its public-key signature are **static for the life
of the instance and readable by any local process** — so "IID valid" means "some
process on that instance spoke," not "the intended agent spoke." Note the nonce
footgun: a client that *persists* its anti-replay nonce to disk makes it readable
by co-tenant processes. (Feeds E-04.)

#### AT-4 — `tpm`: rogue-hardware TOFU, quote replay, EK↔AK binding [S] — **MED**
*An attacker enrolling rogue hardware, or replaying a captured quote.* First-seen
enrollment (04 open q) is TOFU — a rogue machine enrolling before the real one
wins the identity; quote replay without a fresh nonce forges liveness; a broken
EK→AK→DevID chain lets a key be certified by the wrong TPM. *Mitigation:*
enrollment requires a fresh Signet nonce in the quote (anti-replay), EK cert
chained to a pinned TPM-vendor CA, AK certified by the EK, human approval for
first-seen hardware (join-token-gated), and bind identity to the EK public via
**`ActivateCredential`** proof-of-possession; use TPM **HMAC + parameter-encrypted
sessions** and channel-binding to kill relay. *Prior art:* **TPM-FAIL
(CVE-2019-16863)** extracted an ECDSA attestation key over the network via a
timing side channel; **TPM bus sniffing** (Dolos/trmm.net) and the **TPM Genie**
interposer (NCC) forge `PCR_Extend`/quote responses on the serial bus; the **TPM
reset attack** replays a benign boot to reconstruct "clean" PCRs; and there is
"currently no way to authenticate a TPM," so blind cloud-init TOFU trusts whatever
EK/AK (or *software* TPM) is presented first. (Feeds E-04.)

#### AT-5 — `webauthn`: origin/RP-ID/challenge validation & synced-passkey `amr` inflation [S] — **MED**
*Phisher, or an attacker relying on weak server-side WebAuthn checks.* Server must
validate `origin`, `rpIdHash`, `type`, and single-use `challenge`; accepting
`attestation=none` or not checking AAGUID means a **synced/software passkey** is
indistinguishable from a **hardware** authenticator — yet 06's conditional claims
gate high-tier roles on "`amr` includes a hardware factor." Claiming hardware for
a synced passkey **inflates `amr`** and defeats step-up. *Impact:* step-up /
hardware-factor gate bypassed. *Mitigation:* single-use server-issued challenges,
strict origin/RP-ID binding, and — where a role's policy demands a hardware factor
— require and verify **attestation** (AAGUID allow-list / cert) rather than
trusting the client's word; treat synced passkeys as a *lower* `amr` tier — check
the backup-eligible (BE)/backup-state (BS) flags and disallow synced credentials
for privileged issuance. *Prior art:* **CVE-2026-30964** (webauthn-lib collapsed
origins to host-only, ignoring scheme/port → cross-origin assertions accepted);
**CVE-2025-26788** (StrongKey FIDO: start login as victim, sign the challenge with
the *attacker's own* passkey → account takeover, because the server didn't verify
the credential belonged to the claimed user); and the documented weakening of
hardware binding by iCloud/Google **synced passkeys** ("your passkey is weak").
(Feeds E-04.)

#### AT-6 — `join-token`: replay, leakage, approver phishing [S, E] — **MED**
*Anyone who intercepts a token, or who social-engineers the approver.* "Whatever
the approver says" (04) makes the approver the whole trust anchor. *Impact:* rogue
enrollment at approver-chosen scope. *Mitigation:* single-use, short TTL, bound to
the intended principal path/scope at mint time (approver commits scope up front,
not at redemption), delivered out-of-band, audited; rate-limit redemption
attempts. *Prior art:* Synacktiv "So I became a node" (AKS) — a low-priv
`hostNetwork` pod read the cluster **bootstrap/join token** from the metadata
service, then submitted **auto-approved** CSRs for `system:node:<any>` and
escalated to `cluster-admin`. The specific footgun is letting a join-token holder
request an identity for an *arbitrary/pre-existing* node; bind the issued identity
to the exact node the token was minted for.

### 4. Agent (workstation + host)

#### AG-1 — Cache theft vs sender-binding strength varies by OS [S, I] — **HIGH**
*Thief of a workstation / reader of the agent cache.* Sender-binding makes a
stolen cache inert **only as strong as the platform keystore**: TPM 2.0 / Secure
Enclave keys are non-exportable (strong); a **software-key fallback on a Linux
box without a TPM is weak** — the binding key sits on disk and travels with the
cache. *Impact:* on weak-binding platforms, stolen cache = usable session for its
TTL. *Mitigation:* require hardware binding where available; where not, **shorten
session TTL aggressively** and/or refuse high tiers; document the per-OS binding
strength matrix (this is E-05). Never claim "stolen cache is inert" unqualified —
qualify by keystore. *Critical caveat (E-05 confirms):* hardware binding stops key
**exfiltration**, not key **use** — a local root/co-user attacker cannot export a
TPM/Secure-Enclave-bound key but can drive it as a **signing oracle** through the
agent socket (the ssh-agent-hijack pattern, MITRE **T1563.001**; `ssh-tpm-agent`
has the same shape). The real control is the socket's access control + per-use
user presence, not non-exportability. Secure Enclave keys created *without* a
user-presence ACL are silently usable by any local process; create keys with
mandatory per-use biometric/PIN for privileged operations.

#### AG-2 — IPC on multi-user machines: another user requests credentials [E, S] — **HIGH**
*A second local user, or a malicious local process, on a shared host.* The agent
serves credentials over a Unix socket / named pipe (08). Without peer-cred
authorization, any local process connecting to the socket can request the human's
role credentials or drive the ssh-agent / localhost-OIDC helper. *Impact:* local
privilege escalation to the agent's principal. *Mitigation:* **peer-cred checks**
(`SO_PEERCRED`/`getpeereid` on Unix, named-pipe ACLs + client PID/SID checks on
Windows) binding the socket to the owning UID; socket perms `0600` in the user's
runtime dir; per-request authorization; for host mode, restrict which local
UIDs/services may request which certs. 08 flags this as open — make it a hard
requirement. Root/administrator can always impersonate — **accepted** (root owns
the machine).

#### AG-3 — Agent renews against a rogue Signet (MITM) [S, T] — **MED**
*Network attacker between agent and server.* If the renewal loop trusts DNS/TLS
without pinning, an attacker redirects renewals to a rogue server that mints
attacker-chosen creds or harvests the session. *Mitigation:* agent pins Signet's
trust bundle / server cert; sender-bound session proves possession to the real
server; fail closed on pin mismatch. Additionally, if the sender-binding proof is
DPoP-style, the renewal endpoint must keep a **server-side `jti` replay cache**
with a tight window and, where renewals hit multiple stateless nodes, issue
**server nonces** — RFC 9449 §11 concedes `jti`+`iat` alone leaves a replay
window across stateless servers.

#### AG-4 — Host-mode credential delivery via files on disk [I] — **MED**
*Local users on a host receiving certs written to disk for non-Signet-aware
daemons (08 open q).* Cert/key files world-readable, or lingering after rotation,
leak service identity. *Mitigation:* strict file perms + ownership, tmpfs where
possible, atomic rotate + SIGHUP, prefer systemd credentials / socket handoff
over files. (Feeds E-05.)

### 5. Federation (bundle exchange, bootstrap/TOFU, revocation transport)

#### FED-1 — Bundle rollback suppresses revocation [T, D] — **HIGH**
*Network attacker or compromised bundle endpoint.* If revocations piggyback on
bundle refresh (02 open q) and an attacker serves a **stale** bundle (or blocks
refresh), revocations never propagate and a revoked peer/anchor stays trusted.
Offline verification means no independent check. *Impact:* revocation defeated
across a federation boundary. *Mitigation:* **monotonic bundle epoch/sequence** +
signed `issued-at` + **max-age/fail-closed** on staleness (a bundle older than N
is not trusted for high tiers); never accept an epoch lower than the last seen;
alert on refresh failure. Recommend explicit signed revocation lists with their
own monotonic counter, not merely "absence in the new bundle." *Prior art:* the
**SPIFFE Federation standard**'s own security considerations — clients poll per
`refresh_hint` (5-min default) and merely "SHOULD retry" on failure, so a blocked
poll leaves stale key material trusted; **there is no push revocation** (it is
eventual, poll-based); and deprecated keys linger. Plan key rotation windows
accordingly (publish new keys 3–5× the refresh hint ahead).

#### FED-2 — Bundle-endpoint compromise injects a rogue anchor [T, S] — **HIGH**
*Attacker who controls a peer's refresh endpoint or its signing key.* A refreshed
bundle is trusted if it validates against the previously-pinned anchor; but if the
*peer's own root* is compromised, or the refresh is signed by a key the victim
now trusts, a rogue anchor enters the trust set. *Impact:* attacker-chosen root
accepted → mint anything in the peer's namespace and have the victim trust it.
*Mitigation:* pin the peer **root SPKI** (not just an endpoint URL); bundle
updates must be signed by the pinned root (or a clearly-scoped rotation key
counter-signed by it); require out-of-band confirmation for root-key rotation of a
peer; bound what a peer's anchor may assert (a peer bundle authorizes that peer's
namespace only — enforce on receipt). *Prior art (SPIFFE Federation std):*
"the trustworthiness and integrity of a bundle endpoint server is essential";
**permanent HTTP redirects** can silently rewrite a client's endpoint config
in-band ("can easily go unnoticed" — clients MUST treat all redirects as
temporary); the **`https_spiffe`→`https_web` profile downgrade** has "no secure
method to distinguish" from the URL alone (pin the profile explicitly);
**bundle contents from different trust domains MUST NOT be merged** (merging lets
one domain forge another's identities); and a **federation chain** cascades — a
compromise of any hop compromises the "next," so keep chains short / prefer direct
peering.

#### FED-3 — Bootstrap TOFU/MITM at first contact [S, T] — **HIGH**
*Man-in-the-middle at the very first bundle exchange / join.* TOFU pins whatever
fingerprint arrives first; a MITM at bootstrap pins the attacker. 02 already says
"out-of-band fingerprint or one-time join token; TOFU only where explicitly
enabled" — good. *Impact:* attacker becomes the trusted peer/parent from the
start. *Mitigation:* keep out-of-band fingerprint the default for federation and
child-join; TOFU is opt-in and clearly labeled lower-assurance; join tokens
single-use + scoped (see AT-6); log and surface first-pin events for human
confirmation.

#### FED-4 — Cross-domain namespace confusion [S] — **MED**
*A federated peer asserting identities outside its namespace.* Without on-receipt
scoping, a peer bundle could be leveraged to accept `spiffe://victim/…` from the
peer's chain. *Mitigation:* on receipt, constrain each trusted anchor to *its own*
trust-domain namespace; reject cross-namespace assertions regardless of chain
validity (the SPIFFE trust-domain model — enforce it, don't assume it).

### 6. Enrollment ceremonies, backups, seal, audit, time

#### EN-1 — First-seen enrollment races & approver confusion [S] — **MED**
Covered by AT-4/AT-6/FED-3; consolidate: every first-seen ceremony (TPM, cloud
instance, join token, peer bundle) is TOFU-shaped and needs anti-replay nonce +
scoped commitment + human approval + audit. Make "first-seen" a single reviewed
code path, not per-verifier ad hoc.

#### BK-1 — Backup exfiltration & DR misuse [I, T] — **MED/HIGH**
*Attacker reading backup targets (S3/GCS/NFS).* Covered by ST-2 (whole-store
envelope) and ST-1 (rollback). Additional: backups leave the process encrypted
(11) — verify the envelope key is **not** stored alongside the backup and that
seal is required to restore; test restore as an adversarial path (10).

#### SEAL-1 — Auto-unseal releases keys to a stolen machine [E, I] — **HIGH**
*Physical thief of a bare-metal node, or an attacker who can boot it.* TPM
auto-unseal without a PCR/measured-boot policy releases the data key to anyone who
powers the box on; cloud-KMS auto-unseal turns **KMS/IAM misconfig or key access**
into unseal (a single IAM policy = your seal). *Impact:* at-rest protection void;
attacker gets an unsealed store (→ DB-3 keys). *Mitigation:* **PCR-bound / measured-
boot TPM sealing** (unseal only in the expected boot state), optionally + an
operator secret for high-value nodes; least-privilege KMS grants with tight
conditions and CloudTrail/audit on Decrypt; Shamir for the universal fallback;
design the **migrate-seal** ceremony carefully (E-09) — seal migration is a
key-exposure moment. State the threat model of each seal backend explicitly.
*Prior art:* Vault's docs note recovery keys **cannot** decrypt the root key under
auto-unseal (trust fully shifts to the KMS key's IAM policy), and that **deleting
the seal/KMS key makes Vault unrecoverable "even from backups"** — a built-in
destructive/ransomware vector (protect the key with deletion protection +
immutable backups). For TPM physical seal, the **bus-sniffing / TPM-reset**
attacks (see AT-4) mean sealing solely to PCRs on a discrete-TPM box is defeatable
by a physical attacker — pair with parameter-encrypted sessions and an operator
secret on high-value nodes.

#### SEAL-2 — Break-glass abuse [E] — **MED**
*Insider misusing the offline-root emergency-admin path (11).* Break-glass must
exist (sealed-server recovery) but is a standing backdoor. *Mitigation:* the
offline-root emergency credential is a scoped, short-TTL, loudly-audited, ideally
multi-person ceremony; every use alarms; document and drill it.

#### AL-1 — Audit-log tampering by the compromised process [R, T] — **HIGH**
*An attacker with RCE in Signet (DB-3) — the same process that writes the audit
log.* An in-process append-only log is rewritable by whoever owns the process
before anyone reads it, so it cannot prove what a *compromised Signet* did.
*Impact:* repudiation; the security asset (01) is untrustworthy exactly when it
matters. *Mitigation:* **hash-chain** the log (each entry commits to the prior)
**and anchor externally** — periodic signed checkpoints shipped off-box
(append-only object store with object-lock, or a transparency-log style external
witness), so tampering is at least *detectable*. 11 flags "hash-chaining — worth
it in v1?" — E-01 answer: **yes**, because DB-3 makes the log's own host
untrusted; without external anchoring the log defends only against outsiders, not
against the very compromise you most need it for. *Prior art:* Vault
**CVE-2025-6000** delivered "audit-free persistence" via a malicious plugin — the
attacker who owns the process owns its log. And the Kerberos **Diamond/Sapphire**
lesson (K-6) demands the log record enough **issuance provenance** to distinguish a
legitimately-issued credential from a tampered-but-real one, not merely
forged-from-scratch ones.

#### TIME-1 — Clock rollback extends stolen credentials [T, E] — **HIGH**
*An attacker who controls a relying party's clock (NTP spoof, VM clock, an
RP the attacker roots).* TTL-based revocation is only as good as the verifier's
clock: hold an RP's clock **back** and an expired (revoked-by-expiry) credential
stays "valid" indefinitely — defeating the primary revocation lever (stop
renewing). *Impact:* revocation window becomes unbounded on clock-controlled RPs.
*Mitigation:* rely on authenticated time where it matters; bound tolerated skew
(03 already says "document tolerated skew" — quantify it, e.g. ±N min, reject
outside); for crown jewels use **tier-3 online** introspection, which doesn't
depend on the RP clock; monitor RP clock drift; sign issuance timestamps and have
agents refuse to present creds their own (trusted) clock says are expired. Also
address issuance-side skew: TTLs are leader-clock-relative (03) — document the
issuance↔verification skew budget.

#### TIME-2 — Session/role TTL is the real revocation window — state it per class [D] — **MED**
Not an attack per se but the honest accounting the docs owe: after detection, an
already-issued **role credential** remains valid up to role-TTL (default 15m); a
**session** is killable server-side but only bites at the agent's next renewal, so
already-minted role creds from it live their role-TTL; a **compromised workload**
holding role creds has role-TTL of access regardless of session kill; **X.509/SSH
certs** live their cert-TTL with CRL as backstop. *Mitigation/requirement:* 01
must publish the **accepted revocation window per credential class** (tension #2),
and 06 tiers 2–4 are the levers to shrink it for sensitive roles.

---

## Top-10 ranked residual risks

Ranked by (impact × likelihood × how much the *architecture* — not just an
implementation bug — carries the risk).

| # | Risk | ID(s) | Sev | Why it ranks here |
|---|---|---|---|---|
| 1 | **Single-process key concentration; RCE = domain-total + offline-forgeable session key (golden-ticket).** | DB-3 | CRIT | Inherent to the value prop; one memory bug spends everything; offline verification means forgeries can't be recalled. Mitigation (HSM/TPM-resident keys, key separation, fast rotation) is strong but not free. |
| 2 | **Parent can silently impersonate any "sovereign" child** (hierarchy-as-PKI). | DB-1 | CRIT | Falsifies a headline claim; only fix is architectural (federate-as-equals) or detection-only (pinning/transparency). Must be stated honestly *before* users build on the promise. |
| 3 | **Delegation-only-narrows leans on RP-side name-constraint enforcement that is weak/absent** (URI SANs; not applicable to OIDC/KV at all). | DB-2 | CRIT | Reference stack (Go) has shipped URI-constraint bypass CVEs; two of four v1 dialects don't chain-verify. Blast-radius claim overstated. Gates E-02. |
| 4 | **Mapping-rule injection = ESC1 privilege escalation.** | K-1 | HIGH | The most likely *implementation* path to vertical escalation; directly mirrors the most-exploited ADCS class. Fully mitigable by scoping mapping writes — but must be designed in. |
| 5 | **Attestation verifier confusion / audience replay across the six methods.** | AT-0, AT-1, AT-2, AT-3 | HIGH | Many JWT-shaped verifiers in one system; loose `iss`/`aud` = attestation bypass. Standard but must-fix; k8s-SA and cloud-IID replay are concrete and easy to get wrong. |
| 6 | **Audit-log tampering by the compromised process.** | AL-1 | HIGH | The one asset you need after DB-3 is the one DB-3 can rewrite. Needs external anchoring in v1, which 11 currently only asks about. |
| 7 | **Freshness-ladder downgrade (tier-3 role in an offline token).** | K-2 | HIGH | Defeats the entire ladder silently; "structurally impossible" is only true if centrally enforced and property-tested across all + future dialects. |
| 8 | **Bundle rollback / federation revocation suppression + bootstrap MITM.** | FED-1, FED-2, FED-3 | HIGH | The cross-domain revocation lever is fragile; needs monotonic epochs + fail-closed staleness + root-SPKI pinning. |
| 9 | **Clock rollback unbounds the revocation window on controlled RPs.** | TIME-1 | HIGH | Undermines the core "TTL = revocation latency" premise for offline verification; crown jewels must not depend on RP clocks. |
| 10 | **Backup/snapshot rollback resurrects revoked grants; auto-unseal to a stolen machine.** | ST-1, SEAL-1 | HIGH | Operational vectors that quietly undo revocation and at-rest protection; both fixable with monotonic epochs, tombstones, and PCR-bound seal. |

Honorable mentions just outside the 10: cache-theft vs weak binding on TPM-less
Linux (AG-1), multi-user IPC authz (AG-2), whole-store at-rest confidentiality
(ST-2).

---

## Recommendation

**The architecture is fundamentally sound and worth building** — the
partition-tolerant, issuer-enforced, per-domain design is a coherent and
defensible answer to sovereign infra, and most findings are standard controls to
*implement*, not architecture to *change*. But three things must be fixed at the
**doc/design** level before first code, because they are promises the current
architecture cannot keep as written:

1. **Reframe sovereignty (DB-1).** Split the concept in the docs: *availability
   sovereignty* (partition tolerance — true, keep the claim) vs *authority
   sovereignty against a superior* (only via federate-as-equals — a PKI child is
   never sovereign against its parent). Offer optional intermediate-pinning /
   transparency for detection and co-signing for prevention, each with its stated
   cost. This is the highest-value edit in the whole pass.
2. **Downgrade the name-constraint claim to a per-dialect matrix (DB-2)** and make
   issuer-side path validation + short-lived intermediates the primary control,
   RP-side enforcement a bonus. Feed the specifics to E-02.
3. **Make external key custody (HSM/TPM/KMS-resident signing) a first-class,
   recommended option, and separate keys by function (DB-3).** Quantify the
   in-memory-vs-external residual-risk delta in 01. Pair with fast session-key
   rotation (KRBTGT lesson) and tier-3 for crown-jewel secrets.

Then adopt, as v1 requirements (not open questions), the controls that current
docs still list as "open": **scoped mapping-rule writes (K-1), central tier-gate
enforcement (K-2), strict per-verifier iss/aud pinning + Signet-specific audience
(AT-0), peer-cred IPC authz (AG-2), monotonic epochs + fail-closed staleness for
bundles and restores (FED-1/ST-1), hash-chained + externally-anchored audit
(AL-1), PCR-bound seal (SEAL-1), and a published per-class revocation window
(TIME-2).**

Nothing found justifies stopping. The concentration risk (DB-3) is real and
permanent, but it is the *point* of the system; the honest move is to quantify it
and offer the HSM/TPM boundary that turns "catastrophic exfiltration" into
"bounded uptime-only use." Ship single-node homelab first (its threat model is
the mildest), earn the hardening on the way to multi-tenant/multi-org.

---

## Impact on design docs (explicit change list)

**`00-charter.md`**
- "What Signet is": qualify "sovereign-friendly: every trust domain remains fully
  operational while partitioned" as an **availability** property; add a sentence
  that authority-sovereignty against a *superior* domain is achieved by being
  one's own root and federating, not by being a PKI child (DB-1).

**`01-threat-model.md`** (rewrite — full proposed draft below)
- Promote Status Open→Draft; fold the entire threat catalog; add the DESIGN-BREAKING
  section (DB-1/2/3); resolve the three tensions with concrete positions;
  publish the **per-class accepted revocation window** table (TIME-2); add
  clock-attack (TIME-1) and verifier-confusion (AT-0) as first-class attacker
  capabilities.

**`02-trust-topology.md`**
- "Hierarchy = the PKI chain": add an explicit **parent-power** subsection — a
  parent can re-issue a child's intermediate and impersonate the subtree; name
  the three mitigations (federate-as-equals for real sovereignty;
  intermediate-pinning/transparency for detection; co-signing for prevention) and
  their costs (DB-1).
- Replace the blanket "every independent verifier enforces this, offline" with a
  **per-dialect enforcement matrix** and the fallback (issuer-side validation +
  short intermediates); cross-reference CVE-2024-45341 and E-02 (DB-2).
- "Federation": specify **monotonic bundle epochs, fail-closed staleness
  (max-age), root-SPKI pinning, and on-receipt namespace scoping** as
  requirements, not open questions (FED-1/2/4). Keep out-of-band-fingerprint
  default (FED-3).
- Move "Parent-compromise resistance" from Open to a stated Decided position.

**`03-consistency-storage.md`**
- Encryption-at-rest open question: recommend **whole-store envelope** as the
  floor (ST-2), KV double-enveloped.
- Add **monotonic epoch + revocation tombstones surviving restore** to the backup
  design (ST-1). Quantify tolerated clock skew (TIME-1).

**`04-identity-attestation.md`**
- Add a **per-verifier hardening list**: Signet-specific audience + pinned
  iss/JWKS for every JWT verifier (AT-0/1/2); IMDSv2 + first-seen binding for
  cloud-IID (AT-3); nonce + EK-chain + human approval for TPM (AT-4); attestation/
  AAGUID for hardware-factor `amr` claims (AT-5); scoped single-use join tokens
  (AT-6). Resolve "evidence strength taxonomy" toward a small ordered tier set so
  synced-passkey vs hardware is expressible (AT-5).
- Mapping rules: state that they are authorization-bearing and **scope-constrained
  to the author's subtree** (K-1) — this belongs here and in 05.

**`05-authorization.md`**
- Add **mapping-rule / binding writes obey delegation-only-narrows**, enforced at
  write and re-checked at issuance (K-1). Keep additive-only (K-4).
- Note the per-audience filter (future) must preserve the central tier-gate (K-2).

**`06-credential-lifecycle.md`**
- Make the **tier gate a single central mint-path enforcement**, not per-dialect;
  add the named "no tier-3 role in an offline token" property test hook (K-2).
- Add **per-OS sender-binding strength** caveat and the "stolen cache is inert
  *iff* hardware-bound" qualification (AG-1); cross-ref E-05.
- Publish the **per-class revocation window** and tie tiers 2–4 to shrinking it
  (TIME-2). KRBTGT-style **session-key fast rotation** requirement (DB-3).

**`08-agents-platforms.md`**
- Promote IPC authz from open question to **requirement**: peer-cred checks +
  socket perms + per-request authorization; Windows named-pipe ACLs (AG-2).
- Agent **pins Signet's bundle/cert** for renewal (AG-3); host-mode file delivery
  perms/tmpfs/systemd-creds (AG-4).

**`09-module-layout.md`**
- Add a **`keys/` seal interface requirement**: PKCS#11 / TPM / KMS-resident
  signing as a supported backend, keys separated by function (DB-3).

**`10-testing-strategy.md`**
- Add named property/security tests: mapping-rule scope containment (K-1),
  central tier-gate across all + future dialects (K-2), verifier audience/iss
  isolation (AT-0), bundle-epoch monotonicity & fail-closed staleness (FED-1),
  restore-rollback epoch regression (ST-1), clock-skew bounds (TIME-1).

**`11-operations.md`**
- Audit log: **decide "yes" on hash-chaining + external anchoring for v1** (AL-1).
- Seal: require **PCR-bound/measured-boot** for TPM auto-unseal; least-priv KMS +
  Decrypt auditing; document each backend's threat model; treat **migrate-seal**
  and **restore** as key-exposure ceremonies (SEAL-1, ST-1). Break-glass is
  scoped/short/loud/multi-person (SEAL-2).

**`12-governance.md`**
- SECURITY.md should name the concentration model and the HSM/TPM recommendation
  as a documented hardening tier before a 1.0 claim; third-party audit must
  specifically cover the issuance path and the tier gate.

---

## Confidence and what would change the conclusion

**Confidence: high** on the threat *catalog* and on DB-1 and DB-3 (these follow
directly from well-established properties of subordinate-CA delegation and of
in-memory keys, corroborated by AD/ADCS, Kerberos, and Vault prior art).
**Medium-high** on DB-2's severity: it hinges on *empirical* RP enforcement
behavior, which is exactly what **E-02** will measure — if E-02 finds URI-SAN
constraint enforcement is broadly correct in the specific stacks Signet's RPs use,
DB-2 downgrades from CRIT to HIGH (still real for OIDC/KV, which never chain-
verify). **Medium** on relative ranking of items 4–10 — reasonable people could
reorder within the HIGH band.

What would change the conclusion:
- **E-02** showing name-constraint enforcement is either far better or far worse
  than assumed moves DB-2 and the whole "verified offline by everyone" premise.
- **E-05** showing hardware sender-binding is unavailable/weak on a target OS
  raises AG-1 and forces shorter session TTLs (or refusing that platform for high
  tiers).
- A decision to support **HSM/TPM-resident signing** as default materially lowers
  risk #1 (DB-3) — the single biggest lever available.
- Introducing **RFC 8693 token exchange** or **first-class deny bindings** or
  **role nesting** later would each open new escalation surface (K-3/K-4) and
  should get their own mini threat pass.
- If Signet ever moves to a **shared multi-domain process** to save resources,
  the per-domain blast-radius bound (a load-bearing mitigation) collapses —
  that would be a new, worse threat model.

---
---

# PROPOSED REPLACEMENT for `docs/01-threat-model.md`

> Draft for human review; do not overwrite `01-threat-model.md` until folded in.

```markdown
# 01 — Threat model

**Status: Draft** (was Open; completed by exploration E-01, pending review).

## Purpose

Drives every other decision: which attacker, what blast radius, what must survive
partition, and what we explicitly do not defend against. Security properties are
enforced **at the issuer** (what Signet is willing to mint), per charter
principle #3 — never dependent on relying-party goodwill.

## Assets

- Domain **root CA keys** (offline) and **online intermediate** signing keys.
- **Session-signing** and **role-signing** keys (the golden-ticket-equivalent
  keys: theft = forge any session/role credential).
- **Session credentials** (agent-held, sender-bound) and **role credentials**.
- The **identity graph, role bindings, and mapping rules** (integrity first;
  confidentiality also matters — the graph is a target map).
- The **KV secret store** contents (confidentiality + integrity).
- The **audit log** (integrity, completeness — a security asset).
- **Attestation trust anchors** (k8s issuer JWKS, TPM/vendor CAs, upstream IdP
  keys, cloud IID signers) and **federation bundles / pins**.
- The **seal / at-rest data key** and backups.

## Trust boundaries

Per-domain Raft group (linearizable within a domain); between domains only signed
artifacts flow (eventually consistent). The running server process is a single
trust boundary holding live signing keys + KV plaintext (see Concentration). Each
agent↔daemon IPC socket is a local trust boundary. Each relying party verifies
offline by default and is trusted only to enforce what its own verifier enforces.

## Attacker classes

- **Stolen workstation / agent cache** — mitigated by sender-binding, *as strong
  as the platform keystore* (TPM/Secure Enclave strong; software-key fallback
  weak — then TTL is the bound).
- **Compromised workload** holding a valid short-lived credential — bounded by
  role-TTL; tier-2/3/4 shrink it for sensitive roles.
- **Compromised relying party** (Grafana, a fleet host) — including one whose
  **clock** the attacker controls (extends stolen-credential life; use online
  tiers for crown jewels).
- **Compromised child domain / malicious delegated admin** — bounded by name
  constraints *where the RP enforces them* + issuer-side path validation + short
  intermediates + scoped mapping-rule writes. (See per-dialect matrix in 02.)
- **Compromised parent domain** — can silently re-issue a child's intermediate
  and impersonate the subtree (see Sovereignty).
- **Network attacker** at enrollment/bootstrap/renewal/bundle-refresh — MITM,
  bundle rollback, rogue-server renewal — mitigated by out-of-band fingerprints,
  monotonic bundle epochs with fail-closed staleness, and agent pinning.
- **Malicious insider** with delegated admin at a subtree — bounded to that
  subtree by delegation-only-narrows in *both* bindings and mapping rules.
- **Signet server compromise (RCE)** — the concentration case: one process holds
  intermediates + signing keys + KV plaintext.
- **Attestation-confusion attacker** — replays evidence valid for one verifier
  into another; mitigated by per-verifier iss/aud/JWKS pinning + Signet-specific
  audience.

## DESIGN-BREAKING findings (resolved positions)

1. **"Sovereign child" under hierarchy-as-PKI.** A parent CA can, offline, mint a
   second name-constrained intermediate for a child and impersonate its whole
   subtree; RPs pin the root, so the child cannot prevent it. Position:
   *availability sovereignty* (partition tolerance) is real and retained;
   *authority sovereignty against a superior* is achieved **only by being one's
   own root and federating as equals**, not by being a PKI child. Optional
   intermediate-pinning / a transparency-epoch log give **detection**; **co-
   signing** gives **prevention** at the cost of offline parent re-issue. Docs
   00/02 corrected to say this plainly.

2. **Delegation-only-narrows depends on RP name-constraint enforcement, which is
   weak on URI SANs and absent for OIDC/KV.** Go `crypto/x509` has shipped URI-
   constraint bypasses (CVE-2024-45341); OIDC/KV dialects don't chain-verify at
   all. Position: issuer-side path validation + short-lived intermediates are the
   **primary** control; RP-side enforcement is a bonus quantified by E-02; the
   per-dialect boundary is documented in 02 (X.509/SSH: chain constraints iff RP
   enforces; OIDC/KV: issuer-federation configuration).

3. **Concentration: one RCE = domain-total, and the session key is a golden-
   ticket key.** Position (accepted, hard-mitigated): support **HSM/TPM/KMS-
   resident signing** so RCE = key *use during uptime*, not key *exfiltration*;
   **separate keys by function** with independent, fast rotation (KRBTGT lesson);
   **crown-jewel secrets on tier-3**; **whole-store + KV envelope** so backups are
   inert; per-domain process isolation caps blast radius to one domain. Residual
   risk stated: with in-memory keys, RCE is domain-total and offline-forgeable;
   with external key custody, forgeries stop at key-use revocation / process kill.

## Known tensions — resolved

1. **Concentration** → see DESIGN-BREAKING #3. Residual risk quantified;
   HSM/TPM-resident signing is the recommended hardening on capable hardware.
2. **Revocation window with offline verification.** TTL = revocation latency.
   Accepted windows per class:

   | Credential class | Default TTL / window | Shrink lever |
   |---|---|---|
   | Role credential (OIDC/KV/SSH/X.509 leaf) | ≤ 15 min | tier-2 short-leash; tier-3 online = ~0 |
   | Session credential | hours (12h homelab); killable server-side, bites at next renewal | shorter TTL on weak-binding OS; tier-4 step-up |
   | X.509/SSH cert | cert TTL (minutes–hours) | CRL per intermediate as backstop |
   | Intermediate CA | short-lived, re-issued from offline root | revoke intermediate = subtree kill |

   Clock caveat: TTL bounds hold only within tolerated skew; a clock-controlled RP
   can extend a credential — crown jewels use tier-3 online, which is clock-
   independent.
3. **Parent power over children** → see DESIGN-BREAKING #1.

## Threat catalog

See exploration `explorations/E-01-threat-model.md` for the full STRIDE catalog
(kernel K-1..K-6, store ST-1..ST-3, attestation AT-0..AT-6, agent AG-1..AG-4,
federation FED-1..FED-4, enrollment/backup/seal/audit/time EN/BK/SEAL/AL/TIME).
The v1 must-fix controls promoted out of "open questions" by E-01:

- **Scoped mapping-rule writes** (delegation-only-narrows applies to mapping rules
  too — the ESC1 analogue). [K-1]
- **Central tier-gate enforcement** in the mint path; no dialect can expand a
  tier-3 role. [K-2]
- **Per-verifier iss/aud/JWKS pinning + a Signet-specific audience** on every
  JWT-shaped verifier; verifier chosen by config, never inferred. [AT-0/1/2/3]
- **Peer-cred IPC authorization** on agent sockets/pipes. [AG-2]
- **Monotonic bundle epochs + fail-closed staleness + root-SPKI pinning**;
  **restore** guarded by monotonic epoch with revocation tombstones. [FED-1, ST-1]
- **Hash-chained + externally-anchored audit log** (the compromised process must
  not be able to erase its tracks). [AL-1]
- **PCR-bound / measured-boot seal** for TPM auto-unseal; least-priv audited KMS.
  [SEAL-1]
- **Whole-store at-rest envelope** so backups are uniformly inert. [ST-2]

## Explicitly out of scope (accepted risk)

- **Root/administrator on a machine** can impersonate any local agent principal —
  the OS owner owns the agent. Multi-user protection is against *peer* users, not
  root.
- **Root-domain key compromise** is domain-existential and recoverable only by
  re-bootstrapping trust; we minimize exposure (offline, air-gapped ceremonies),
  we do not "defend" it.
- **Upstream IdP account takeover** transitively yields a Signet session; mitigated
  by requiring phishing-resistant WebAuthn for high-tier roles regardless of how
  the session was born — not by defending the upstream.

## Exploration

Completed by E-01. Feeds forward: E-02 (name-constraint enforcement reality —
gates DB-2 severity), E-04 (attestation ceremony hardening), E-05 (sender-binding
strength per OS — gates AG-1), E-09 (seal ceremonies — SEAL-1), E-12 (federation
artifact format — FED-1/2).
```

## Sources

**PKI-as-authorization / ADCS ESC corpus (K-1, DB-1/2)**
- SpecterOps, *Certified Pre-Owned* (ESC1–ESC8): https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf ; maintained ESC1–ESC16 wiki: https://docs.specterops.io/ghostpack-docs/certify/
- ESC13 (policy-OID→group link): https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53
- ESC15 / EKUwu — **CVE-2024-49019** (application-policy injection): https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc
- Certifried — **CVE-2022-26923** (requester-controlled name = auth identity): https://www.thehacker.recipes/ad/movement/adcs/certifried
- CA-failure timeline (TÜRKTRUST, NIC India, DigiNotar, Symantec): https://sslmate.com/resources/certificate_authority_failures
- Path-length / self-issued re-issuance: https://blaufish.github.io/security/research/2025/02/15/path-length-constraint.html
- Certificate Transparency (RFC 6962) overview: https://cacm.acm.org/practice/certificate-transparency/

**Name-constraint enforcement reality (DB-2, feeds E-02)**
- Go **CVE-2024-45341** (URI SAN IPv6-zone-ID bypass): https://github.com/golang/go/issues/71156 ; under-enforcement report #59171: https://github.com/golang/go/issues/59171 ; **CVE-2025-61727** (wildcard vs excluded DNS): https://github.com/golang/go/issues/76935 ; **CVE-2026-33810** (excludedSubtrees case-sensitivity); **CVE-2026-27137/27138**, **CVE-2025-58187** *(2026 entries: confirm fixed versions at https://pkg.go.dev/vuln/ before publishing)*
- OpenSSL **CVE-2021-3450** (CA-check bypass): https://www.openssl.org/news/secadv/20210325.txt ; **CVE-2022-3602/3786** (overflow in name-constraint check): https://www.openssl.org/news/secadv/20221101.txt
- SPIFFE X509-SVID std (URI name constraints OPTIONAL / unsupported in the wild): https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md

**Concentration / secrets store (DB-3, ST, SEAL, AL)**
- Cyata "Cracking the Vault" (**CVE-2025-6000** first Vault RCE, **-5999** root escalation, **-6037** cert-auth CN impersonation, MFA/lockout cluster): https://cyata.ai/blog/cracking-the-vault-how-we-found-zero-day-flaws-in-authentication-identity-and-authorization-in-hashicorp-vault/
- Aembit "Vault Fault" (concentration / blast-radius argument): https://aembit.io/blog/vault-fault-secrets-managers-and-the-limits-of-centralized-trust/
- Vault security model (unsealed = keys in RAM; not an EDR): https://developer.hashicorp.com/vault/docs/internals/security ; seal best practices / KMS-key-deletion: https://developer.hashicorp.com/vault/docs/configuration/seal/seal-best-practices
- GitGuardian blast-radius of a leaked secret: https://blog.gitguardian.com/blog-blast-radius-leaked-secrets/

**Cloud/k8s auth confusion (AT-1, AT-3)**
- Vault AWS/GCP auth bypass **CVE-2020-16250/16251** (Project Zero "Enter the Vault"): https://projectzero.google/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html ; AWS-auth cache confusion **CVE-2025-11621**: https://zeropath.com/blog/cve-2025-11621-vault-aws-auth-bypass
- Vault k8s-auth audience-not-checked (#175): https://github.com/hashicorp/vault-plugin-auth-kubernetes/issues/175 ; `token_reviewer_jwt` anti-pattern (#12951)
- IMDSv1 SSRF / IID static-and-readable: https://hackingthe.cloud/aws/exploitation/ec2-metadata-ssrf/ ; Vault AWS auth (nonce/TOFU): https://developer.hashicorp.com/vault/docs/auth/aws

**SPIFFE/SPIRE (AT-0, FED-1/2/3/4, DB-1)**
- SPIRE **CVE-2021-27099** (aws_iid path-normalization = attestation confusion): https://github.com/spiffe/spire/security/advisories/GHSA-q7gm-mjrg-44h9 ; **CVE-2021-27098** (agent impersonation via legacy Node API): https://github.com/spiffe/spire/security/advisories/GHSA-h746-rm5q-8mgq ; **AIKIDO-2025-10384** (JWT-SVID `exp` not validated): https://intel.aikido.dev/cve/AIKIDO-2025-10384
- SPIFFE Federation std (bundle-endpoint trust, redirects, profile downgrade, no push revocation, no bundle-merge, chain cascade, TOFU bootstrap): https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Federation.md ; Nested SPIRE (upstream compromise = whole domain): https://spiffe.io/docs/latest/architecture/nested/readme/

**Kerberos / OIDC / JOSE / step-up (K-6, K-2, AT-2)**
- Golden/Silver/Diamond/Sapphire tickets: https://www.picussecurity.com/resource/blog/golden-ticket-attack-mitre-t1558.001 ; https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/ ; KRBTGT-twice remediation: https://www.semperis.com/blog/how-to-defend-against-golden-ticket-attacks/
- Keycloak **CVE-2026-11800** (alg confusion): https://github.com/keycloak/keycloak/issues/50357 ; **CVE-2026-1486** (disabled-IdP): https://www.sentinelone.com/vulnerability-database/cve-2026-1486/ ; **CVE-2026-37979** (audience-agnostic introspection): https://dailycve.com/keycloak-authorization-bypass-in-oidc-token-introspection-cve-2026-37979-medium-dc-jun2026-174/ ; **CVE-2026-1180** (`jwks_uri` SSRF): https://advisories.gitlab.com/maven/org.keycloak/keycloak-adapter-core/CVE-2026-1180/
- JWT alg-confusion / `none` / `kid` / `jku`: https://portswigger.net/web-security/jwt ; https://workos.com/blog/jwt-algorithm-confusion-attacks ; audience confusion: https://blog.baited.io/2026/jwt-audience-confusion-identity-microservices/
- `amr`/`acr` downgrade (absent-signal fail-open): https://learn.microsoft.com/en-us/answers/questions/5874604/ ; RFC 9470: https://www.rfc-editor.org/rfc/rfc9470.html

**Attestation / sender-binding / WebAuthn (AT-4/5/6, AG-1)**
- TPM-FAIL **CVE-2019-16863**: https://tpm.fail/ ; TPM bus sniffing: https://trmm.net/tpm-sniffing/ ; TPM Genie interposer: https://github.com/nccgroup/TPMGenie ; RATS TPM attest (nonce/relay/AK↔DevID): https://www.ietf.org/archive/id/draft-ietf-rats-tpm-based-network-device-attest-11.html
- WebAuthn **CVE-2026-30964** (origin bypass): https://advisories.gitlab.com/composer/web-auth/webauthn-lib/CVE-2026-30964/ ; **CVE-2025-26788** (StrongKey passkey ATO): https://www.securing.pl/en/cve-2025-26788-passkey-authentication-bypass-in-strongkey-fido-server/ ; synced passkeys weak: https://yourpasskeyisweak.com/
- ssh-agent hijack signing-oracle (MITRE **T1563.001**): https://attack.mitre.org/techniques/T1563/001/ ; DPoP replay (RFC 9449 §11): https://www.rfc-editor.org/rfc/rfc9449.html
- Join-token node impersonation (Synacktiv, AKS bootstrap tokens): https://www.synacktiv.com/en/publications/so-i-became-a-node-exploiting-bootstrap-tokens-in-azure-kubernetes-service

**RFCs**
- RFC 5280 (name constraints), 6962 (CT), 7662 (introspection), 8555 (ACME),
  8628 (device flow), 8693 (token exchange), 8705 (mTLS-bound tokens),
  9449 (DPoP), 9470 (OAuth step-up).

*Caveat: several 2026-dated CVEs (Go constraint bugs; some Keycloak entries) were
sourced via secondary trackers; verify exact IDs and fixed versions against the
primary advisory / pkg.go.dev/vuln during fold-in.*
