# Explorations — agent fan-out missions

Deep investigations run as parallel agent missions before implementation.
Each mission produces a report in this directory (`E-NN-<slug>.md`); findings
are then folded back into the numbered design doc that owns the question,
and the mission report remains as the evidence trail.

**Report format**: Question → Method/sources → Findings → Recommendation →
Impact on design docs (explicit list of doc sections to change) → Confidence
and what would change the conclusion.

## Mission register

| ID | Mission | Feeds | Priority |
|---|---|---|---|
| E-01 | ✅ **DONE** — **Threat model pass** — STRIDE sweep; 3 design-critical findings (sovereign-child contradiction, name-constraint dependency, key concentration); folded into 00–11 | 01 | P0 |
| E-02 | ✅ **DONE** — **Name-constraint enforcement reality** — measured 5 verifiers × 15 chains; bet unsound for URI/SPIFFE (webpki-family rejects legit chains); issuer-side primary + constraints as DiD (DNS+IP+email always, URI opt-in) | 02 | P0 |
| E-03 | ✅ **DONE** — **Raft library + storage engine selection** — hashicorp/raft + bbolt (2 files) + Litestream-shaped generations over Raft-entry WAL; no MVCC; two encryption layers | 03 | P0 |
| E-04 | **Attestation evidence deep-dive** — TPM 2.0 enrollment ceremony (EK→AK→DevID), AWS/GCP instance identity verification, k8s OIDC discovery for private clusters, WebAuthn server-side requirements | 04 | P1 |
| E-05 | **Sender-binding per platform** — TPM 2.0 / Secure Enclave / CNG key operations from Go; mTLS-bound tokens vs DPoP; what binding survives which theft scenario on each OS | 06, 08 | P1 |
| E-06 | ✅ **DONE** — **Vault API compatibility surface** — ~15-route Tier A compat line from pinned consumer source; homelab-verified (pki/sign only, sys/health body parsed by inframonitor); ~2–3k LoC | 07 | P0 |
| E-07 | **SAML risk survey** — XML-DSig CVE history (signature wrapping, canonicalization), Go ecosystem options, feasibility/scope of a constrained IdP-only implementation; recommend build/vendor/defer | 07 | P2 |
| E-08 | **OIDC minimal conformance set** — which specs/flows are actually required by kubectl, Grafana, ArgoCD, Harbor, Proxmox, Tailscale; whether to run the official certification suite in CI | 07, 10 | P1 |
| E-09 | **Seal/unseal ceremony design** — TPM, cloud KMS, Shamir; init/rekey/rotate/migrate ceremonies; what Vault got wrong operationally and how to avoid it | 11 | P1 |
| E-10 | **Interop test harness design** — kind + containerized real clients (ESO, cert-manager, Grafana, sshd) as a CI release gate; headless browser SSO flows | 10 | P2 |
| E-11 | **Prior-art mining** — what Zitadel, Kanidm, SPIRE, Teleport, step-ca each got right/wrong at the module level (issuance paths, agent UX, HA story); steal shamelessly, cite | all | P2 |
| E-13 | ✅ **DONE** — **Cold-read of the kernel data model + whole design** — 15 findings, none design-breaking; 9 real spec holes folded into 13/14/05/06/01/03/07: stable principal IDs (F1), group-membership narrows (F2), tier-as-role-attribute (F3), grantor lifecycle (F4), per-domain trees (F5), genesis root-key persistence (F6), reconciler authorship + config-repo tier-0 (F7), KV auth mapping (F8), runtime entities + activation semantics (F9), SPIFFE path grammar (F11). Verdict: right-sized core, hold MVP-first sequencing. | 13/14/all | P1 |
| E-12 | **Federation artifact format & sovereign-child mechanics** — SPIFFE bundle format suitability, revocation transport, bundle refresh/pinning protocol; PLUS the sovereign-child crypto (doc 02 "Child modes"): cross-certificate format parent↔child-root; optional self-certifying namespace (RFC 3972-style, name=H(child key)) + friendly-name discovery layer; optional CONIKS/Key-Transparency log (inclusion proofs, monitoring, split-view/gossip); optional FROST/threshold-Ed25519 child root key; and where per-issuance liveness (nonce+timestamp child sig) belongs in the online tiers (06). Must satisfy FED-1/2/3/4 requirements from E-01. | 02 | P1 |

## MVP reviews (2026-08-16)

| ID | Mission | Feeds | Status |
|---|---|---|---|
| E-14 | ✅ **Reduction review of MVP plan** — ~half the code: 8→6 packages, cut RolePolicy/version-history/internal-CA from MVP (all additive-later); resequence curl→ESO-token-auth→k8s-SA; Raft verdict = keep real single-node, zero membership machinery | 15 | DONE |
| E-15 | ✅ **Elegance review of MVP plan** — one-write-path sound; 4 contracts to state (Apply determinism, tokens hash-in-Op, audit-as-FSM-state, propose/apply validation split); name the Proposer port; Login/Issue API is a clean prefix — offline dialects absorb with no fork | 15 | DONE |

Both folded into doc 15 (2026-08-16). The one conflict — E-14 wanted 4
packages, E-15's dependency DAG forbids merging `op` (durable versioned codec)
and `fsm` (import cycle: FSM→kernel→store) into others — resolved at 6 internal
packages, each surviving seam justified by a hard constraint.

## Sequencing

**All four P0 missions are complete (2026-08-16) and folded into the docs.**
Headline outcomes:

- **E-01** surfaced 3 design-critical findings, all resolved at the doc level:
  (1) a PKI child is never sovereign *against* its parent — split availability
  vs authority sovereignty, real sovereignty = own-root + federate; (2)
  name-constraint enforcement can't be primary (confirmed by E-02); (3) key
  concentration is inherent — mitigate with HSM/TPM-resident signing. Eight
  controls promoted from open-questions to v1 requirements.
- **E-02** empirically killed the "every verifier enforces constraints offline"
  claim for URI/SPIFFE (webpki-family rejects legitimate constrained chains).
  Model survives: issuer-side validation primary, constraints as
  defense-in-depth (DNS+IP+email always, URI opt-in), workload scoping via
  SPIFFE bundle partitioning.
- **E-03** picked hashicorp/raft + bbolt + Litestream-shaped backups.
- **E-06** pinned the ~15-route Vault compat line, homelab-verified.

The delegation model, storage bet, and compat surface are sound (with the
sovereignty claim corrected). Nothing found justifies stopping.

**Next**: P1 missions before the relevant subsystem's implementation —
E-04 (attestation ceremonies, now carrying E-01's AT-* hardening list),
E-05 (sender-binding per OS, gates AG-1), E-09 (seal ceremonies, carries
SEAL-1), E-12 (federation format, carries FED-1/2). E-08 (OIDC conformance)
before the OIDC dialect. P2 anytime. Then the first vertical slice.
