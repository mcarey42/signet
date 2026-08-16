# 11 — Operations

**Status: Open**

## Key custody & seal (Open — highest-stakes operational design)

- **Domain root keys live offline** (or in TPM/KMS custody); the running
  server holds only short-lived intermediates. Root ceremonies (create,
  re-issue intermediate, subtree revocation) are explicit CLI ceremonies,
  not API calls.
- **Seal interface** (unseal-at-boot for the at-rest data key): pluggable —
  TPM 2.0 (homelab/bare metal), cloud KMS (AWS/GCP nodes), Shamir shares
  (universal fallback). Vault's operational pain lives here; Mission E-09
  designs the ceremony set (init, unseal, rekey, rotate, migrate-seal).
  **E-01 SEAL-1 requirements**: TPM auto-unseal must be **PCR-bound /
  measured-boot** (unseal only in the expected boot state — a bare
  PCR-less seal releases the key to whoever powers the box on), optionally +
  an operator secret on high-value nodes; KMS auto-unseal uses least-priv
  grants with tight conditions and Decrypt auditing (a single IAM policy
  becomes your seal; KMS-key deletion makes the store unrecoverable even from
  backups — deletion-protect it + immutable backups). Each backend's threat
  model is stated explicitly; migrate-seal and restore are key-exposure
  ceremonies.
- **HSM/TPM/KMS-resident signing** (E-01 DB-3): a first-class recommended
  option so an RCE yields key *use during uptime*, not key *exfiltration*.
  Keys separated by function, rotated independently; session-signing key
  fast-rotatable (double-rotation to invalidate forged sessions).
- KV secrets additionally enveloped under a data key so leaked backups are
  inert without the seal (03).

## Backups (Decided via E-03 — format details in doc 03)

- Generations (FSM snapshot + contiguity-verified Raft-entry segments) to
  dumb blob targets: S3, GCS, NFS/local. ~10 s loss window at our volume.
- **Encrypted before egress**: chunked AEAD under a **backup key** that is
  seal-wrapped but *distinct* from the barrier key — a backup credential
  never equals a live-store credential. Leaked backups are doubly inert
  (outer AEAD + inner barrier ciphertext).
- Restore is a first-class tested path (10): single-node DR from object
  storage (`signet restore --from …` onto an empty data dir), multi-node =
  restore one + wipe/rejoin.
- **Re-parenting × restore**: snapshot meta carries the domain's trust-chain
  fingerprint. On mismatch with the configured parent, restore refuses unless
  `--re-parent`, which restores local state but quarantines parent-derived
  trust material (domain intermediate, cached bundles) as
  stale-pending-ceremony; local-only issuance may continue (sovereignty).
  Never silently resurrect a dead trust lineage.
- Data dir on local disk always; NFS is a backup target, never a data dir.

## Encryption at rest (Decided via E-03)

Two layers, both: a Vault-style **barrier keyring** (every value AEAD'd
before touching the engine; epoch-based online rekey; sealed by the E-09
seal) **plus per-subtree DEK envelopes** for KV secrets and private key
material (per-subtree rotation; dropping a DEK = cryptographic erase of a
subtree; a scraped barrier key alone doesn't open the KV corpus). Bucket
names/graph structure stay plaintext in-store for range scans; the backup
wrapper hides them off-box.

## Packaging & delivery

- systemd units (fleet), Helm chart / k8s manifests (in-cluster), cloud-init
  snippets (cloud VMs), single tarball + binary otherwise.
- Upgrade story: single binary swap + migration-on-start with version gates;
  Raft-rolling upgrades for multi-node domains.

## Observability

- Structured audit log for every issuance and policy decision — the audit log
  is a security asset (01). **Decided (E-01 AL-1): hash-chained AND externally
  anchored in v1** — periodic signed checkpoints shipped off-box (object-lock
  store or transparency-style witness). An in-process append-only log is
  rewritable by an RCE'd process (the one compromise you most need it for; cf.
  Vault CVE-2025-6000 "audit-free persistence"), so external anchoring is what
  makes tampering detectable. The log records enough issuance **provenance** to
  distinguish a legitimately-issued credential from a tampered-but-real one
  (the diamond-ticket lesson).
- Prometheus metrics; health endpoints that distinguish "sealed" from "down".

## Open questions

- Audit log: hash-chaining / external anchor for tamper evidence — worth it in v1?
- Multi-node homelab topology: 3-node domain across clusters vs single-node +
  aggressive backup. (Homelab can start single-node.)
- Break-glass: sealed-server recovery when WebAuthn/agents are unavailable
  (offline root can always mint an emergency admin credential — document the
  ceremony).
