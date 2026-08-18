# 11 — Operations

**Status: Draft** (seal, key custody, rotation, and anchored audit implemented;
backups still design-only)

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

### Built: anchored audit (2026-08-17, milestone 5a)

`internal/store` chains every audit entry to its predecessor; `internal/audit`
adds signed checkpoints and peer witnessing. `signet audit verify | checkpoint |
witness | witnessed`, proven end to end in `test/audit/run.sh`.

**The chain and the anchor catch different things, and the split is the whole
design.** Measured, in that order, against a real rewrite:

| Attack | Hash chain | Witness |
|---|---|---|
| Edit a record in place | **caught** — breaks every link after it | caught |
| Remove an entry from the middle | **caught** — sequence and links both fail | caught |
| Truncate the newest entries | *misses* — what remains is a valid chain | **caught** |
| Roll back and re-run differently | *misses* — internally perfect, same keys | **caught** |
| Wipe the node and start over | *misses* — a fresh valid chain | **caught** (key changes) |

The third and fourth rows are why this milestone is "anchored" rather than
"hash-chained". A chain assumes the attacker cannot recompute it; whoever holds
the node can. `test/audit/run.sh` asserts that the local chain reports the
rewritten log as **intact** — because it is — immediately before the witness
refuses it. Shipping the chain alone would have been a tamper-evidence claim
that does not survive its own threat model.

**Witnesses verify, they do not file.** A witness is handed the entries since
the checkpoint it last saw and replays them onto the head it already holds. A
filing-cabinet witness would catch only rewrites that contradict a checkpoint it
happens to possess and miss everything between them; replay makes it an
append-only enforcer, so whatever a witness has accepted is provably a prefix of
what it accepts later.

**Conflicts are stored, not just returned.** The value of a witness is that it
holds evidence after the fact, so a detection that vanished with the error would
be worth nothing. A witness in conflict refuses further checkpoints from that
domain until the conflict is resolved deliberately — it cannot be reset by
asking again.

**The checkpoint key is pinned on first witness.** A node rebuilt from nothing
loses its audit key, so it can no longer prove it is the same domain; that is
recorded as evidence in its own right rather than treated as a rotation.

Still open: shipping checkpoints to a non-Signet anchor (object-lock bucket,
transparency log) for domains with no peer to witness them; and scheduling, so
witnessing happens on a timer rather than when an operator remembers. A domain
that witnesses nobody and is witnessed by nobody has a hash chain and nothing
anchoring it — `signet audit witnessed` says so out loud.

## Decided: private keys are sealed before they are proposed (2026-08-16)

Implemented. Private key material — the CA intermediate and every signing key —
is enclosed in a **seal envelope** before it is ever proposed, so the plaintext
never enters the Raft log at all, not even in an entry later compacted away.
What the log holds is a data key wrapped by the seal plus material encrypted
under that data key. Recovering it requires the seal, which for a hardware seal
means the device.

The barrier still protects everything on top; the envelope is what makes the
barrier insufficient on its own. `Apply` refuses a key record that arrives with
plaintext material, so the property is enforced at the write path rather than
trusted to callers.

**Seals are pluggable and the interface is the same either way:**

- `file:///path/to/seal.key` — the default. Defends against a stolen backup or
  a leaked store file, not against someone who owns the host.
- `pkcs11:?module=…&token=…&pin=…&label=…` — an HSM. Wrap and unwrap happen
  *inside the device*; the wrapping key is never readable, so a compromise of
  Signet's memory, disk, or backups yields the ability to ask the HSM to work
  while the process runs, not the key itself (E-01 DB-3's "key use during
  uptime, not key exfiltration").

The barrier root key is generated once, wrapped by the seal, and only ever
written in wrapped form (`root.seal`). A data directory therefore cannot be
opened by anything but the seal that created it — verified: substituting a file
seal for the HSM fails with the wrapping key's identity, and removing the token
stops the domain from starting rather than letting it come up degraded.

PKCS#11 requires cgo, so it lives behind a `pkcs11` build tag; the default
binary stays static and pure-Go (docs/09). A build without the tag **refuses** a
configured hardware seal rather than falling back, because a domain that
believes its keys are in an HSM and is wrong is worse off than one that will not
start. `make test-hsm` provisions a SoftHSM token and runs the seal tests
against it — the same code path a real HSM takes.

### Seal rotation (implemented)

`signet seal rotate -to <uri>` moves custody from one seal to another — a file
seal to an HSM, or one HSM key to its successor. `signet seal status` shows
which wrapping key currently holds each item.

It is a **rewrap, not a re-key**. Every signing key keeps its identity and the
CA is untouched, so credentials already issued stay valid: changing who holds
the wrapping key says nothing about the keys being wrapped, and conflating the
two would turn a custody change into an outage. Verified end to end — after
rotating a live domain from a file seal to SoftHSM, the JWKS `kid`, the CA
fingerprint, and previously issued tokens are all unchanged.

Order within the ceremony is deliberate: **material first, root key last**. A
crash between them leaves a domain that still opens with the *old* seal, which
is recoverable by re-running; the reverse order would leave the store unreadable
until someone finished the job by hand. The ceremony is idempotent and resumable
— items already under the destination are skipped — and it **proves the result
by opening every item under the destination seal alone** before reporting
success, because a record that merely claims the new seal proves nothing.

Two operational consequences, both printed by the command:

- Keep the old seal until the ceremony reports success. An interrupted run needs
  both.
- Destroying the old seal also shreds **any backup taken before the rotation**:
  those hold material wrapped by the old seal and nothing else can open them.
  That is the crypto-shredding property working as intended, but it is only
  desirable if you meant it.

Cost is O(number of signing keys), i.e. a handful. That is the deliberate price
of wrapping envelopes with the seal *directly* rather than under an intermediate
key-encryption key: an attacker inside the running process must ask the device
to open each key and loses that ability when the process dies, whereas a KEK
would make rotation a single blob rewrite and hand that same attacker everything
at once.

### Keys held in hardware, not merely wrapped by it (implemented)

There are two different things a device can do for a key, and the difference
matters:

| | Where the private key exists | What an attacker inside the process gets |
|---|---|---|
| **Wrapped** (envelope) | Encrypted at rest; **plaintext in Signet's memory when used** | The key, by reading memory |
| **Held** (reference) | **Only inside the token, ever** | The ability to *ask* for signatures while the process lives |

`signet genesis -ca-in-hardware` takes the second path for the CA. The root and
intermediate keys are generated **inside the token** with `CKA_SENSITIVE` and
`CKA_EXTRACTABLE=false`, and generation reads those attributes back — a token
that quietly ignored them would be lying, so the ceremony refuses the key rather
than trusting it. What Signet stores is a `KeyRef`: a pointer, not a secret.
Every signature is computed in the device.

Verified against SoftHSM: certificates issued this way verify against the chain,
no PEM key material exists in `state.db`, `raft.db`, or on disk anywhere, **no
root key file exists**, and `pkcs11-tool --read-object --type privkey` is
refused by the token.

The operational trade is real and stated at genesis time:

- There is no root key file to protect, lose, or copy. "Offline root" becomes
  a token in a safe rather than a file on a USB stick, and re-issuing an
  intermediate becomes a ceremony with the device.
- There is also **no way to back the root up**. A non-extractable key cannot be
  copied, by definition. Survivability means two tokens each holding their own
  root, or accepting that losing the device means re-establishing trust from
  scratch.

Signing keys for the offline dialects (OIDC tokens, SSH certificates) are still
*wrapped* rather than *held*; moving them to references is the same mechanism
and is the natural next step.

Still open: per-subtree DEKs for KV values (cryptographic erase of a subtree),
and rotation of the signing keys themselves, which is the separate operation you
perform when a *key* rather than a *seal* is suspect.

## Superseded: the original question (raised 2026-08-16)

Today `PutCA` and `PutKey` carry **private key material** through Raft into
state.db, barrier-encrypted. Public certificates belong there — they are
domain state, every replica needs them, and they are published anyway. Private
keys are a different question, and the deciding property is that **the log is
forever**:

- Rotating a signing key does not unwrite its predecessor. The old key remains
  in historical log entries, in snapshots, and in every immutable backup
  generation built from them. A barrier-key compromise at *any future time*
  therefore exposes *every* signing key the domain has ever held — the exact
  opposite of what rotation is supposed to buy.
- This applies equally to the CA intermediate and to the session/role signing
  keys, which are the golden-ticket keys (E-01 DB-3).

Options, roughly in increasing order of cost:

1. **Status quo** (MVP): barrier-encrypted in the log. Simple, and the key is
   available wherever leadership lands — which is why it was done this way —
   but it has the accumulation property above.
2. **Envelope under a seal-held DEK**: the log holds key ciphertext that the
   barrier alone cannot open; the DEK is held by the external seal (TPM/KMS).
   A barrier compromise is then insufficient, and destroying the DEK
   cryptographically shreds the historical copies. Reuses the per-subtree DEK
   design already sketched above.
3. **Reference-only**: the store holds a *handle* (PKCS#11 object, TPM key,
   KMS key ID); the private key never exists as bytes Signet writes anywhere.
   RCE then yields key *use during uptime* rather than exfiltration (E-01
   DB-3's recommended hardening). Cost: signing requires the external device to
   be reachable, and every node that may become leader needs access.

Leaning 2 as the next step and 3 as the destination, with the `keys.Key` type
already shaped so the private half can stop being a byte slice without callers
changing. Decide before multi-node, because adding replicas multiplies the
number of places a key at rest exists.

## Open questions

- Audit log: hash-chaining / external anchor for tamper evidence — worth it in v1?
- Multi-node homelab topology: 3-node domain across clusters vs single-node +
  aggressive backup. (Homelab can start single-node.)
- Break-glass: sealed-server recovery when WebAuthn/agents are unavailable
  (offline root can always mint an emergency admin credential — document the
  ceremony).
