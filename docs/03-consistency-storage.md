# 03 — Consistency & storage

**Status: Decided** (via E-03; implementation tunables remain open)
Evidence: [explorations/E-03-raft-storage.md](explorations/E-03-raft-storage.md)

## Decided architecture

- **No global database.** Each trust domain runs its own consensus group:
  1, 3, or 5 nodes, Raft, linearizable *within the domain*. Credential
  issuance is a local act; a domain partitioned from everything still works.
- **Between domains: signed artifacts only** (see 02), eventually consistent,
  verified on receipt. Sovereignty means never waiting on a remote quorum.
- **Spanner rejected deliberately**: external consistency across regions is
  the exact dependency sovereign deployments exist to eliminate.
- Single-node mode is first-class (Celeron, homelab, edge) — one-voter
  bootstrap, no operational ceremony. With the 03/11 backup design (~10 s
  RPO), "single-node + aggressive backup" is a sound small-site topology.

## Decided components (E-03)

- **Raft library: `hashicorp/raft`** (≥ v1.7.x; pre-vote default). Batteries
  match our shape exactly (FSM interface, streaming snapshots, TCP/TLS
  transport, single-voter `BootstrapCluster`, `RecoverCluster` DR), and the
  workload twins (Vault/OpenBao/Consul, rqlite) have run it for years at our
  scale. etcd-io/raft rejected: the module is lighter but we'd hand-write the
  crash-safe WAL/transport/snapshot layer (charter-violating risk) atop a
  strained maintainer org. dragonboat rejected: dormant releases, heavy deps.
  License MPL-2.0 — notice-level only, recorded in doc 12.
- **Storage engine: bbolt (MIT), one engine, two files** —
  `raft.db` (log + stable store via `raft-boltdb/v2`; escape hatch: a ~200-line
  in-house bbolt LogStore if that dep sours) and `state.db` (FSM keyspace:
  identity graph, bindings, KV, sessions/leases as bbolt buckets). Near-zero
  import graph, single-file ops, mmap-friendly on small hardware, 12-year
  crash-safety lineage. pebble rejected (66-module dep graph, LSM for a
  no-write-volume system); badger rejected (stewardship churn, data-loss
  history); own engine rejected on charter principle. raft-wal not adopted
  in v1 (experimental; solves high-churn problems we don't have).
- **No MVCC.** The Raft apply loop is the single writer (bbolt agrees — one
  write tx). Long reads (backup streaming, exports) ride bbolt read-tx
  snapshots for free; linearizable reads via leader-lease/read-index barrier,
  not versioned keys.
- **Raft entry payloads are barrier-ciphertext** — mutations are encrypted
  before `raft.Apply`, so the log store and every shipped backup segment
  inherit at-rest protection automatically (layering details in 11).

## Backup format (Decided — details in 11)

Litestream-shaped **generations** over Raft-entry WAL shipping:

- **The Raft log IS the WAL** — increments are committed logical entries,
  engine-agnostic, immune to future engine swaps and mmap coherence games.
- A generation = one FSM snapshot (Vault-style: FSM stream + meta + SHA-256
  manifest, engine-independent) + contiguous, index-range-named, self-
  checksummed, AEAD-encrypted entry segments (~4 MiB / ~10 s cuts). Any gap
  or lineage break starts a new generation; restore verifies contiguity
  before applying.
- Targets are dumb blob stores behind one small driver interface (S3, GCS,
  file/NFS): create-only writes, unique names, **zero locking** — which is
  why the format is NFS-safe while a data dir is not (flock on NFS is
  known-broken here; data dir on local disk, always).
- Restore: verify manifest/contiguity → unseal → materialize `state.db` from
  snapshot → replay segments through the normal `FSM.Apply` path → fresh
  single-voter Raft config at the restored index. Multi-node: restore one,
  wipe + rejoin the rest. Restore and re-parenting are first-class tested
  paths (10); re-parent semantics in 11.

## Anti-rollback & whole-store envelope (E-01 — requirements)

- **Whole-store barrier** [ST-2]: the barrier covers the identity graph,
  bindings, mapping rules, and attestation anchors — not just KV — so a leaked
  backup is uniformly inert (the graph is a target map). KV/keys double-
  enveloped on top (per 11).
- **Anti-rollback** [ST-1]: restore must not silently resurrect revoked state.
  A monotonic epoch/version counter is persisted and cross-checked; revocation
  records are **tombstones that survive restore** and aren't GC'd before the
  credentials they cover expire; restore is a privileged audited ceremony (11)
  that replays post-snapshot revocations and alerts on epoch regression.
- **Clock skew** [TIME-1]: TTLs are leader-clock-relative; state the tolerated
  issuance↔verification skew budget (start ±30s, reject outside) — a
  clock-controlled RP otherwise unbounds the revocation window; crown jewels
  use tier-3 online (clock-independent).

## Time (Decided)

**NTP (or equivalent) is a hard dependency** — every credential system needs
rough time agreement (Kerberos has required <5min skew for decades). The
"delta since issuance" idea was rejected: it still needs a reference for "now,"
and a fast clock still mis-expires credentials; monotonic clocks measure
durations on one machine but give no cross-machine agreement, which is what TTL
validation requires. Requirements: NTP required; defined skew budget; signed
issuance timestamps; agents refuse to present creds their own trusted clock
says are expired; crown jewels on tier-3 (clock-independent).

**Signed time-beacon (cheap double-verify):** Signet nodes emit a signed
"current time" in responses so a skewed client can **detect** drift/tampering
(not *trust* it as sole source — a rogue server could lie, so NTP stays
primary). The sound "get fancy" option is **Roughtime** (authenticated time
with cross-server lie-detection) — a later enhancement, same detect-don't-
solely-trust posture.

## Remaining open (implementation-stage)

- Segment cadence / old-generation compaction tunables.
- Exact bucket schema for the FSM keyspace (settle with the first vertical
  slice).
- Tolerated clock skew statement for TTLs (no TrueTime; TTLs relative to
  leader clock — document the bound).
