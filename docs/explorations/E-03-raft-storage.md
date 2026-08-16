# E-03 — Raft library + storage engine + backup format

**Mission:** E-03 (P0) · **Feeds:** doc 03 (primary), doc 11 (backups/encryption) · **Date:** 2026-08-16
**Status: Complete — recommendations below**

## Question

Three selections for Signet's per-domain consensus/storage core:

1. **Raft library** — hashicorp/raft vs etcd-io/raft (go.etcd.io/raft/v3) vs a credible third (dragonboat assessed).
2. **Storage engine** — bbolt vs pebble vs badger vs own append-only log + in-memory index, for both the Raft log store and the state-machine (FSM) store.
3. **Backup format** — concrete snapshot + WAL-stream interface: what a snapshot *is*, how increments ship, encryption-before-egress, restore (incl. single-node DR from object storage), and re-parenting interaction.

Plus: is MVCC needed, and how should at-rest encryption layer (whole-engine vs per-subtree envelope)?

Constraints that drove everything: single-node first-class (Celeron, no quorum theater); low write volume; ~zero dependency budget beyond "one Raft library, one storage engine"; Apache-2.0-leaning project; data dir always local disk; NFS backup target only.

## Method / sources

Web research 2026-08-16: GitHub repos (releases, issues, go.mod files fetched raw), pkg.go.dev, HashiCorp/OpenBao docs, Litestream design docs, CNCF TOC project-health discussion. Key sources:

- hashicorp/raft releases — https://github.com/hashicorp/raft/releases (v1.7.3, 2025-03-20; pre-vote default since v1.7.0, critical fixes in v1.7.1)
- hashicorp/raft go.mod — https://raw.githubusercontent.com/hashicorp/raft/main/go.mod
- etcd-io/raft — https://github.com/etcd-io/raft (Apache-2.0, minimalist scope) + go.mod
- CockroachDB fork — https://github.com/cockroachdb/raft (forked from etcd-io/raft, 2024)
- etcd project health — https://github.com/cncf/toc/issues/898 (maintainer turnover; "lack of new folks with sufficient knowledge to offset the loss")
- dragonboat — https://github.com/lni/dragonboat (v3.3 from 2021; v4 unreleased on unstable master; go.mod pulls pebble, cockroachdb/errors→sentry-go, memberlist…)
- bbolt — https://github.com/etcd-io/bbolt/releases (v1.5.0 2025-06-21; 1.4.x and 1.3.x maintenance lines active Aug 2025)
- pebble go.mod — https://raw.githubusercontent.com/cockroachdb/pebble/master/go.mod (66 require lines)
- badger — https://github.com/hypermodeinc/badger + issue history (#570 "Prove that Badger loses data", #1126)
- raft-boltdb — https://github.com/hashicorp/raft-boltdb (MPL-2.0; v2 = bbolt backend)
- raft-wal — https://github.com/hashicorp/raft-wal (MPL-2.0; README: "still considered experimental")
- OpenBao integrated storage — https://openbao.org/docs/internals/integrated-storage/ (bbolt state; "snapshot just truncates the raft logs"); auto-snapshot issue https://github.com/openbao/openbao/issues/795
- Litestream — https://litestream.io/how-it-works/ + https://fly.io/blog/litestream-v050-is-here/ (generations, snapshot + sequential WAL segments, gap ⇒ new generation, contiguity check before restore)

## Findings

### 1. Raft libraries

| Criterion | hashicorp/raft | etcd-io/raft (raft/v3) | dragonboat |
|---|---|---|---|
| API model | Batteries included: `FSM` interface (Apply/Snapshot/Restore), pluggable `Transport` (TCP w/ TLS via StreamLayer ships), `LogStore`/`StableStore`/`SnapshotStore` interfaces | Pure state machine: you own the event loop (`Ready` channel), transport, log persistence (WAL), snapshot orchestration. etcd's own WAL/transport live in the etcd repo, not the library | Full multi-group node host: built-in transport, log storage (pebble), its own snapshot pipeline |
| Code you must write | ~glue: implement `FSM`, pick stores | An entire durability + transport layer (etcd's `wal` package is ~3k lines you'd port or reinvent) — the exact code the charter says never to hand-roll | Little, but you inherit its opinions and deps |
| Single-node ergonomics | First-class: `BootstrapCluster` with one server; this is exactly Vault/OpenBao/Consul dev-and-small-prod mode; `RecoverCluster`/peers.json is a documented DR path | Works (single-member etcd is common) but *you* build the bootstrap/recovery ergonomics | Oriented to multi-group, multi-node clusters; docs/examples assume 3–5 nodes |
| Snapshot integration | Built-in: `FSM.Snapshot() → SnapshotSink` streaming, `FileSnapshotStore` provided, snapshot store is an interface (drop-in for our encrypted/remote sink) | You drive compaction and snapshot transfer yourself via `Ready`/`ReportSnapshot` | Built-in, tied to its storage layer |
| Dynamic membership | `AddVoter`/`AddNonvoter`/`RemoveServer`/`LeadershipTransfer`; joint consensus not needed at our scale | Joint consensus (two-phase) — more general, more surface | Yes |
| Pre-vote / check-quorum | Pre-vote implemented and **default since v1.7.0** (2024; fixed in v1.7.1); leader lease/stepdown behavior built in | Both, as config flags, long-proven | Yes |
| Maintenance 2025–26 | Active: v1.7.3 (2025-03), issues triaged into 2026; HashiCorp/IBM funds it because Consul/Vault/Nomad sit on it | Alive but strained: library is "stable and feature complete"; etcd org has documented maintainer-capacity problems (CNCF TOC #898); **CockroachDB forked to cockroachdb/raft in 2024** to evolve independently — the second-biggest user left | v3.3 released 2021; v4 has sat unreleased on an "unstable" master for years; effectively one maintainer |
| License | **MPL-2.0** (library was *not* BUSL-relicensed; file-level copyleft, standard practice to depend on from Apache/MIT projects — e.g. rqlite, MIT, ships it) | **Apache-2.0** | Apache-2.0 |
| Transitive deps (go.mod require, excl. test-only) | Small: go-hclog, go-metrics, go-msgpack/v2 (+ isatty/colorable/color via hclog, x/sys) — ~8 modules, all pure Go | **Near zero**: google.golang.org/protobuf only (testify/datadriven are test-only) | Heavy: pebble (pinned 2022 pre-release!), cockroachdb/errors → **sentry-go**, memberlist → miekg/dns, VictoriaMetrics/metrics, lz4, snappy… 40+ modules |
| Track record | Consul, Vault, Nomad, OpenBao, rqlite — i.e. the exact workload shape Signet has (small control-plane state, low write rate, 1–5 nodes) | etcd, Kubernetes-adjacent everything, CockroachDB (until fork), TiKV lineage — huge-scale multi-tenant workloads | A few Chinese-market databases (matrixorigin lineage) |

**The dependency-weight picture inverts once you count what etcd/raft makes you build.** etcd-io/raft the *module* is the lightest, but Signet would then hand-write a crash-safe WAL, snapshot transfer, transport framing, and bootstrap/recovery tooling — hundreds of hours and the riskiest kind of code (durability). hashicorp/raft's ~8 small pure-Go modules buy all of that, proven in Vault for 6+ years. Dragonboat is honestly assessed as disqualified: wrong shape (multi-group perf machine), dormant release train, and a dependency graph (sentry-go inside a consensus library) that violates the charter by itself.

**Is following OpenBao/Vault (hashicorp/raft + bbolt) inertia?** No — it's convergent evidence. Vault's integrated storage has the same profile Signet targets (secrets/identity control plane, low write volume, tiny clusters, snapshot-based DR), it displaced Consul-backed storage precisely because operators wanted single-binary simplicity, and OpenBao's docs confirm the pairing keeps snapshots cheap ("data already persisted in BoltDB, the snapshot process just needs to truncate the raft logs"). The one place the pairing shows age — raft-boltdb freelist bloat under *high* churn, which motivated raft-wal — does not bite at Signet's write volume, and raft-wal remains README-labeled experimental anyway.

**MPL-2.0 caveat:** file-level copyleft only. Signet stays Apache-2.0; obligations are keeping MPL notices and publishing modifications *to the MPL files themselves* if we ever fork/patch the library. No viral effect on Signet code. Acceptable; note it in doc 12 (governance/licensing).

### 2. Storage engines

| Criterion | bbolt | pebble | badger | own append-only log + mem index |
|---|---|---|---|---|
| Model | B+tree, mmap, single file, one writer / many readers | LSM, background compaction goroutines | LSM + value log | bespoke |
| Crash-safety record | Bolt lineage since 2013; backs etcd, Consul, Vault/OpenBao, k3s/kine; actively maintained under etcd-io (v1.5.0 Jun 2025; 1.4.x/1.3.x maintenance releases Aug 2025) | Excellent (CockroachDB), but validated inside CRDB's harness | Historical data-loss issues (#570, #1126); v4.0.0 tag retracted; stewardship churn Dgraph→Hypermode | Unproven by definition; fsync/rename/torn-write discipline is exactly the hard part |
| Deps (library import graph) | **~zero**: x/sys (+x/sync); cobra/etc. are CLI/test-only | **66 require lines** incl. zstd (cgo-optional), sentry-go via cockroachdb/errors, prometheus client — a dependency event horizon | Moderate-heavy: ristretto, flatbuffers, klauspost/compress… | zero |
| Fit at low write volume | Ideal: write amp of CoW B+tree is irrelevant at our rate; no background threads; predictable | Pays LSM complexity (compaction CPU/RAM) for write throughput we will never generate | Same mismatch + value-log GC tuning | n/a |
| Celeron-class footprint | mmap = page cache does the work; tiny heap; zero idle CPU | Memtables + block cache + compaction; tens-to-hundreds of MB working set | Similar or worse (default options are memory-hungry) | small |
| Ops story | **One file per store**; `cp`-able when quiesced; read-only tx = consistent snapshot for free | Directory of SSTs + MANIFEST + WAL | Directory + value logs | our problem forever |
| License | MIT | BSD-3-Clause | Apache-2.0 | — |

bbolt's known weaknesses — large-DB freelist growth, write throughput ceilings, whole-file mmap — all sit outside Signet's envelope (domain state is megabytes-to-low-gigabytes, writes are sparse). The "own engine" option is rejected on charter principle 2's spirit: durability code is crypto-adjacent — never hand-roll what has a boring, vetted incumbent. It would also *delay* the backup story, not simplify it, since the Raft layer (below) already gives us the logical WAL to ship.

**Log store vs FSM store:** use the Vault/OpenBao file layout — two bbolt files, one engine:

- `raft.db` — Raft log + stable store. Start with **hashicorp/raft-boltdb/v2** (bbolt-backed, MPL-2.0). If the MPL dep or its freelist behavior ever offends, a bbolt `LogStore`/`StableStore` is ~200 lines of Apache-2.0 code we can write in an afternoon — it's a key-value mapping, not consensus. Do **not** adopt raft-wal in v1 (experimental label; solves a high-churn problem we don't have).
- `state.db` — the FSM: identity graph, role bindings, KV secrets, leases, one keyspace of bbolt buckets (doc 03 "Schema" question).

Separate files keep log truncation from fragmenting the state file, make FSM snapshot/restore an atomic file-swap, and match the operational folklore of every Vault/OpenBao runbook.

### 3. MVCC — not needed

The Raft apply loop is the single writer; bbolt permits exactly one write tx anyway, so the engine and the consensus model agree. Readers get consistency for free: a bbolt read transaction sees an immutable snapshot of the tree without blocking the writer — that covers the two "long read" cases (backup streaming, large list/export) that usually motivate MVCC. Full MVCC (multi-version keys, GC, tx timestamps) buys concurrent-writer semantics Signet cannot use and etcd-style watch-history Signet doesn't promise. **Decide: single-writer-apply; no MVCC.** If cross-key read-your-writes matters for an API call, serve linearizable reads via leader lease/read-index barrier, not versioned storage.

### 4. Backup format — snapshot + WAL stream

What each prior art contributes:

- **Vault/OpenBao snapshots**: the snapshot is the *FSM*, not the engine file — `operator raft snapshot save` produces a self-contained archive (FSM stream + metadata + SHA256SUMS) that restores onto any node and is engine-version-independent. Steal: FSM-level snapshots, integrity manifest, restore-then-rejoin flow. Weakness: full snapshots only; incremental backup doesn't exist (community agents just re-ship full snapshots on a timer — OpenBao #795).
- **etcd snapshots**: engine-level (bbolt file copy) — fast but couples backup format to storage internals and mmap page layout. Reject as the *interchange* format; fine as a local fast path.
- **Litestream**: the shape we want for increments — a **generation** = one full snapshot + a strictly contiguous sequence of WAL segments; any gap or lineage change starts a new generation; restore verifies contiguity before applying; hierarchical compaction keeps restore to ~a dozen objects. Steal: generations, contiguity-checked segments, dumb-object-storage-only requirements (no server; works on S3/GCS/NFS alike).

**Signet's twist: the Raft log *is* the WAL.** Because every mutation is a committed Raft entry, the incremental stream is engine-agnostic logical replication — ship committed entries, not engine pages. That means the backup format survives any future engine change and never fights mmap/page-cache coherence the way file-level copying does.

Concrete design:

- **Snapshot** = Raft FSM snapshot (the same `FSM.Snapshot()` stream consensus already uses), wrapped: `meta.json` (format version, domain UUID + trust-chain fingerprint, raft term + index, key epochs, schema version) + encrypted FSM stream + SHA-256 manifest. Values inside the stream are *already* barrier-ciphertext (see §5); the wrapper AEAD additionally hides structure/keys/metadata.
- **WAL segments** = batches of committed Raft entries `(index, term, data)` in `[snapshotIndex+1 …]`, cut by size (~4 MiB) or time (~10 s at our volume), each self-checksummed and AEAD-encrypted, named by index range so contiguity is verifiable from object listing alone.
- **Generation** = `(domainUUID, snapshotIndex, snapshotTerm, random 8-hex)`. New generation on: new snapshot, term regression/lineage break detected, or seal rekey. Object layout: `<prefix>/<domainUUID>/<generation>/snapshot`, `.../wal/<firstIndex>-<lastIndex>`, `.../MANIFEST`.
- **Targets**: one small driver interface (put/get/list/delete, ranged get) — S3, GCS, file/NFS. NFS driver needs **no locking** (writes are create-only, names are unique) — which is precisely why the format works on NFS while a data dir cannot.

```go
// Backup target: dumb blob store. No locks, no server, create-only writes.
type BackupTarget interface {
    Put(ctx context.Context, key string, r io.Reader) error
    Get(ctx context.Context, key string) (io.ReadCloser, error)
    List(ctx context.Context, prefix string) ([]ObjectInfo, error)
    Delete(ctx context.Context, key string) error
}

// Streamed, encrypted-before-egress backup of one domain.
type BackupWriter interface {
    // Full FSM snapshot at a raft (index, term); starts a new generation.
    BeginSnapshot(meta SnapshotMeta) (io.WriteCloser, error) // AEAD chunked stream
    // Committed raft entries after the generation's snapshot index.
    AppendEntries(entries []raft.Log) error                  // cut into segments internally
    // Durably record segment/manifest state.
    Sync(ctx context.Context) error
}

type Restorer interface {
    // Latest generation ≤ target point; verifies manifest + contiguity FIRST.
    Plan(ctx context.Context, t BackupTarget, domain uuid.UUID, at RestorePoint) (RestorePlan, error)
    // Decrypt+load snapshot into a fresh state.db, then replay segments
    // through the normal FSM.Apply path; refuse on any gap or MAC failure.
    Execute(ctx context.Context, plan RestorePlan, dataDir string, unseal Sealer) error
}
```

- **Encryption before egress**: chunked AEAD (AES-256-GCM or XChaCha20-Poly1305, 64 KiB frames, nonce = frame counter, AAD = meta hash) under a **backup key** wrapped by the seal — a *distinct* wrap from the barrier key so a backup credential never equals a live-store credential. A leaked backup is doubly inert: outer AEAD + inner barrier ciphertext (doc 11's requirement).
- **Restore / single-node DR**: `signet restore --from s3://… --domain <uuid>` on an empty data dir: fetch MANIFEST → verify generation contiguity and checksums → unseal (TPM/KMS/Shamir per E-09) → unwrap backup key → materialize `state.db` from snapshot → replay WAL segments via `FSM.Apply` → write a fresh single-voter Raft config (`RecoverCluster`-style) at the restored index → serve. Loss window = one segment interval (~10 s), vs hours-to-a-day for Vault-style periodic full snapshots. Multi-node: restore one node, wipe+rejoin the rest (Vault's proven flow).
- **Re-parenting × restore**: `meta.json` carries the domain's trust-chain fingerprint. Restore compares it to the currently configured parent: match ⇒ plain restore; mismatch ⇒ refuse unless `--re-parent`, which restores the *local* state (identities, bindings, KV, leases) but marks parent-derived material — the domain intermediate, cached parent bundles, upstream federation artifacts — as **stale-pending-ceremony**, and requires the re-parent ceremony (new intermediate issued by the new parent, doc 02/11) before the domain serves credentials that chain upward. Local-only issuance may optionally continue in the interim (sovereignty principle). This makes restore-into-new-parent a designed path, not a foot-gun that silently resurrects a dead trust lineage.

### 5. Encryption-at-rest layering

Two layers, both, not either/or:

1. **Barrier (whole-store)**: every value AEAD-encrypted with a keyring data key before it touches bbolt (Vault's proven model). Keyring supports epochs → online rekey without rewriting history at once. Sealed by the E-09 seal (TPM/KMS/Shamir). Protects: stolen disk, stolen `state.db`/`raft.db` (Raft entry payloads are barrier-ciphertext too — entries are encrypted before `raft.Apply`, so the log store and every WAL backup segment inherit protection automatically).
2. **Per-subtree envelope (KV secrets + private key material)**: subtree DEKs wrapped by the barrier key; values under those subtrees are `DEK-AEAD(barrier-AEAD(...))`-independent — i.e., enveloped under their DEK *inside* the barrier. Buys: per-subtree rotation/shredding (drop the DEK ⇒ cryptographic erase of a tenant/subtree), and defense-in-depth so a memory-scraped barrier key alone doesn't open the KV corpus. Cheap at our volume; matches doc 11's "leaked backups inert without the seal" with margin.

Bucket names / graph structure remain plaintext inside the store (needed for range scans); the backup wrapper's outer AEAD hides them at rest off-box.

## Recommendation

1. **Raft: hashicorp/raft (v1.7.x, pre-vote default).** Batteries (FSM, snapshots, transport, single-voter bootstrap, cluster recovery) exactly match Signet's shape; actively maintained through 2025–26; the workload twin (Vault/OpenBao/Consul) has run it for years at our exact scale including single-node. MPL-2.0 is a notice-level obligation, not a contamination risk (precedent: rqlite/MIT). etcd-io/raft's zero-dep purity is real but would force us to hand-write WAL + transport + snapshot plumbing — charter-violating risk — while its org shows maintainer strain and lost its flagship external user to a 2024 fork. Following the Vault pairing is evidence-based convergence, not inertia; the one known wart (raft-boltdb under high churn) is out of our envelope.
2. **Storage: bbolt (MIT) for both stores, two files** — `raft.db` via raft-boltdb/v2 (with a trivial in-house bbolt LogStore as the escape hatch), `state.db` for the FSM keyspace. Near-zero import graph, single-file ops, mmap-friendly on Celeron, 12-year crash-safety record, actively maintained under etcd-io. Pebble rejected on dependency weight alone (66 requires incl. sentry-go) before even reaching LSM/idle-compaction mismatch; badger rejected on stewardship churn + data-loss history; own engine rejected on charter principle.
3. **Backup: Litestream-shaped generations over Raft-entry WAL shipping + Vault-shaped FSM snapshots**, chunk-AEAD-encrypted under a seal-wrapped backup key before egress, to dumb blob targets (S3/GCS/NFS, create-only, lock-free). Restore = snapshot + contiguity-verified replay + single-voter cluster recovery; re-parenting is an explicit `--re-parent` mode that quarantines parent-derived trust material pending ceremony.

**MVCC: no** — Raft single-writer apply + bbolt read-tx snapshots cover every real need; linearizable reads via read-barrier, not versioned keys.
**Encryption: both layers** — Vault-style barrier keyring for everything + per-subtree DEK envelopes for KV/keys (rotation + cryptographic erase + inert backups).

## Impact on design docs

- **doc 03 "Open questions"** → resolve and move to Decided:
  - Raft library: hashicorp/raft; note MPL-2.0 posture and pre-vote/1.7.1 minimum version.
  - Storage engine: bbolt ×2 files (raft.db / state.db); record raft-boltdb→own-LogStore escape hatch and explicit rejection rationale for pebble/badger/own.
  - MVCC line: decide "single-writer apply; bbolt read-tx for long reads; no MVCC".
  - Encryption layering line: decide "barrier keyring + per-subtree DEK envelope" (cross-ref 11).
  - Add: Raft entries carry barrier-ciphertext payloads (log store + backups inherit encryption).
- **doc 03 "Requirements"** — expand the backup bullet to name the format: generations, FSM snapshot + committed-entry segments, contiguity rule, lock-free NFS compatibility.
- **doc 11 "Backups"** → format moves Open→Decided: generation layout, segment cadence (≈10 s loss window), backup key distinct from barrier key and wrapped by seal, restore flow incl. single-node DR and `--re-parent` quarantine semantics. Cross-ref E-09 (seal) for key custody of the backup wrap.
- **doc 11 "Open questions"** — the "single-node + aggressive backup" homelab topology becomes concretely viable (10 s RPO); reflect that in the 3-node-vs-single-node discussion.
- **doc 09 (module layout)** — expect packages: `consensus` (raft glue), `store` (bbolt + barrier), `backup` (writer/restorer/targets).
- **doc 12 (governance)** — record third-party license inventory: MPL-2.0 (hashicorp/raft, raft-boltdb), MIT (bbolt), and the notice obligations.

## Confidence and what would change the conclusion

**Confidence: high** on all three picks (raft: high; bbolt: very high; backup shape: high on architecture, medium on tunables like segment cadence and compaction of old generations — settle those in implementation).

Would change the conclusion:

- **hashicorp/raft relicensed to BUSL** (IBM-era policy shift) → drop to etcd-io/raft + write our own WAL/transport, or adopt a community fork; the FSM/store interfaces recommended here keep that swap contained to the `consensus` package. (No signal of this today; the library stayed MPL through the 2023 BUSL wave and the IBM acquisition.)
- **Signet's write volume assumption breaks** (e.g., per-request lease writes at high QPS) → revisit raft-wal (if it sheds the experimental label) for the log store; bbolt FSM likely still fine.
- **Domain state grows to tens of GB** (it shouldn't — that's a design smell for an identity kernel) → bbolt mmap + full-snapshot cost degrade; pebble re-enters despite its deps.
- **etcd-io/raft ships an official maintained WAL+transport companion module** → the "you build the durability layer" objection weakens; dependency-purity argument could then win.
- **raft-boltdb goes unmaintained** → execute the escape hatch (in-house ~200-line bbolt LogStore); pre-planned, not conclusion-changing.
