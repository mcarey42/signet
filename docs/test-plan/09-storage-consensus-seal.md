# Test plan 09 — Storage, consensus, and seals

**Status: Draft** · **Date: 2026-08-18** · **Area owner: storage/consensus/seal**

Scope: `internal/store` (buckets, `Tx`, barrier, snapshot), `internal/fsm`
(Raft FSM + `Node`), `internal/seal` (file seal, envelopes, root key, PKCS#11),
and `internal/kernel/sealrotate.go` (inventory, rotation, verification).

Design references: [03 — Consistency & storage](../03-consistency-storage.md),
[11 — Operations](../11-operations.md),
[E-03 — Raft/storage/backup](../explorations/E-03-raft-storage.md),
[10 — Testing strategy](../10-testing-strategy.md).

Everything below is grounded in `file:line` against the tree at commit time. Where
a claim was established by running code rather than by reading it, the scenario
says **(verified)** and the observed output is quoted.

---

## 0. How these tests run

The source tree sits on an NFS mount whose server does not implement `flock`, and
the Go toolchain locks `go.mod` during module operations. **Never run bare
`go test`/`go build` in this tree.** Use the Makefile targets, which rsync to a
local-disk mirror first (`Makefile:1-10`):

| Command | What it runs | Source |
|---|---|---|
| `make test` | full suite, default (pure-Go, no PKCS#11) build | `Makefile:24-26` |
| `make build` | static default binary | `Makefile:19-22` |
| `make softhsm` | provisions a SoftHSM2 token + AES wrapping key | `Makefile:54-61` |
| `make test-hsm` | `softhsm` then `go test -tags pkcs11 ./internal/seal/` with `SIGNET_TEST_PKCS11` set | `Makefile:63-68` |
| `make build-hsm` | cgo binary with hardware-seal support | `Makefile:72-75` |

Consequences for this plan:

- Every scenario tagged **[hsm]** requires `make test-hsm` (or an equivalent
  environment) and is skipped otherwise — `pkcs11_test.go:22-34` skips when
  `SIGNET_TEST_PKCS11` is unset.
- Scenarios tagged **[default-build]** must be asserted under the *untagged*
  build, because they are about what a binary without `pkcs11` refuses to do.
  `make test` is the only place they are meaningful.
- Crash-injection scenarios (§8) need a harness that does not exist yet; the
  plan states what it must do rather than pretending an in-process test suffices.

---

## 1. Invariants this area must protect

Each scenario names the invariant it defends. Stating them separately keeps the
matrix honest: a test that does not map to one of these is decoration.

| ID | Invariant | Where it is claimed |
|---|---|---|
| **INV-AAD** | A sealed value is bound to its (bucket, key). Moving ciphertext to another location must fail to open, never silently succeed. | `barrier.go:95-102`, `store.go:115,125,146` |
| **INV-NONCE-DET** | `Apply` is a pure function of (op, prior state); the nonce is derived from log position so replicas produce byte-identical ciphertext. | `barrier.go:55-62`, `docs/03:41-44` |
| **INV-NONCE-UNIQ** | The same (barrier key, nonce) pair is never used for two different plaintexts. AES-GCM fails catastrophically otherwise — keystream and the GHASH authentication key both fall out. | implied by `barrier.go:60-62,84-93`; **not stated anywhere in the source** |
| **INV-IDEM** | Replaying a committed entry over its own results is a no-op. Accumulating values (`m.CurrentVersion + 1`, `secrets.go:67`) must not drift. | `store.go:163-174`, `fsm.go:36-46`, `fsm_test.go:31-36` |
| **INV-ATOMIC** | A mutation and its audit record commit together or not at all. | `audit.go:80-84`, `fsm.go:57-70` |
| **INV-SNAP-FIDELITY** | Snapshot → restore reproduces every bucket byte-for-byte, including the watermark and the audit chain. | `snapshot.go:7-10,13-35,40-60`, `fsm.go:85-102` |
| **INV-SEAL-CUSTODY** | The barrier root key exists on disk only in wrapped form; the data directory is useless without the seal that created it. | `seal.go:191-196`, `docs/11:152-156` |
| **INV-SEAL-BIND** | A wrapped blob opens only under the seal that wrapped it *and* the AAD it was wrapped for. | `seal.go:50-53,162-164`, `seal_test.go:44-66` |
| **INV-ROT-IDENTITY** | Seal rotation is a custody change, not a re-key: key IDs, public halves, and previously issued credentials survive it. | `sealrotate.go:16-29`, `docs/11:165-176` |
| **INV-ROT-PROVEN** | A rotation reports success only after every item has been *opened* under the destination seal. | `sealrotate.go:165-168`, `main.go:832-841` |
| **INV-HELD** | A key generated inside a token is `CKA_SENSITIVE` and `CKA_EXTRACTABLE=false`, verified by read-back, and its private half never enters Signet's address space. | `pkcs11_signer.go:20-24,50-52,83-85` |
| **INV-NO-FALLBACK** | A configured hardware seal in a binary without PKCS#11 support is refused, never silently downgraded. | `pkcs11_disabled.go:17-24`, `docs/11:158-163` |
| **INV-LINEAGE** | State and the Raft log that produced it must belong to the same lineage. A store must never be driven by a log that did not produce it. | **not claimed or enforced anywhere** — see §9.1 |

---

## 2. Barrier: encryption, AAD binding, deterministic nonces

`internal/store/barrier.go`. **There is no `barrier_test.go`.** Everything here
is either exercised incidentally through `audit_test.go` or is a GAP.

| ID | Precondition | Input | Expected result | Invariant | Coverage |
|---|---|---|---|---|---|
| BAR-01 | Barrier over a 32-byte root key | `SealRandom(pt, aad)` then `Open(ct, aad)` | round-trips to `pt`; `ct` does not contain `pt` | INV-AAD | **GAP** (only `seal_test.go:23-40` covers the *seal*, not the barrier) |
| BAR-02 | as above | `SealDeterministic(1,1,0,pt,aad)` then `Open` | round-trips | INV-NONCE-DET | **GAP** |
| BAR-03 | as above | two `SealRandom` calls, same plaintext+aad | ciphertexts differ (nonce is random, `barrier.go:48-52`) | INV-NONCE-UNIQ | **GAP** |
| BAR-04 | two barriers from the *same* root key | `SealDeterministic(t,i,s,pt,aad)` on each | byte-identical output | INV-NONCE-DET | PARTIAL — `apply_test.go:90-125` asserts this at the store level, not the barrier |
| BAR-05 | one barrier | `SealDeterministic` over the cross product of term ∈ {0,1,2^63}, index ∈ {0,1,2^63}, seq ∈ {0,1,2^31} | all 27 derived nonces distinct; no two (term,index,seq) triples collide | INV-NONCE-UNIQ | **GAP** |
| BAR-06 | one barrier | `deriveNonce(0, 1, 0)` vs `deriveNonce(1, 0, 0)` — the classic field-shift collision | distinct nonces (fields are fixed-width big-endian, `barrier.go:85-88`) | INV-NONCE-UNIQ | **GAP** |
| BAR-07 | one barrier | `SealDeterministic(t,i,s,pt1,aad)` and `SealDeterministic(t,i,s,pt2,aad)` with `pt1 != pt2` | **nonces are identical** — this is the documented cost of determinism and the caller is responsible for never doing it | INV-NONCE-UNIQ | **GAP** — verified by probe: *"identical (term,index,seq) yields an identical nonce for different plaintext"*. This must be a *named, commented* test so the property is visible, not accidental. |
| BAR-08 | sealed under `aad("principals","alice")` | `Open` with `aad("bindings","alice")` | error `barrier: open: …message authentication failed` | INV-AAD | **GAP** |
| BAR-09 | sealed under `aad("principals","alice")` | `Open` with `aad("principals","bob")` | error | INV-AAD | **GAP** |
| BAR-10 | ciphertext from barrier A | `Open` under barrier B (different root key) | error | INV-AAD | **GAP** |
| BAR-11 | valid ciphertext | flip one bit in the tag region, `Open` | error, no plaintext returned | INV-AAD | **GAP** |
| BAR-12 | valid ciphertext | flip one bit in the *nonce* prefix, `Open` | error | INV-AAD | **GAP** |
| BAR-13 | valid ciphertext | truncate to 11 bytes (< `NonceSize`), `Open` | error `barrier: ciphertext too short` (`barrier.go:74-76`), **not** a panic or slice-bounds fault | INV-AAD | **GAP** |
| BAR-14 | valid ciphertext | truncate to exactly 12 bytes (nonce only, zero-length body) | error from GCM, no panic | INV-AAD | **GAP** |
| BAR-15 | valid ciphertext | append 1 trailing byte | error | INV-AAD | **GAP** |
| BAR-16 | — | `NewBarrier(nil)` and `NewBarrier([]byte{})` | HKDF with an empty IKM currently *succeeds* (`barrier.go:30`); decide whether this must be refused — see Q1 | INV-SEAL-CUSTODY | **GAP** |
| BAR-17 | two barriers from root keys differing in one bit | seal the same plaintext deterministically | ciphertexts differ, and neither opens the other's | INV-AAD | **GAP** |
| BAR-18 | — | `aad("secret_data", "a\x001")` vs `aad("secret", "_data\x00a\x001")` | distinct AAD byte strings; bucket names contain no NUL so the separator at `barrier.go:99` is unambiguous even though `BucketSecretData` **keys** contain NUL (`secrets.go:19-21`) | INV-AAD | **GAP** — this is exactly the ambiguity `ChainHash` was length-prefixed to avoid (`audit.go:66-78`); the barrier's AAD relies on an unstated argument instead |
| BAR-19 | barrier over root key K | `SealRandom` vs `SealDeterministic` output for the same input | both open with the same `Open`; nonce travels in the ciphertext (`barrier.go:64-68,70-72`) | INV-NONCE-DET | **GAP** |
| BAR-20 | — | HKDF info strings `signet/barrier/v1` (`barrier.go:24`) and `signet/nonce/v1` (`barrier.go:90`) | golden-vector test: a fixed root key produces a fixed barrier key and a fixed nonce, so a future refactor that changes derivation is caught as the store-format break it is | INV-SNAP-FIDELITY | **GAP** |

---

## 3. Store: buckets, transactions, scans

`internal/store/store.go`. **There is no `store_test.go`.**

| ID | Precondition | Input | Expected result | Invariant | Coverage |
|---|---|---|---|---|---|
| STO-01 | empty dir | `Open(path, key)` | all 19 buckets in `allBuckets` (`store.go:39-45`) exist afterwards | INV-SNAP-FIDELITY | PARTIAL — implied by `audit_test.go:15-27` succeeding |
| STO-02 | store with data | `Open` again with the same key | prior values readable | INV-SEAL-CUSTODY | PARTIAL — `fsm_test.go:68-88` at the node level |
| STO-03 | store written under key A | `Open` with key B | **currently succeeds.** `Open` performs no verification that the root key matches the store (`store.go:58-79`) | INV-SEAL-CUSTODY | **GAP** — verified by probe: *"store.Open accepted a root key that cannot decrypt the store"*, and a subsequent `Put` overwrote the real value irrecoverably. See §9.2 |
| STO-04 | store already open in this process | second `Open` on the same path | blocks then fails after the 5 s bbolt timeout (`store.go:63`) | single-writer | **GAP** |
| STO-05 | `state.db` truncated to 512 bytes | `Open` | a clean error naming the file, never a panic or a silently-empty store | INV-SNAP-FIDELITY | **GAP** |
| STO-06 | `state.db` replaced with 4 KiB of random bytes | `Open` | clean error | INV-SNAP-FIDELITY | **GAP** |
| STO-07 | `state.db` is a valid bbolt file with no Signet buckets | `Open` | buckets created, store behaves as empty (`store.go:67-73`) | — | **GAP** |
| STO-08 | write tx | `Put(bucket, key, val)` then `Get` in the same tx | returns `val, true, nil` | INV-AAD | PARTIAL — `audit_test.go:98-112` |
| STO-09 | read tx | `Put` | `ErrReadOnly` (`store.go:112-114`) | — | **GAP** |
| STO-10 | read tx | `Delete` | `ErrReadOnly` (`store.go:133-135`) | — | **GAP** |
| STO-11 | any tx | `Get(bucket, "absent")` | `nil, false, nil` | — | PARTIAL — `audit.go:118-122` relies on it |
| STO-12 | any tx | `Get("no_such_bucket", k)` | **panics with a nil-pointer dereference.** `store.go:121` calls `.Get` on the `nil` returned by `tx.Bucket` | — | **GAP** — verified by probe: *"Tx.Get on an unknown bucket panics: runtime error: invalid memory address or nil pointer dereference"*. Same hazard at `store.go:117` (Put), `:136` (Delete), `:142` (ScanPrefix). See Q2 |
| STO-13 | write tx | `Put` then `Delete` then `Get` | `nil, false, nil` | — | PARTIAL — `audit_test.go:147-162` |
| STO-14 | one write tx, N `Put`s | observe `t.seq` progression | seq increments once per `Put` only (`store.go:116`); `Delete` does not consume a seq | INV-NONCE-UNIQ | **GAP** |
| STO-15 | 100 keys under two prefixes | `ScanPrefix(bucket, "a/", fn)` | visits only `a/…`, in ascending key order, decrypted | INV-AAD | PARTIAL — `audit.go:165-189` uses it with an empty prefix; a non-empty prefix is untested |
| STO-16 | as above | `fn` returns `false` on the 3rd key | scan stops, returns `nil` (`store.go:150-152`) | — | **GAP** |
| STO-17 | bucket where one value was tampered | `ScanPrefix` | returns the barrier error and aborts the scan (`store.go:147-148`) — a scan must not skip an unreadable record and pretend the bucket is shorter | INV-AAD | **GAP** |
| STO-18 | empty bucket | `ScanPrefix(bucket, "x", fn)` | `fn` never called, returns nil | — | **GAP** |
| STO-19 | `BucketSecretData` with keys `p\x00…0001` and `p\x00…0002` | `ScanPrefix(bucket, "p\x00", fn)` | both visited; embedded NUL in the key does not truncate the prefix comparison (`store.go:193-203`) | INV-AAD | **GAP** |
| STO-20 | write tx at `(term=5, index=9)` | `Position()` | `(5, 9)` (`store.go:158`) | INV-NONCE-DET | **GAP** |
| STO-21 | read tx | `Position()` | `(0, 0)` — a read tx carries no position (`store.go:98`); confirm no caller uses it to seal | INV-NONCE-UNIQ | **GAP** |
| STO-22 | store with data | `View` while a `Update` runs concurrently | the reader sees a consistent pre-write snapshot and does not block the writer (E-03 §3, `E-03:80-82`) | — | **GAP** |
| STO-23 | write tx whose `fn` returns an error | after `Update` returns | nothing was written — bbolt rolls back | INV-ATOMIC | PARTIAL — `apply_test.go:276-308` asserts "rejected ops write nothing" but through `kernel.Apply`, which returns `nil` from the tx closure |
| STO-24 | — | `EncodeUint(0)`, `EncodeUint(^uint64(0))` round-tripped through `binary.BigEndian.Uint64` | exact (`store.go:205-210`) | — | **GAP** |

---

## 4. Applied-index watermark and idempotence under replay

`store.go:160-191` + `fsm.go:27-33,43-46,69,73`. This is where the "a secret's
version drifted on every restart" bug lived, and where it can still return.

| ID | Precondition | Input | Expected result | Invariant | Coverage |
|---|---|---|---|---|---|
| WM-01 | fresh store | `AppliedIndex()` | `(0, nil)` — absent key is not an error (`store.go:180-183`) | INV-IDEM | **GAP** |
| WM-02 | `SetAppliedIndex(7)` committed | `AppliedIndex()` | `(7, nil)` | INV-IDEM | **GAP** |
| WM-03 | `SetAppliedIndex(7)` in a tx that then errors | `AppliedIndex()` | `0` — the watermark rolls back with its mutation | INV-ATOMIC | **GAP** |
| WM-04 | meta value replaced with a 4-byte plaintext | `AppliedIndex()` | error `applied index is %d bytes, want 8` (`store.go:184-186`) | INV-IDEM | **GAP** |
| WM-05 | meta value replaced with non-ciphertext garbage | `AppliedIndex()` | error from the barrier, `idx == 0` | INV-IDEM | **GAP** — verified by probe: *"corrupt AppliedIndex = 0 err = barrier: open: cipher: message authentication failed"* |
| WM-06 | as WM-05 | construct `fsm.New(st)` | **must refuse to construct, or surface the error.** Today `fsm.go:29-31` discards it and the FSM starts with `applied = 0` | INV-IDEM, INV-NONCE-UNIQ | **GAP — live bug, see §9.1** |
| WM-07 | domain with one secret at version 3, watermark corrupted, node restarted | read the secret | version 3 | INV-IDEM | **GAP** — verified by probe: **version drifted to 6**, and the audit chain broke (`count 6 → 12`, `VerifyAuditChain` reported *"audit chain broken at entry 1 … numbered out of sequence"*) |
| WM-08 | node started, one secret written, node closed, reopened twice | read the secret | version stays 1 | INV-IDEM | **COVERED** — `fsm_test.go:37-89` |
| WM-09 | as WM-08 | session token from before the restart | still resolves | INV-IDEM | **COVERED** — `fsm_test.go:70-74` |
| WM-10 | as WM-08 | audit chain after two restarts | `VerifyAuditChain` returns no break and the count is unchanged | INV-ATOMIC | **GAP** — the drift guard is asserted on the secret version only; the audit chain is the more sensitive accumulator (a replay both duplicates the count and rewrites entries at the same `term:index:seq` key, `audit.go:104`) |
| WM-11 | node with `applied = 8`, then a committed entry arrives at index 8 | `Apply` | skipped, returns `op.Result{}` (`fsm.go:44-46`) | INV-IDEM | PARTIAL — exercised indirectly by WM-08, never asserted directly |
| WM-12 | node with `applied = 8`, entry arrives at index 9 with a **different** lineage (fresh Raft log) | `Apply` | must be refused, not applied | INV-LINEAGE | **GAP** |
| WM-13 | node with `applied = 8`, `raft.db` deleted, node restarted, a write proposed | `Propose` result | **write is silently dropped and reported as success.** `HasExistingState` is false (`node.go:93`), a fresh cluster bootstraps at index 1, `fsm.go:44-46` skips every entry ≤ 8, and `Propose` returns `res, res.Err` = `op.Result{}, nil` (`node.go:170-174`) | INV-LINEAGE | **GAP — live bug, see §9.1.** Verified by probe: `PutSecret after raft.db loss: version=0 err=<nil>`, then the read still returned `v1` |
| WM-14 | as WM-13, after ≥ 8 further writes | later writes | begin applying again — the loss window is bounded by the stale watermark, so the corruption is *partial*, which is worse than total | INV-LINEAGE | **GAP** |
| WM-15 | `Store.Update(9, 99, …)` called twice with different payloads | inspect both ciphertexts | identical nonces under the same barrier key. `Store.Update` is a public API with no guard against reusing a log position (`store.go:88-92`) | INV-NONCE-UNIQ | **GAP** — the existing tests do exactly this on purpose (`audit_test.go:98,147,183,231` all use `(9, 99)`), which shows the API offers no protection. See Q3 |
| WM-16 | 500 entries applied, node restarted 5× | secret version, audit count, principal count | all stable across every restart | INV-IDEM | **GAP** — WM-08 uses one secret and two restarts; a longer soak is what catches an off-by-one in the guard |

---

## 5. Snapshot and restore

`internal/store/snapshot.go` + `fsm.go:77-114`. **There is no `snapshot_test.go`.**

| ID | Precondition | Input | Expected result | Invariant | Coverage |
|---|---|---|---|---|---|
| SNP-01 | store with ≥ 1 value in **every** one of the 19 buckets | `SnapshotRaw()` → `RestoreRaw()` into a fresh store → read everything | byte-identical ciphertext and identical plaintext in all 19 buckets | INV-SNAP-FIDELITY | **GAP** — `apply_test.go:102-125` compares two snapshots for determinism but never restores one, and the fixture touches ~5 buckets |
| SNP-02 | as SNP-01 | `SnapshotRaw` twice with no writes between | identical maps | INV-SNAP-FIDELITY | **COVERED** — `apply_test.go:113-125` |
| SNP-03 | as SNP-01 | JSON-encode the snapshot twice (`fsm.go:107`) | identical bytes — required if E-03's SHA-256 manifest (`E-03:96-98`) is to mean anything | INV-SNAP-FIDELITY | **GAP** — verified by probe: bytes matched, because `encoding/json` sorts map keys. That is a property of the encoder, not of Signet; it deserves an explicit test so a future switch to a streaming or CBOR encoder cannot silently break the manifest |
| SNP-04 | store containing the watermark and audit meta | snapshot → restore → `AppliedIndex()` | equals the pre-snapshot value; `fsm.Restore` reloads it (`fsm.go:94-100`) | INV-IDEM | **GAP** |
| SNP-05 | store with a 200-entry audit chain | snapshot → restore → `VerifyAuditChain()` | chain verifies, head and count unchanged | INV-ATOMIC | **GAP** |
| SNP-06 | **non-empty** destination store with different data | `RestoreRaw(snapshot)` | destination holds exactly the snapshot; every pre-existing key in `allBuckets` is gone (`snapshot.go:42-47`) | INV-SNAP-FIDELITY | **GAP** — this is the "restore into a non-empty store" case and it is entirely untested |
| SNP-07 | destination store containing a bucket **not** in `allBuckets` | `RestoreRaw` | that bucket survives untouched — restore is not as destructive as its doc comment claims (`snapshot.go:37-39` says "replaces all state") | INV-SNAP-FIDELITY | **GAP** |
| SNP-08 | snapshot containing a bucket name **not** in `allBuckets` (e.g. taken by a newer binary) | `RestoreRaw` | **currently: silently dropped.** `snapshot.go:42` iterates `allBuckets`, not `data`. A downgrade restore loses data and reports success | INV-SNAP-FIDELITY | **GAP** — see Q4 |
| SNP-09 | snapshot with a bucket missing entirely | `RestoreRaw` | that bucket is created empty (`snapshot.go:48-51`) — including `meta`, which resets the watermark to 0 and re-arms WM-06/WM-13 | INV-IDEM | **GAP** |
| SNP-10 | snapshot from domain A | `fsm.Restore` into a node of domain B | **must refuse.** Today `fsm.go:85-102` decodes any JSON and restores it; nothing carries a domain identity or a barrier fingerprint, so the store becomes uniformly undecryptable and the node reports success | INV-LINEAGE | **GAP** — E-03 requires `meta.json` with a domain UUID and trust-chain fingerprint (`E-03:96,131`); the FSM snapshot format has neither |
| SNP-11 | snapshot truncated mid-JSON | `fsm.Restore` | error `fsm: decode snapshot: …` (`fsm.go:88-90`) and **the store is unchanged** — decode happens before `RestoreRaw`, so this holds today; assert it | INV-SNAP-FIDELITY | **GAP** |
| SNP-12 | snapshot whose JSON is valid but whose values are not barrier ciphertext | `fsm.Restore` | restore "succeeds"; every subsequent read fails. Decide whether restore must probe-decrypt a sentinel — see Q5 | INV-SNAP-FIDELITY | **GAP** |
| SNP-13 | snapshot JSON of 2 GiB | `fsm.Restore` | bounded memory, or a documented refusal. `json.NewDecoder(rc).Decode` into `map[string]map[string][]byte` (`fsm.go:87-90`) is unbounded, as is `SnapshotRaw` materialising the whole store in RAM (`snapshot.go:13-35`) — both are at odds with the Celeron-class target (`E-03:67`) | — | **GAP** |
| SNP-14 | `raft.SnapshotSink` that errors on `Write` | `snapshot.Persist` | `sink.Cancel()` is called and the error returned (`fsm.go:106-111`) | INV-SNAP-FIDELITY | **GAP** |
| SNP-15 | `sink.Close()` errors | `Persist` | error propagated, sink not left open | — | **GAP** |
| SNP-16 | `RestoreRaw` where `CreateBucket` fails part-way (simulate with a tiny page limit / injected error) | after the failed `Update` | bbolt rolls the whole thing back — the store is either fully old or fully new, never half-deleted | INV-ATOMIC | **GAP** |
| SNP-17 | node applying entries while `SnapshotRaw` runs | snapshot content | reflects a single consistent point (read tx, `snapshot.go:15`) — no torn cross-bucket state | INV-SNAP-FIDELITY | **GAP** |
| SNP-18 | restore, then Raft replays entries the snapshot already covers | those entries | skipped via the reloaded watermark (`fsm.go:94-100`) | INV-IDEM | **GAP** |

---

## 6. FSM and Node: bootstrap, election, propose

`internal/fsm/fsm.go`, `internal/fsm/node.go`.

| ID | Precondition | Input | Expected result | Invariant | Coverage |
|---|---|---|---|---|---|
| FSM-01 | fresh store | `New(st)` | `applied == 0` | INV-IDEM | **GAP** |
| FSM-02 | store with watermark 12 | `New(st)` | `applied == 12` | INV-IDEM | **GAP** |
| FSM-03 | log entry whose `Data` is not barrier ciphertext | `Apply` | `op.Result{Err: "fsm: decrypt entry N"}` (`fsm.go:47-50`), watermark unchanged, nothing written | INV-ATOMIC | **GAP** |
| FSM-04 | entry that decrypts but is not a valid `op` | `Apply` | `op.Result{Err: "fsm: decode entry N"}` (`fsm.go:51-54`), nothing written | INV-ATOMIC | **GAP** |
| FSM-05 | entry sealed under the wrong AAD (not `signet/op/v1`, `fsm.go:20`) | `Apply` | decrypt error | INV-AAD | **GAP** |
| FSM-06 | entry carrying an op the kernel rejects | `Apply` | `res.Err` set, **audit record still written**, watermark still advanced (`fsm.go:59-69`) | INV-ATOMIC | PARTIAL — `apply_test.go:276-308` covers "rejected ops write no state" but not "and still write their audit record and advance the watermark" |
| FSM-07 | `kernel.NewAuditRecord` errors | `Apply` | whole tx rolls back — no mutation without its audit record (`fsm.go:62-65`) | INV-ATOMIC | **GAP** |
| FSM-08 | `tx.AppendAudit` errors | `Apply` | whole tx rolls back | INV-ATOMIC | **GAP** |
| FSM-09 | applied entry N | `Apply(N)` again with *different* payload bytes | skipped (`fsm.go:44-46`); assert the store is untouched and no second nonce is burned at (term, N) | INV-NONCE-UNIQ | **GAP** |
| NODE-01 | empty data dir | `fsm.Open` then `WaitForLeader` | single-voter cluster bootstraps (`node.go:106-113`), node becomes leader | — | **COVERED** — `fsm_test.go:16-29` (helper used by both tests) |
| NODE-02 | existing data dir | `fsm.Open` | no re-bootstrap (`node.go:93-98`), leader again | — | **COVERED** — `fsm_test.go:68-71` |
| NODE-03 | data dir bootstrapped as `signet-a` | reopen with `NodeID: "signet-b"`, `WaitForLeader` | error naming the node and explaining the stored configuration (`node.go:137-143`) | — | **GAP** — verified by probe; the message fires correctly, but nothing asserts it, so a refactor could silently degrade it to a bare timeout |
| NODE-04 | as NODE-03 | reopen under the original name | leader again — the failure is recoverable exactly as the message says | — | **GAP** |
| NODE-05 | `cfg.NodeID == ""` | `fsm.Open` | defaults to `signet-0` (`node.go:47-49`); a domain created with the default and reopened with an explicit `signet-0` still works | — | **GAP** |
| NODE-06 | `cfg.Seal` names a missing file | `fsm.Open` | error from `seal.Open` before anything is created; **no partial data dir left behind** (`node.go:57-60` returns before `store.Open`) | INV-SEAL-CUSTODY | **GAP** |
| NODE-07 | `cfg.Seal == ""` | `fsm.Open` | error `seal: no seal configured` (`seal.go:68-70`) | INV-NO-FALLBACK | PARTIAL — `seal_test.go:129-135` covers `Open("")` at the seal level, not through `fsm.Open` |
| NODE-08 | data dir where `raft.db` is a directory | `fsm.Open` | error, and `st` is closed rather than leaked (`node.go:74-78`) | — | **GAP** |
| NODE-09 | `BootstrapCluster` fails | `fsm.Open` | error returned — **but `logs` and `st` are not closed** on this path (`node.go:110-112`), unlike every other error path | — | **GAP** (resource leak, low severity) |
| NODE-10 | leader node | `Propose(ctx, op)` | encrypts with `SealRandom` at propose time (`node.go:157`) so the Raft log holds ciphertext only (`docs/03:41-44`); assert `raft.db` on disk contains no plaintext op field name | INV-AAD | **GAP** — this is a headline claim of doc 03 with no test behind it |
| NODE-11 | leader node | `Propose` with an already-cancelled ctx | error, no partial state | — | **GAP** |
| NODE-12 | leader node | `Propose` with a ctx deadline 1 ms out | timeout error (`node.go:162-166`), not a hang | — | **GAP** |
| NODE-13 | non-leader node (renamed, NODE-03 state) | `Propose` | error, never a silent no-op | INV-LINEAGE | **GAP** |
| NODE-14 | FSM returns something other than `op.Result` | `Propose` | error `unexpected apply result %T` (`node.go:170-173`) | — | **GAP** |
| NODE-15 | running node | `Status()` | `Initialized=true`, `Sealed=false`, `Leader=true`, `SealName`/`SealKeyID` match the configured seal (`node.go:188-197`) | — | **GAP** |
| NODE-16 | node opened with a pkcs11 seal **[hsm]** | `Status()` | `SealName == "pkcs11"`, `SealKeyID == "<token>/<label>"` (`pkcs11.go:185-186`) | — | **GAP** |
| NODE-17 | running node | `Close()` | raft shut down, log store closed, store closed, **seal closed** (`node.go:199-210`); a second `Close` does not panic | — | **GAP** |
| NODE-18 | node closed | `Propose` | error, not a panic | — | **GAP** |

---

## 7. Seals

### 7.1 File seal, root key, envelopes (default build)

| ID | Precondition | Input | Expected result | Invariant | Coverage |
|---|---|---|---|---|---|
| SLF-01 | fresh key file | `Wrap` then `Unwrap` with the same AAD | round-trips; blob does not contain the plaintext | INV-SEAL-BIND | **COVERED** — `seal_test.go:23-40` |
| SLF-02 | as above | `Unwrap` with a different AAD | error | INV-SEAL-BIND | **COVERED** — `seal_test.go:44-53` |
| SLF-03 | two independent key files | seal A's blob into seal B | error naming the key IDs (`seal.go:162-164`) | INV-SEAL-BIND | **COVERED** — `seal_test.go:57-66` |
| SLF-04 | seal A's blob with `KeyID` blanked | `Unwrap` under seal B | error — the `KeyID != ""` shortcut (`seal.go:162`) must not become an authentication bypass; GCM still refuses | INV-SEAL-BIND | **GAP** |
| SLF-05 | valid blob | `Unwrap(nil, aad)` | error `seal: nothing to unwrap` (`seal.go:159-161`), not a panic | — | **GAP** |
| SLF-06 | valid blob | corrupt one byte of `b.CT`; `Unwrap` | error | INV-SEAL-BIND | **GAP** |
| SLF-07 | valid blob | corrupt one byte of `b.Nonce`; `Unwrap` | error | INV-SEAL-BIND | **GAP** |
| SLF-08 | valid blob | `b.Nonce = nil`; `Unwrap` | error, no panic (GCM rejects a wrong-size nonce) | — | **GAP** |
| SLF-09 | key file of 31 bytes | `OpenFile` | error naming the file and the byte count (`seal.go:119-121`) | INV-SEAL-CUSTODY | **GAP** |
| SLF-10 | key file absent | `OpenFile` | error `seal: read <path>: …` (`seal.go:116-118`) | INV-SEAL-CUSTODY | **GAP** |
| SLF-11 | key file is a directory | `OpenFile` | clean error | — | **GAP** |
| SLF-12 | key file of 32 zero bytes | `OpenFile` | currently accepted (only length is checked). Decide whether low-entropy material should be refused — Q1 | INV-SEAL-CUSTODY | **GAP** |
| SLF-13 | two `OpenFile` calls on the same file | compare `KeyID()` | identical and stable across processes (`seal.go:136-140`) | INV-ROT-IDENTITY | **GAP** |
| SLF-14 | two different key files | compare `KeyID()` | differ — "which seal is this" is answerable without opening anything | INV-ROT-IDENTITY | PARTIAL — implied by SLF-03's error |
| SLF-15 | existing key file | `GenerateKeyFile(path)` | error — refuses to clobber (`O_EXCL`, `seal.go:178-181`) | INV-SEAL-CUSTODY | **GAP** |
| SLF-16 | new path | `GenerateKeyFile` | file is mode `0600` and 32 bytes | INV-SEAL-CUSTODY | **GAP** |
| SLF-17 | `Open("file:///abs/path")` | — | opens `/abs/path` | — | PARTIAL — used everywhere in `fsm_test.go:18` |
| SLF-18 | `Open("file://relative/seal.key")` | — | opens `relative/seal.key`, not `/seal.key` (`seal.go:77-82`) | — | **GAP** — this was a real past bug (`main.go:973-976`) and has no regression test |
| SLF-19 | `Open("")`, `Open("wat://x")`, `Open("kms://nope")` | — | all error | INV-NO-FALLBACK | **COVERED** — `seal_test.go:129-135` |
| SLF-20 | `Open("file:")` (empty opaque and path) | — | clean error, not an open of `""` (`seal.go:80-83`) | — | **GAP** |
| SLF-21 | fresh dir | `LoadOrCreateRootKey` twice | same key both times; `root.seal` never contains the key in the clear | INV-SEAL-CUSTODY | **COVERED** — `seal_test.go:101-127` |
| SLF-22 | dir with a root key from seal A | `LoadOrCreateRootKey(sealB, dir)` | error `cannot unseal the root key — is this the right seal?` (`seal.go:204-207`) | INV-SEAL-CUSTODY | **COVERED** — `seal_test.go:124-126` |
| SLF-23 | dir where `root.seal` is not JSON | `LoadOrCreateRootKey` | error naming the path (`seal.go:200-203`) | — | **GAP** |
| SLF-24 | dir where `root.seal` is empty (0 bytes) | `LoadOrCreateRootKey` | error, **not** silent regeneration — an empty file is `os.ReadFile` success, so it falls into the JSON-unmarshal error at `seal.go:201`; assert it | INV-SEAL-CUSTODY | **GAP** |
| SLF-25 | dir where `root.seal` is **absent** but `state.db` exists and holds data | `LoadOrCreateRootKey` | **must refuse.** Today it mints a brand-new root key and writes it (`seal.go:213-228`), after which every stored value is undecryptable and the node still starts | INV-SEAL-CUSTODY | **GAP — live bug, see §9.3.** Verified by probe: *"node opened after root.seal was deleted"*, *"a fresh root.seal was written over the missing one"*, *"prior state is now unreadable: barrier: open: cipher: message authentication failed"* |
| SLF-26 | read-only data dir | `LoadOrCreateRootKey` on first use | error, and no half-written `root.seal` | INV-SEAL-CUSTODY | **GAP** |
| SLF-27 | `root.seal` mode | after creation | `0600` (`seal.go:225`) | INV-SEAL-CUSTODY | **GAP** |
| SLF-28 | any seal | `NewEnvelope` → `Open` with the same AAD | round-trips; neither `CT` nor `DEK.CT` contains the plaintext | INV-SEAL-BIND | **COVERED** — `seal_test.go:71-97` |
| SLF-29 | envelope from seal A | `Open` under seal B | error | INV-SEAL-BIND | **COVERED** — `seal_test.go:90-93` |
| SLF-30 | envelope under AAD X | `Open` under AAD Y | error | INV-SEAL-BIND | **COVERED** — `seal_test.go:94-96` |
| SLF-31 | `Envelope{DEK: nil}` and `(*Envelope)(nil)` | `Open` | error `seal: empty envelope` (`seal.go:278-280`), no panic | — | **GAP** |
| SLF-32 | valid envelope | corrupt `e.CT`; `Open` | error (`seal.go:298-301`) | INV-SEAL-BIND | **GAP** |
| SLF-33 | valid envelope | corrupt `e.DEK.CT`; `Open` | error at the unwrap step | INV-SEAL-BIND | **GAP** |
| SLF-34 | two `NewEnvelope` calls, same plaintext and AAD | compare | different DEKs, different ciphertexts (fresh DEK per envelope, `seal.go:247-250`) | INV-SEAL-BIND | **GAP** |
| SLF-35 | after `NewEnvelope` / `Envelope.Open` | inspect the DEK buffers | zeroed (`seal.go:269-272`, `seal.go:285-289`) | INV-HELD | **GAP** (hard to assert in Go; at minimum a review checklist item) |

### 7.2 Root-key rewrap

| ID | Precondition | Input | Expected result | Invariant | Coverage |
|---|---|---|---|---|---|
| REW-01 | `root.seal` wrapped by A | `RewrapRootKey(A, B, dir)` | `root.seal` now opens under B and yields the **same** root key; the barrier is untouched (`seal.go:305-310`) | INV-ROT-IDENTITY | **GAP** |
| REW-02 | as REW-01, after the rewrap | `LoadOrCreateRootKey(B, dir)` | same bytes as before the rewrap — the store still opens | INV-ROT-IDENTITY | **GAP** |
| REW-03 | as REW-01, after the rewrap | `LoadOrCreateRootKey(A, dir)` | error — A no longer opens `root.seal` | INV-SEAL-CUSTODY | **GAP** |
| REW-04 | already rewrapped to B | `RewrapRootKey(A, B, dir)` again | no-op success — the resume path (`seal.go:321-327`) | INV-ROT-IDENTITY | **GAP** |
| REW-05 | `root.seal` *claims* B but was wrapped by C | `RewrapRootKey(A, B, dir)` | error `root key claims the new seal but does not open under it` (`seal.go:322-326`) | INV-ROT-PROVEN | **GAP** |
| REW-06 | `root.seal` wrapped by C | `RewrapRootKey(A, B, dir)` | error `cannot unseal the root key with the current seal` (`seal.go:329-331`) | INV-SEAL-CUSTODY | **GAP** |
| REW-07 | `root.seal` absent | `RewrapRootKey` | error naming the path (`seal.go:313-315`) — **not** silent creation | INV-SEAL-CUSTODY | **GAP** |
| REW-08 | after a successful rewrap | list the data dir | `root.seal.prev` exists and **still opens under the old seal** (`seal.go:342-343`) | INV-SEAL-CUSTODY | **GAP — see §9.4.** Verified by probe: *"root.seal.prev + the old seal file still yield the barrier root key after rotation"*, and with the default seal location (`main.go:963-966`) the old `seal.key` is in the same directory |
| REW-09 | after a rewrap | `RootKeyWrappedBy(dir)` | `"<seal>/<keyid>"` of the destination, readable without either seal (`seal.go:352-364`) | INV-ROT-PROVEN | **GAP** |
| REW-10 | `root.seal` corrupt | `RootKeyWrappedBy` | error, not a partial string | — | **GAP** |
| REW-11 | crash simulated after `.prev` is written but before the rename | reopen with the old seal | domain still opens; re-running the ceremony completes it (`seal.go:341-349`) | INV-ROT-IDENTITY | **GAP** (needs the §8 harness) |
| REW-12 | crash simulated after the rename but before `fsync` of the directory | reopen | **undefined today.** `os.WriteFile` + `os.Rename` at `seal.go:342-349` never fsyncs the file or the parent directory; a crash can leave `root.seal` present-but-empty, which is unrecoverable | INV-SEAL-CUSTODY | **GAP — see §8.4 and Q6** |

### 7.3 PKCS#11 seal **[hsm]** — `make test-hsm`

| ID | Precondition | Input | Expected result | Invariant | Coverage |
|---|---|---|---|---|---|
| HSM-01 | SoftHSM token `signet`, AES key `signet-seal` | `Open(uri)`; `Name()`, `KeyID()` | `"pkcs11"`, `"signet/signet-seal"` (`pkcs11.go:185-186`) | — | **COVERED** — `pkcs11_test.go:36-40` |
| HSM-02 | as above | `Wrap`/`Unwrap` round trip | round-trips; the token returns no plaintext | INV-SEAL-BIND | **COVERED** — `pkcs11_test.go:36-56` |
| HSM-03 | as above | `Unwrap` under a different AAD | error | INV-SEAL-BIND | **COVERED** — `pkcs11_test.go:58-67` |
| HSM-04 | as above | envelope + root key round trip; file seal cannot open what the token wrapped | as asserted | INV-SEAL-CUSTODY | **COVERED** — `pkcs11_test.go:72-122` |
| HSM-05 | `module=` omitted, or `label=` omitted | `Open` | error `pkcs11 needs at least module= and label=` (`pkcs11.go:100-102`) | — | **GAP** |
| HSM-06 | `module=` points at a non-existent `.so` | `Open` | error `cannot load PKCS#11 module` (`pkcs11.go:69-72`) | INV-NO-FALLBACK | **GAP** under `-tags pkcs11` (see BLD-02) |
| HSM-07 | `module=` points at a file that is not a PKCS#11 provider | `Open` | error from `Initialize` (`pkcs11.go:73-76`), context destroyed, nothing cached | — | **GAP** |
| HSM-08 | correct module, wrong `pin=` | `Open` | error `pkcs11 login: … CKR_PIN_INCORRECT`; session closed and module released (`pkcs11.go:121-125`) | INV-NO-FALLBACK | **GAP** — verified by probe: `seal: pkcs11 login: pkcs11: 0xA0: CKR_PIN_INCORRECT` |
| HSM-09 | repeated wrong PIN | `Open` ×N | must not lock the token in a way the test suite depends on; document the SoftHSM/HSM difference | — | **GAP** |
| HSM-10 | unknown `token=` label | `Open` | error `no token labelled %q` (`pkcs11.go:158`) | — | **GAP** — verified by probe |
| HSM-11 | `token=` omitted | `Open` | first available slot is used (`pkcs11.go:154`); assert this is deliberate and documented | — | **GAP** |
| HSM-12 | `slot=` set to a non-numeric value | `Open` | error `slot=%q` (`pkcs11.go:139-142`) | — | **GAP** |
| HSM-13 | `slot=` set to a valid but wrong slot | `Open` | error from the key search, not a wrong-key success | INV-SEAL-BIND | **GAP** |
| HSM-14 | `label=` names no key in the token | `Open` | error `no secret key labelled %q` (`pkcs11.go:175-176`) | — | **GAP** — verified by probe |
| HSM-15 | two secret keys share `label=` | `Open` | error `%d keys labelled %q; the label must be unique` (`pkcs11.go:179-182`) — ambiguity would mean wrapping under an unknown key | INV-SEAL-BIND | **GAP** |
| HSM-16 | one seal already open on module M | open a **second** seal on the same module path string | succeeds; `C_Initialize` is refcounted (`pkcs11.go:52-79`). This is what rotation does | INV-ROT-IDENTITY | **GAP** — verified by probe: OK. The comment at `pkcs11.go:47-51` says this was a real bug; there is no test guarding the fix |
| HSM-17 | one seal open on `/path/lib.so` | open a second on a **symlink** to the same library | **fails with `CKR_CRYPTOKI_ALREADY_INITIALIZED`.** The cache is keyed by the raw string (`pkcs11.go:62-66`), not a canonical path | INV-ROT-IDENTITY | **GAP** — verified by probe: `seal: pkcs11 initialize: pkcs11: 0x191: CKR_CRYPTOKI_ALREADY_INITIALIZED`. See Q7 |
| HSM-18 | two seals on module M | close the first | the second still wraps/unwraps — `Finalize` only on the last release (`pkcs11.go:88-96`) | INV-ROT-IDENTITY | **GAP** |
| HSM-19 | one seal on module M | `Close()` twice | second is a no-op, refcount not double-decremented (`pkcs11.go:188-198`) | — | **GAP** |
| HSM-20 | seal closed | `Wrap` | error, not a nil-pointer panic — `p.ctx` is set to `nil` at `pkcs11.go:195` but `Wrap`/`Unwrap` (`pkcs11.go:207-244`) do not check it | — | **GAP** (suspected panic) |
| HSM-21 | two seals on module M, one logged in | opening the second | `CKR_USER_ALREADY_LOGGED_IN` treated as success (`pkcs11.go:118-126,200-203`) | INV-ROT-IDENTITY | **GAP** |
| HSM-22 | seal open, token removed / module made to fail mid-operation | `Wrap` | error surfaced to the caller; the node reports a seal failure rather than writing unsealed material | INV-SEAL-CUSTODY | **GAP** — requires a fault-injecting PKCS#11 shim (§8.5) |
| HSM-23 | blob wrapped by token/label X | `Unwrap` on a seal whose `KeyID()` is Y | **currently: the KeyID is ignored.** `PKCS11Seal.Unwrap` (`pkcs11.go:226-244`) has no equivalent of `FileSeal`'s check at `seal.go:162-164`; it fails only because the crypto fails, with a bare `CKR_*` | INV-SEAL-BIND | **GAP** — verified by probe: *"PKCS11Seal.Unwrap ignores Blob.KeyID and unwrapped a blob labelled for another key"* (label rewritten on a blob the same key had wrapped). See Q8 |
| HSM-24 | HSM-wrapped root key, token detached | `fsm.Open` | node **refuses to start** (`docs/11:154-156` claims this is verified) | INV-SEAL-CUSTODY | **GAP** at the unit level; only asserted prose |

### 7.4 Keys held in hardware **[hsm]**

| ID | Precondition | Input | Expected result | Invariant | Coverage |
|---|---|---|---|---|---|
| HLD-01 | signing seal | `GenerateSigner(label, AlgECDSAP256)` → `Signer` → `Sign` | signature verifies under the public key the token reported; `crypto/x509` can issue a self-signed cert with it | INV-HELD | **COVERED** — `pkcs11_signer_test.go:20-73` |
| HLD-02 | as above with `AlgRSA2048` | same | same, for all three digest prefixes (`pkcs11_signer.go:316-320`) | INV-HELD | **GAP** — only ECDSA is tested |
| HLD-03 | signing seal | `GenerateSigner(label, "Ed25519")` | error naming the supported algorithms (`pkcs11_signer.go:68-72`) | — | **GAP** |
| HLD-04 | generated key | read back `CKA_EXTRACTABLE` / `CKA_SENSITIVE` | `false` / `true`; generation refuses the key otherwise (`pkcs11_signer.go:89-123`) | INV-HELD | PARTIAL — `pkcs11_signer_test.go:20-31` exercises the happy path only; the **refusal** branch (`pkcs11_signer.go:106-120`) is never taken by any test |
| HLD-05 | a token that reports `CKA_EXTRACTABLE=true` | `GenerateSigner` | refused with the "defeats the reason for holding it in hardware" error | INV-HELD | **GAP** — needs a mock/shim token (§8.5); this is the single most security-relevant untested branch in the package |
| HLD-06 | a token whose `GetAttributeValue` errors on these attributes | `GenerateSigner` | **currently accepted** (`pkcs11_signer.go:98-102` returns `nil`). A token that reports `CKA_EXTRACTABLE=true` but errors on `CKA_SENSITIVE` therefore passes, because the two are fetched in one call | INV-HELD | **GAP** — see Q9 |
| HLD-07 | key generated | `pkcs11-tool --read-object --type privkey --label …` | refused by the token (`docs/11:219-222`) | INV-HELD | **GAP** at the automated level (asserted only in prose) |
| HLD-08 | key generated | grep `state.db`, `raft.db`, and the data dir for PEM markers | none present | INV-HELD | **GAP** |
| HLD-09 | `KeyRef` naming a label the token does not hold | `Signer(ref)` | error explaining that the reference points at a missing key (`pkcs11_signer.go:141-151`) | INV-HELD | **COVERED** — `pkcs11_signer_test.go:76-82` |
| HLD-10 | two private keys sharing a label | `Signer(ref)` with no `ID` | error `holds %d keys labelled %q` (`pkcs11_signer.go:154-157`) | INV-HELD | **GAP** |
| HLD-11 | `KeyRef{Seal: "file"}` | `Signer(ref)` on a pkcs11 seal | error `key reference names the %q seal` (`pkcs11_signer.go:167-171`) | INV-HELD | **GAP** |
| HLD-12 | `Signer(nil)` | — | error, no panic (`pkcs11_signer.go:164-166`) | — | **GAP** |
| HLD-13 | ECDSA signer | `Sign(_, digest, nil)` | error naming the missing `SignerOpts` (`pkcs11_signer.go:259-264`) | — | **COVERED** — `pkcs11_signer_test.go:86-101` |
| HLD-14 | ECDSA signer | `Sign(_, []byte{}, crypto.SHA256)` | error `asked to sign an empty digest` (`pkcs11_signer.go:265-267`) | — | **GAP** |
| HLD-15 | ECDSA signer | `Sign(_, digest, crypto.SHA512)` | error `this key signs SHA-256 digests` (`pkcs11_signer.go:273-275`) | — | **GAP** |
| HLD-16 | RSA signer | `Sign` with `crypto.MD5` | error `cannot sign %s digests` (`pkcs11_signer.go:296-299`) | — | **GAP** |
| HLD-17 | ECDSA signer | a token returning an odd-length signature | error `not a valid r||s pair` (`pkcs11_signer.go:286-288`) | — | **GAP** (needs a shim) |
| HLD-18 | ECDSA public point returned raw vs DER-`OCTET STRING`-wrapped | `readPublic` | both decode to the same point (`pkcs11_signer.go:202-204`) | INV-HELD | **GAP** — vendor-variance code with no test |
| HLD-19 | key generated | `DeleteSigner(ref)` then `Signer(ref)` | delete removes both halves (`pkcs11_signer.go:230-243`); the signer lookup then errors | INV-HELD | PARTIAL — used as cleanup in `pkcs11_signer_test.go:31,93`, never asserted |
| HLD-20 | `DeleteSigner` on an absent ref | — | no error — deletion is idempotent (`pkcs11_signer.go:236-238`) | — | **GAP** |
| HLD-21 | file seal | `AsSigningSeal(f)` | error explaining a file seal wraps but cannot hold (`signer.go:55-63`) | INV-HELD | **COVERED** — `pkcs11_signer_test.go:105-117` (but note: this file is `//go:build pkcs11`, so the assertion only runs in the HSM build — see BLD-05) |
| HLD-22 | `(*KeyRef)(nil)` | `String()` | `"<none>"` (`signer.go:27-32`) | — | **GAP** |
| HLD-23 | many concurrent `Sign` calls on one seal | — | serialized by `p.mu` (`pkcs11_signer.go:268-269`, `pkcs11.go:38`); no interleaved `SignInit`/`Sign` corruption. Run under `-race` | INV-HELD | **GAP** — the single mutex around a single session is the correctness argument for the whole package and nothing exercises it |

### 7.5 Build-tag gating

| ID | Build | Input | Expected result | Invariant | Coverage |
|---|---|---|---|---|---|
| BLD-01 | **[default-build]** | `seal.Open("pkcs11:?module=…&label=…")` | error whose text names the missing `-tags pkcs11` and the cgo reason (`pkcs11_disabled.go:20-24`) | INV-NO-FALLBACK | PARTIAL — `seal_test.go:140-145` asserts only `err != nil` |
| BLD-02 | **[hsm]** | the *same call* under `-tags pkcs11` | also errors, but for a different reason (module not found). `seal_test.go:140-145` has **no build tag**, so under `make test-hsm` it passes for the wrong reason and would not notice if the refusal message were deleted | INV-NO-FALLBACK | **GAP** — split the test: assert the message text under `!pkcs11`, assert `CKR`/module-load failure under `pkcs11` |
| BLD-03 | **[default-build]** | `fsm.Open(Config{Seal: "pkcs11:…"})` | node refuses to start; **no data dir is created and no root key is minted** (`node.go:53-60` runs `MkdirAll` *before* `seal.Open`, so the directory *is* created — assert the store and root key are not) | INV-NO-FALLBACK | **GAP** |
| BLD-04 | **[default-build]** | `signet genesis -seal 'pkcs11:…'` | exits non-zero with the rebuild instruction; no partial domain left behind | INV-NO-FALLBACK | **GAP** |
| BLD-05 | **[default-build]** | `seal.AsSigningSeal(fileSeal)` | error | INV-HELD | **GAP** — the only assertion lives in `pkcs11_signer_test.go:105-117`, which is `//go:build pkcs11`, so the default build never checks it |
| BLD-06 | both builds | `PKCS11Config` struct shape | identical fields in `pkcs11.go:29-35` and `pkcs11_disabled.go:9-15`; a compile-time assertion or a shared type would keep them from drifting | — | **GAP** |

---

## 8. Durability and crash safety

This is the thinnest area today: **no test in the repository kills a process, and
no test injects an I/O fault.** Everything below is a GAP. Each row states the
invariant a crash must not break, and what the harness has to do.

### 8.1 Required harness

Two mechanisms are needed and neither exists:

1. **Crash points.** A build-tagged (`//go:build crashtest`) hook —
   `crash.Point("after-raft-commit")` — that a child process turns into an
   immediate `os.Exit(2)` when the named point is armed by an environment
   variable. The parent test spawns the child, arms one point, waits for it to
   die, then reopens the data dir in-process and asserts. This keeps the
   production build free of test scaffolding while making the "process dies
   between X and Y" cases real rather than simulated.
2. **A fault-injecting PKCS#11 shim.** A `Seal`/`SigningSeal` wrapper that can be
   told to fail the Nth `Wrap`, `Unwrap`, `Sign`, or `GetAttributeValue`, and a
   fake token that lies about `CKA_EXTRACTABLE`. Needed for HSM-22, HLD-05,
   HLD-06, HLD-17.

### 8.2 Crash between the Raft commit and the bbolt commit

| ID | Crash point | Expected on restart | Invariant |
|---|---|---|---|
| CRS-01 | after `raft.Apply` returns committed, before `FSM.Apply` runs | entry is replayed and applied exactly once; watermark ends at that index | INV-IDEM |
| CRS-02 | inside the store `Update` closure, after `kernel.Apply` mutated the tx but before `SetAppliedIndex` (`fsm.go:61-69`) | bbolt rolls the whole tx back; the entry replays cleanly; **the same (term,index,seq) nonces are reused for the same plaintexts**, which is safe precisely because the rollback means the first attempt left nothing behind | INV-ATOMIC, INV-NONCE-UNIQ |
| CRS-03 | after `SetAppliedIndex` inside the tx, before bbolt's fsync | either the whole entry is durable or none of it is; never the mutation without the watermark | INV-ATOMIC |
| CRS-04 | after the bbolt commit, before `f.applied.Store` (`fsm.go:73`) | irrelevant in-process, but assert: the durable watermark is the authority, and `fsm.New` must read it (see WM-06) | INV-IDEM |
| CRS-05 | between the mutation tx and the *next* entry, repeated 50× at random points | audit chain verifies, secret versions match the number of distinct committed writes, no bucket holds an unopenable value | INV-IDEM, INV-ATOMIC |
| CRS-06 | `kill -9` during a burst of 200 proposals, then restart and diff against a reference domain fed the same ops without crashing | identical `SnapshotRaw()` output modulo the trailing uncommitted entries | INV-SNAP-FIDELITY |

### 8.3 Crash during a snapshot

| ID | Crash point | Expected on restart | Invariant |
|---|---|---|---|
| CRS-07 | inside `snapshot.Persist` after partial `Write` (`fsm.go:106-111`) | the partial snapshot is discarded (`sink.Cancel`), Raft falls back to the previous snapshot + log, and state is unchanged | INV-SNAP-FIDELITY |
| CRS-08 | after `sink.Close()` but before Raft records the new snapshot | the snapshot is either used whole or ignored; never half-adopted | INV-SNAP-FIDELITY |
| CRS-09 | during `FSM.Restore`'s `RestoreRaw` (`fsm.go:91`) | bbolt rolls back — the store is fully old or fully new, never with buckets deleted and not recreated (`snapshot.go:41-58`) | INV-ATOMIC |
| CRS-10 | after `RestoreRaw` but before `f.applied.Store` (`fsm.go:96-100`) | the watermark is read from the store on next open, so this must be a no-op — **conditional on WM-06 being fixed** | INV-IDEM |
| CRS-11 | disk full during `RestoreRaw` | clean error, store unchanged, node refuses to serve rather than serving a half-restored domain | INV-ATOMIC |

### 8.4 Crash during seal rotation and rewrap

The ceremony order is **material first, root key last** (`main.go:766-772`,
`docs/11:178-184`). These tests are what make that claim true rather than
aspirational.

| ID | Crash point | Expected on restart | Invariant |
|---|---|---|---|
| CRS-12 | after `RotateSeal` rewrapped item 2 of 5 (`sealrotate.go:87-102`) | domain still opens with the **old** seal; `seal status` shows a mixed inventory and warns (`main.go:758-762`); re-running with the same destination completes it | INV-ROT-IDENTITY |
| CRS-13 | after all material moved, before `RewrapRootKey` (`main.go:823-827`) | domain still opens with the old seal (the root key has not moved); re-run completes | INV-ROT-IDENTITY |
| CRS-14 | inside `RewrapRootKey` after `.prev` is written, before `.new` (`seal.go:342-346`) | `root.seal` untouched; old seal still opens; re-run completes | INV-ROT-IDENTITY |
| CRS-15 | after `.new` is written, before the rename (`seal.go:347-349`) | `root.seal` still the old form; re-run completes; the stale `.new` is either overwritten or cleaned | INV-ROT-IDENTITY |
| CRS-16 | immediately after the rename, with the page cache lost | **currently undefined.** No `fsync` on the file or on the parent directory (`seal.go:342-349`); the rename can be durable while the content is not, leaving a zero-length `root.seal` and an unrecoverable domain. Expected behaviour: content fsynced before rename, directory fsynced after | INV-SEAL-CUSTODY |
| CRS-17 | during the initial `LoadOrCreateRootKey` write (`seal.go:225`) | same fsync requirement: a torn first write plus a populated `state.db` is unrecoverable | INV-SEAL-CUSTODY |
| CRS-18 | during `GenerateKeyFile` (`seal.go:178-184`) | either a full 32-byte key file or none; a short file is caught by `OpenFile`'s length check (`seal.go:119-121`), which is the saving grace — assert it | INV-SEAL-CUSTODY |
| CRS-19 | between `RotateSeal` completing and `VerifySealedMaterial` (`main.go:834-841`) | re-running the ceremony re-verifies without moving anything; the operator is never told "complete" without a proof | INV-ROT-PROVEN |
| CRS-20 | mid-`rewrapKey`: the `PutKey` proposal committed but the process died before the next item (`sealrotate.go:130-134`) | that key is under the new seal, the rest under the old; `SealInventory` reports both | INV-ROT-IDENTITY |
| CRS-21 | mid-`rewrapKey`: envelope built under `to` but the proposal never committed | the key remains readable under `from`; the new envelope is discarded — no key is left wrapped by a seal the store does not record | INV-ROT-IDENTITY |

### 8.5 Storage-level fault injection

| ID | Fault | Expected | Invariant |
|---|---|---|---|
| CRS-22 | `state.db` truncated to a page boundary mid-file | `Open` errors; node refuses to start | INV-SNAP-FIDELITY |
| CRS-23 | one page of `state.db` zeroed | reads of affected keys error; reads of others succeed; `VerifyAuditChain` reports a break rather than silently shortening | INV-ATOMIC |
| CRS-24 | `raft.db` truncated | `NewBoltStore` errors and `st` is closed (`node.go:74-78`); the node does **not** proceed to bootstrap a fresh cluster over live state | INV-LINEAGE |
| CRS-25 | `raft.db` deleted, `state.db` intact | node must refuse to start, or recover with the correct index — see WM-13 and §9.1 | INV-LINEAGE |
| CRS-26 | disk full during a store `Update` | error returned, tx rolled back, node stays consistent | INV-ATOMIC |
| CRS-27 | data dir on a filesystem without `flock` (NFS) | `bolt.Open` fails or misbehaves; the node must say so plainly, since "data dir on local disk always" is a stated rule (`docs/11:49`, `E-03:59-60`) | — |

---

## 9. Suspected live bugs

All four were reproduced against the tree as it stands, in a local-disk mirror,
using the packages' own APIs. None is caught by `make test` today.

### 9.1 A stale applied-index watermark turns writes into silent no-ops — and a lost one replays the whole log

**Two failure modes of the same missing invariant (INV-LINEAGE): nothing ties the
watermark to the log that produced it.**

*(a) Watermark unreadable → full replay.* `fsm.New` discards the error from
`store.AppliedIndex()`:

```go
// internal/fsm/fsm.go:27-33
func New(st *store.Store) *FSM {
	f := &FSM{st: st}
	if i, err := st.AppliedIndex(); err == nil {
		f.applied.Store(i)
	}
	return f
}
```

`AppliedIndex` returns a non-nil error whenever the meta record fails to decrypt
or is the wrong length (`store.go:180-187`). The FSM then starts at `applied = 0`
and Raft replays every committed entry over its own results. Reproduced: a domain
with a secret at version 3 came back at **version 6**; the audit count went
**6 → 12**; and `VerifyAuditChain` reported *"audit chain broken at entry 1 …
numbered out of sequence"*. That is the exact bug `fsm_test.go:31-36` was written
to prevent, re-armed by a single unreadable byte.

It is worse than version drift. Replaying entry *(term, index)* re-derives the
**same nonce** (`barrier.go:60-62,84-93`) while the plaintext differs (the audit
entry's `Prev`/`Hash` have changed, `audit.go:97-99`). Same AES-GCM key, same
nonce, two plaintexts: the XOR of the plaintexts and the GHASH authentication key
both become recoverable. **The applied-index watermark is not only an idempotence
guard — it is the nonce-uniqueness guard for the entire barrier, and nothing in
the source says so.**

*Fix direction:* `fsm.New` must return an error (or panic at startup) rather than
defaulting to 0; and `Store.Update` should refuse a `(term, index)` at or below
the persisted watermark, so the invariant is enforced where the nonce is derived
rather than one layer up.

*(b) Log lost, state kept → acknowledged writes vanish.* If `raft.db` is absent
while `state.db` survives, `raft.HasExistingState` is false (`node.go:93`), so
`Node.Open` bootstraps a **fresh single-voter cluster starting at index 1**
(`node.go:106-113`). Every new entry is now at an index at or below the persisted
watermark, so `Apply` skips it and returns an empty result (`fsm.go:44-46`), and
`Propose` hands that back as success (`node.go:170-174`). Reproduced:

```
PutSecret after raft.db loss: version=0 err=<nil>
read back: version=1 data=map[k:v1]
```

The write was acknowledged, never applied, and reported no error. The window is
bounded by the stale watermark, so after N further writes the domain starts
working again — a *partial* silent loss, which is harder to notice than a total
one. This is reachable from ordinary operations: a corrupted or hand-deleted
Raft log, and, importantly, **the restore flow E-03 specifies** — "materialize
`state.db` from snapshot → replay segments → write a fresh single-voter Raft
config at the restored index" (`E-03:130`, `docs/03:61-65`). If that fresh config
does not start above the restored index, this is precisely the bug.

*Fix direction:* `Node.Open` must refuse to bootstrap over a store with a
non-zero applied index, or use `raft.RecoverCluster` at the restored index; and
`Propose` must not report success for an entry the FSM skipped.

### 9.2 `store.Open` accepts a root key that cannot decrypt the store, and then overwrites it

`store.Open` (`store.go:58-79`) derives a barrier and creates buckets without ever
checking that the key opens anything already present. Reproduced: opening a store
written under key A with key B succeeded; `AppliedIndex()` returned
`0, barrier: open: cipher: message authentication failed`; a subsequent `Put`
succeeded and **destroyed the original value**, which the correct key could no
longer read. Combined with §9.1(a) — the watermark read fails, so the FSM starts
at 0 and replays — a wrong root key produces a node that starts, elects itself,
looks empty, and writes over everything.

*Fix direction:* on `Open`, write a sentinel value under a known meta key at
creation and require it to decrypt on every subsequent open; refuse otherwise.

### 9.3 A missing `root.seal` is silently replaced with a new root key

`LoadOrCreateRootKey` treats "file does not exist" as first use
(`seal.go:199-211` → `213-228`) with no reference to whether a store already
exists. Reproduced: deleting `root.seal` from a populated data dir let the node
start normally, wrote a **fresh** `root.seal`, and left the prior state
permanently unreadable (*"barrier: open: cipher: message authentication
failed"*). No error, no warning, and — because `fsm.New` swallows the watermark
error — no crash either.

*Fix direction:* refuse to create a root key when `state.db` exists and is
non-empty; say plainly that the seal or the wrapped root key has been lost.

### 9.4 Rotation leaves both halves of the old custody chain in the data directory

`RewrapRootKey` keeps the previous wrapped form as `root.seal.prev`
(`seal.go:341-343`) and never removes it. The default seal path is
`DATA-DIR/seal.key` (`main.go:963-966`). So after the flagship ceremony —
`signet seal rotate` from the default file seal to an HSM — the data directory
still contains **`seal.key`** *and* **`root.seal.prev`**, and the two together
yield the barrier root key. Reproduced: *"root.seal.prev + the old seal file
still yield the barrier root key after rotation"*.

That directly contradicts `docs/11:152-156` ("A data directory therefore cannot be
opened by anything but the seal that created it") and undercuts the CLI's closing
promise that the old seal is no longer needed (`main.go:844-847`). It is not a
break of INV-ROT-IDENTITY — the root key legitimately does not change — but it
means the *stated* attack-surface reduction does not happen unless the operator
knows to delete two files nobody told them about.

*Fix direction:* have the ceremony print exactly which files still hold old
custody and offer to remove them once verification passes; or write `.prev`
outside the data directory.

### 9.5 A PKCS#11 successor key with the same label is invisible to rotation

`PKCS11Seal.KeyID()` is `token + "/" + label` (`pkcs11.go:186`). If an operator
performs the documented "one HSM key to its successor" rotation
(`sealrotate.go:16-17`, `docs/11:167-168`) by replacing the wrapping key **in
place under the same label** — the obvious way to do it — the new seal reports an
identical `KeyID`. Reproduced with SoftHSM:

```
old KeyID = "signet/signet-seal", successor KeyID = "signet/signet-seal"
PROBE CONFIRMED: RotateSeal would treat this item as 'already moved by an earlier run' and skip it
...while the successor cannot actually open it: CKR_ENCRYPTED_DATA_INVALID
root.seal no longer opens: CKR_ENCRYPTED_DATA_INVALID
```

Consequences, in order of severity:

- `SealInventory` reports every item as already under the destination, so
  `signet seal status` shows a **clean, complete** rotation and prints no mixed-state
  warning (`main.go:749-762`) while the material is still wrapped by a key that no
  longer exists.
- `RotateSeal` skips every item (`sealrotate.go:88-90`) and reports "all material
  was already under the destination seal" (`main.go:820-822`).
- The ceremony does then abort at `RewrapRootKey`, which takes its
  "already moved" branch and fails the confirming unwrap (`seal.go:321-327`) — so
  the *full* ceremony is not silently successful. But an operator who ran
  `seal status` first, saw a clean result, and destroyed the old key has already
  lost the domain.

Related: `PKCS11Seal.Unwrap` never checks `Blob.KeyID` at all
(`pkcs11.go:226-244`), unlike `FileSeal.Unwrap` (`seal.go:162-164`), so the
mismatch surfaces as a bare `CKR_ENCRYPTED_DATA_INVALID` instead of "this blob
was wrapped by a different key".

*Fix direction:* derive the PKCS#11 `KeyID` from something that changes with the
key — `CKA_ID`, or a hash of a fixed test-vector wrap — and add the `FileSeal`
KeyID check to `PKCS11Seal.Unwrap`.

### 9.6 Lower-severity

- **`Tx.Get`/`Put`/`Delete`/`ScanPrefix` panic on an unknown bucket name**
  (`store.go:117,121,136,142` dereference the `nil` from `tx.Bucket`). Reproduced.
  A typo'd bucket constant, or a `RestoreRaw` that failed to recreate a bucket,
  becomes a crash rather than an error.
- **`RestoreRaw` silently drops buckets it does not know** (`snapshot.go:42`
  iterates `allBuckets`, not `data`) — a downgrade restore loses data and reports
  success.
- **`Node.Open` leaks `logs` and `st` when `BootstrapCluster` fails**
  (`node.go:110-112`).
- **`PKCS11Seal.Wrap`/`Unwrap` do not check for a closed context**
  (`pkcs11.go:207,226` vs the `p.ctx = nil` at `:195`) — likely a nil-pointer
  panic on use-after-close.
- **`assertNonExtractable` accepts any token whose `GetAttributeValue` errors**
  (`pkcs11_signer.go:98-102`); because both attributes are fetched in one call, a
  token can be `EXTRACTABLE` and still pass.
- **The aliased-module-path `C_Initialize` failure** (HSM-17) — the refcount cache
  is keyed by the raw `module=` string (`pkcs11.go:62-66`).

---

## 10. Coverage summary

| Section | Scenarios | Covered | Partial | Gap |
|---|---:|---:|---:|---:|
| 2 — Barrier (BAR-01…20) | 20 | 0 | 1 | 19 |
| 3 — Store (STO-01…24) | 24 | 0 | 7 | 17 |
| 4 — Watermark / idempotence (WM-01…16) | 16 | 2 | 1 | 13 |
| 5 — Snapshot / restore (SNP-01…18) | 18 | 1 | 0 | 17 |
| 6 — FSM / Node (FSM-01…09, NODE-01…18) | 27 | 2 | 2 | 23 |
| 7.1 — File seal / root key / envelope (SLF-01…35) | 35 | 9 | 2 | 24 |
| 7.2 — Root-key rewrap (REW-01…12) | 12 | 0 | 0 | 12 |
| 7.3 — PKCS#11 seal **[hsm]** (HSM-01…24) | 24 | 4 | 0 | 20 |
| 7.4 — Hardware-held keys **[hsm]** (HLD-01…23) | 23 | 4 | 2 | 17 |
| 7.5 — Build-tag gating (BLD-01…06) | 6 | 0 | 1 | 5 |
| 8 — Durability / crash safety (CRS-01…27) | 27 | 0 | 0 | 27 |
| 11 — Seal rotation (ROT-01…22) | 22 | 6 | 2 | 14 |
| **Total** | **254** | **28** | **18** | **208** |

Covered = an existing test asserts the stated expectation. Partial = an existing
test exercises the code path but does not assert the stated property, or asserts
it only incidentally.

---

## 11. Seal rotation (kernel) — detail

`internal/kernel/sealrotate.go` + the ceremony in `cmd/signet/main.go:766-848`.

| ID | Precondition | Input | Expected result | Invariant | Coverage |
|---|---|---|---|---|---|
| ROT-01 | domain with 2 signing keys + 1 CA under seal A | `SealInventory` | 3 items, sorted by (kind, name), each `SealedBy == "file/<A>"` (`sealrotate.go:40-71`) | INV-ROT-PROVEN | PARTIAL — `sealrotate_test.go:66-68` asserts the count via `RotateSeal` |
| ROT-02 | domain where `BucketKeys` also holds active-key pointers | `SealInventory` | pointers skipped, not reported as unsealed material (`sealrotate.go:45-48`) | — | **GAP** |
| ROT-03 | domain with unparseable JSON in `BucketKeys` | `SealInventory` | that record is skipped silently (`sealrotate.go:49`) — decide whether silence is right, or whether an unreadable key record must be surfaced (Q10) | INV-ROT-PROVEN | **GAP** |
| ROT-04 | as ROT-01 | `RotateSeal(A, B)` | all 3 moved; key IDs, `kid`, and public halves unchanged | INV-ROT-IDENTITY | **COVERED** — `sealrotate_test.go:52-94` |
| ROT-05 | after ROT-04 | `VerifySealedMaterial(B)` | nil | INV-ROT-PROVEN | **COVERED** — `sealrotate_test.go:91-93` |
| ROT-06 | after ROT-04 | `VerifySealedMaterial(A)` | error | INV-SEAL-CUSTODY | **COVERED** — `sealrotate_test.go:98-108` |
| ROT-07 | after ROT-04 | `VerifySealedMaterial(C)` — a third, correctly-shaped seal | error; verification opens rather than trusting labels | INV-ROT-PROVEN | **COVERED** — `sealrotate_test.go:158-169` |
| ROT-08 | after ROT-04 | `RotateSeal(B, B)` | 0 items moved, no error | INV-ROT-IDENTITY | **COVERED** — `sealrotate_test.go:112-130` |
| ROT-09 | exactly one item moved | `SealInventory` | ≥ 2 distinct `SealedBy` values | INV-ROT-PROVEN | **COVERED** — `sealrotate_test.go:134-154` |
| ROT-10 | after ROT-04 | a token issued **before** the rotation | still verifies against the JWKS afterwards | INV-ROT-IDENTITY | PARTIAL — `sealrotate_test.go:83-90` compares JWK fields, not an actual issued token |
| ROT-11 | after ROT-04 | a certificate issued before the rotation | still chains to the unchanged CA | INV-ROT-IDENTITY | **GAP** — `docs/11:174-176` claims this is verified end to end; no test asserts it |
| ROT-12 | rotation where `rewrapKey` fails on item 2 | `RotateSeal` return | returns the items moved so far **and** the error (`sealrotate.go:93-99`); the domain is left in a resumable mixed state | INV-ROT-IDENTITY | **GAP** |
| ROT-13 | rotation where the destination seal cannot wrap (injected failure) | `RotateSeal` | error before any proposal is made for that item; nothing recorded as moved that was not | INV-ROT-PROVEN | **GAP** (needs the §8.5 shim) |
| ROT-14 | file seal → **HSM** **[hsm]** | full `signet seal rotate` | material and root key both under the token; domain opens with the token alone; `kid` and CA fingerprint unchanged | INV-ROT-IDENTITY | **GAP** — the entire cross-backend rotation, which is the feature's headline use case, is tested only file→file |
| ROT-15 | HSM → **successor HSM key, new label** **[hsm]** | full ceremony | completes and verifies | INV-ROT-IDENTITY | **GAP** |
| ROT-16 | HSM → **successor HSM key, same label** **[hsm]** | `SealInventory`, then the full ceremony | inventory must **not** report the material as already migrated | INV-ROT-PROVEN | **GAP — see §9.5**, reproduced |
| ROT-17 | HSM → file seal (a downgrade) | full ceremony | either completes with an explicit warning that custody weakened, or is refused. Currently it silently succeeds | INV-SEAL-CUSTODY | **GAP** — Q11 |
| ROT-18 | rotation with `-to` equal to the current seal URI | `sealRotate` | error `source and destination are the same seal` (`main.go:774-776`) | — | **GAP** |
| ROT-19 | rotation where the actor path names no principal | `sealRotate` | error before anything moves (`main.go:807-811`) | — | **GAP** |
| ROT-20 | rotation on a domain with 0 sealed items | full ceremony | root key still rewraps; the command reports "all material was already under the destination seal" without implying material existed | INV-ROT-IDENTITY | **GAP** |
| ROT-21 | after a completed rotation | audit log | a record exists for each `PutKey`/`PutCA` the rotation proposed (`sealrotate.go:130-134,159-162`), attributed to the actor | INV-ATOMIC | **GAP** |
| ROT-22 | rotation of a domain whose CA key is **held** (`-ca-in-hardware`) rather than wrapped **[hsm]** | `SealInventory` / `RotateSeal` | a `KeyRef` has nothing to rewrap; rotation must skip it and say so, not fail or silently claim to have moved it | INV-HELD | **GAP** — `ca.Material.SealedBy()`/`Rewrap` behaviour for reference-held CAs is unspecified; Q12 |

---

## 12. Questions for the maintainer

1. **Barrier/seal input validation.** Should `NewBarrier` refuse an empty or
   short root key (`barrier.go:29-31`), and should `OpenFile` do more than check
   length ≥ 32 (`seal.go:119-121`)? Today 32 zero bytes is an acceptable seal key.
   What is the intended contract — "callers supply high-entropy material" or
   "the seal validates"?

2. **Unknown bucket names.** Is `Tx.Get("typo", k)` panicking (`store.go:121`)
   acceptable-by-design (a programming error should crash) or should the `Tx`
   methods return an error? It matters because `RestoreRaw` can leave a bucket
   absent (SNP-09) and because the panic is reachable from a data condition, not
   only from a code bug.

3. **Should `Store.Update` enforce the watermark?** `Update(term, index, …)`
   (`store.go:88-92`) is public, takes an arbitrary log position, and derives all
   nonces from it. Moving the "index must exceed the persisted watermark" check
   from `fsm.Apply` into `Store.Update` would make nonce uniqueness a property of
   the storage layer rather than of one caller's discipline. Is there a reason it
   lives in the FSM?

4. **Forward-compatible restore.** Should `RestoreRaw` restore buckets present in
   the snapshot but absent from `allBuckets` (`snapshot.go:42`), or refuse the
   snapshot outright as "written by a newer version"? Silently dropping them is
   the one behaviour that loses data without telling anyone.

5. **Snapshot provenance.** E-03 specifies `meta.json` carrying a domain UUID,
   trust-chain fingerprint, term/index, and key epochs (`E-03:96,131`). The FSM
   snapshot (`fsm.go:104-112`) carries none of it. Is the intent that the backup
   layer wraps the FSM snapshot with that metadata, or should `FSM.Snapshot`
   itself embed a domain identity so `Restore` can refuse a foreign snapshot
   (SNP-10)?

6. **Durability of the seal files.** `LoadOrCreateRootKey` and `RewrapRootKey`
   write `root.seal` with `os.WriteFile` and no `fsync` of the file or the parent
   directory (`seal.go:225,342-349`). Is a torn `root.seal` an accepted risk
   (mitigated by `.prev` and by backups), or should these become
   write-temp → fsync → rename → fsync-dir?

7. **PKCS#11 module identity.** Should `acquireModule` canonicalise the path
   (`filepath.EvalSymlinks`) before using it as the refcount key
   (`pkcs11.go:62-66`)? Two seals reaching the same library by different path
   strings currently fail with `CKR_CRYPTOKI_ALREADY_INITIALIZED` — the exact
   condition the refcount exists to prevent.

8. **`PKCS11Seal.Unwrap` and `Blob.KeyID`.** `FileSeal` refuses a blob wrapped by
   a different key with a clear message (`seal.go:162-164`); the PKCS#11 seal does
   not check at all (`pkcs11.go:226-244`). Deliberate, or an oversight?

9. **Non-extractability read-back.** `assertNonExtractable` returns success when
   `GetAttributeValue` errors (`pkcs11_signer.go:98-102`), and fetches both
   attributes in one call, so a single failure hides both. Should the two be
   fetched separately, and should a token that refuses to report `CKA_EXTRACTABLE`
   specifically be rejected?

10. **Unreadable records in `SealInventory`.** A `BucketKeys` value that does not
    unmarshal is skipped silently (`sealrotate.go:49-51`). Should rotation refuse
    to run when it cannot account for every record, given that its output is what
    an operator uses to decide whether destroying the old seal is safe?

11. **Downgrade rotations.** Is HSM → file seal a supported operation? It works
    today with no warning, and it silently converts "keys held in a device" into
    "keys wrapped by a file beside the data" (`docs/11:204-212`).

12. **Rotation and reference-held keys.** For a CA created with
    `-ca-in-hardware`, the store holds a `KeyRef`, not an envelope. What should
    `SealInventory` report and `RotateSeal` do for such an item — skip it with an
    explicit note that its custody cannot be moved (the key is non-extractable by
    construction), or refuse the whole ceremony until the operator acknowledges
    it?

13. **`Status.Sealed` is hard-coded `false`** (`node.go:191`) on the grounds that
    Signet unseals at startup or refuses to start. If a seal becomes unreachable
    while running (token pulled, HSM-22), should `sys/health` be able to report
    `sealed: true`, or is process exit the intended response?

---

## 13. Recommended order of work

1. **§9.1** — fix and test the two watermark/lineage failures. They are the only
   findings that silently lose or corrupt committed data, and one of them
   re-arms the nonce-uniqueness violation that AES-GCM does not survive.
2. **§9.2 / §9.3** — sentinel check on `store.Open`; refuse to mint a root key
   over an existing store. Two small changes that turn three unrecoverable
   failure modes into startup errors.
3. **Barrier and store unit tests (§2, §3)** — 44 scenarios over two files with
   no test file at all, most of them a few lines each. Highest coverage per hour
   in the whole area.
4. **Snapshot/restore round trip across all 19 buckets (§5)** — SNP-01, SNP-04,
   SNP-05, SNP-06, SNP-08.
5. **The §8.1 crash harness**, then CRS-01…CRS-06 and CRS-12…CRS-19. Every
   durability claim in `docs/11:178-184` currently rests on a code comment.
6. **§9.5 and the HSM rotation matrix (ROT-14…ROT-17)** — the cross-backend
   ceremony is the feature's reason for existing and is tested only file→file.
