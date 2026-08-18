# 06 — Anchored audit: on-rails test plan

**Status: Draft** — design document only. No source or existing test was modified
in producing it.

Scope: the hash chain (`internal/store/audit.go`), the checkpoint/witness
protocol (`internal/audit/audit.go`), the kernel surface
(`internal/kernel/audit.go`), audit-record content (`internal/kernel/apply.go`),
transactional binding to the mutation (`internal/fsm/fsm.go`), and the CLI/HTTP
surfaces (`cmd/signet/audit.go`, the `/v1/audit/*` routes in
`internal/dialect/vaultkv/handler.go`). The claim under test is the one stated in
`docs/11-operations.md:87-103`.

Build note: this tree is on NFS without `flock`. Every scenario below is to be
run with `make test` (Go) or `bash test/audit/run.sh` (end-to-end). Never bare
`go test`/`go build`.

---

## 0. The claim being tested, and how it decomposes

`docs/11-operations.md:90-96` asserts a five-row attack table with a deliberate
split: three rows the chain **misses** and the witness **catches**. The plan is
organised so that split is asserted directly, not implied.

Five distinct detectors exist. Every scenario names exactly one as the layer that
catches it, because a scenario caught by the wrong layer is a design regression
even when the test passes.

| Layer | Code | What it can prove |
|---|---|---|
| **L1 chain** | `store.VerifyAuditChain`, `internal/store/audit.go:161-197` | No entry was edited, removed from the middle, inserted, or reordered *within the log as it now stands* |
| **L2 count** | `kernel.VerifyAudit`, `internal/kernel/audit.go:39-44` | The walked length matches the recorded `audit_count`. Defeated by an attacker who edits the counter (`internal/store/audit.go:41-46` says so) |
| **L3 signature** | `audit.Open`, `internal/audit/audit.go:84-100` | A checkpoint was produced by the holder of the named key and not altered in flight |
| **L4 witness** | `Witnessed.Extend`, `internal/audit/audit.go:161-244` | Whatever this witness accepted before is a prefix of what it is being shown now |
| **L5 pin** | `kernel.Witness`, `internal/kernel/audit.go:145-170` | The domain still signs with the key it signed with at first witness |
| **L0 transaction** | `fsm.Apply` + `store.Update`, `internal/fsm/fsm.go:57-70` | A mutation and its audit record commit together or not at all |

"Layer: none" appears in §11 (residual risk) and nowhere else. If a scenario in
§1–§10 cannot be assigned a layer, it belongs in §11.

Coverage key: **COVERED** (a named existing test asserts it), **PARTIAL** (an
existing test exercises the path but does not assert the property), **GAP** (no
test).

---

## 1. Chain construction and determinism (L1)

Preconditions common to §1: a `store.Store` opened over a temp dir with a fixed
32-byte barrier key, as `openTestStore` does (`internal/store/audit_test.go:15-27`).

### AA-CHAIN-01 — chain over N entries verifies
- **Pre:** empty store.
- **Input:** 5 records appended, each in its own `Update(1, i, …)` transaction
  (`internal/store/audit_test.go:30-40`).
- **Expected:** `VerifyAuditChain` returns `(5, head, nil)`; `AuditCount` returns 5.
- **Layer:** L1.
- **Coverage:** COVERED — `internal/store/audit_test.go:56-77`.

### AA-CHAIN-02 — identical inputs produce identical heads on two stores
- **Pre:** two independently opened stores.
- **Input:** the same 5 record byte sequences into each.
- **Expected:** identical head strings.
- **Layer:** L1 (determinism precondition for L4; two replicas that disagree on
  their own history cannot be witnessed as one domain).
- **Coverage:** COVERED — `internal/store/audit_test.go:69-76`.

### AA-CHAIN-03 — determinism is independent of transaction position
- **Pre:** two stores.
- **Input:** the same 5 records, but store A applies them at
  `(term 1, index 1..5)` and store B at `(term 7, index 900..904)`.
- **Expected:** identical heads and counts. `ChainHash` takes only
  `(prev, record)` (`internal/store/audit.go:71-78`), while the *storage key*
  takes `(term, index, seq)` (`internal/store/audit.go:104`) — the plan asserts
  the head does not leak the key.
- **Layer:** L1.
- **Coverage:** GAP. This is the property that makes AA-CHAIN-02 meaningful for
  real replicas, since two replicas hold entries at the same index but a fresh
  restore may not.

### AA-CHAIN-04 — hash binding is unambiguous
- **Input:** `ChainHash("sha256:AB", "CD")` vs `ChainHash("sha256:A", "BCD")`.
- **Expected:** different; and `ChainHash` is a pure function.
- **Layer:** L1.
- **Coverage:** COVERED — `internal/store/audit_test.go:250-259`.

### AA-CHAIN-05 — genesis is the documented constant
- **Input:** `GenesisHead()`.
- **Expected:** equals `"signet/audit/chain/v1"`
  (`internal/store/audit.go:35,39`), and the first entry's `Prev` equals it.
- **Layer:** L1. A witness replays from `store.GenesisHead()`
  (`internal/audit/audit.go:202-205`), so a silent change to this constant
  invalidates every witness record in existence.
- **Coverage:** GAP. Worth a golden-value test precisely because it is a wire
  constant shared across processes and versions.

### AA-CHAIN-06 — scan order matches sequence order
- **Pre:** entries written across increasing `(term, index)` pairs including a
  term bump (`(1,5)` then `(2,6)`).
- **Input:** `ScanAudit`.
- **Expected:** entries arrive with `Seq` 1,2,3… monotonically. Key ordering is
  lexicographic over `%020d:%020d:%010d` (`internal/store/audit.go:104`), which
  is only equivalent to sequence order because Raft terms are non-decreasing with
  index.
- **Layer:** L1.
- **Coverage:** GAP. The assumption is load-bearing and undocumented; a restore
  that replays entries under a lower term than an existing one would silently
  reorder the chain and produce an `AuditBreak` that looks like tampering.

### AA-CHAIN-07 — empty chain verifies and says nothing
- **Pre:** fresh store, no entries.
- **Expected:** `VerifyAuditChain` → `(0, "signet/audit/chain/v1", nil)`.
  `signet audit verify` prints the "an empty chain verifies trivially" caveat
  (`cmd/signet/audit.go:85-87`).
- **Layer:** L1.
- **Coverage:** GAP (Go). The CLI caveat exists but is unasserted.

---

## 2. Chain negative cases — what the chain DOES catch (L1)

All of §2 assumes the adversary described in `internal/store/audit_test.go:10-13`:
they hold the node and its barrier key and edit the store directly.

### AA-CHAIN-N01 — edit a record in place
- **Pre:** 5 entries.
- **Input:** rewrite entry 3's `Record` field, leaving `Seq`, `Prev`, `Hash` as
  they were.
- **Expected:** `*AuditBreak` with `Seq == 3` and reason containing
  `"record was altered"` (`internal/store/audit.go:182-186`).
- **Layer:** **L1** — chain.
- **Coverage:** COVERED — `internal/store/audit_test.go:80-128`.

### AA-CHAIN-N02 — remove an entry from the middle
- **Pre:** 5 entries.
- **Input:** delete entry 3's key.
- **Expected:** `*AuditBreak` at `Seq == 3`, reason "numbered out of sequence, so
  an entry was inserted or removed" (`internal/store/audit.go:172-176`).
- **Layer:** **L1**.
- **Coverage:** COVERED — `internal/store/audit_test.go:131-162`.

### AA-CHAIN-N03 — insert an entry
- **Pre:** 5 entries.
- **Input:** write a well-formed extra entry with `Seq: 3`, `Prev` = entry 2's
  hash, correct self-hash, at a key sorting between entries 3 and 4.
- **Expected:** the inserted entry occupies scan position 4 while carrying
  `Seq: 3`, so the sequence check fires there with `Expected: 4, Found: 3`
  (`internal/store/audit.go:172-176`) — the break points one past the insertion,
  not at it, which is worth pinning down since the reason string says "an entry
  was inserted or removed" and an operator will read it as a location.
- **Layer:** **L1**.
- **Coverage:** GAP. `docs/11-operations.md:93` claims insertion is caught in the
  same row as removal, but only removal is tested. The two take different
  branches of `VerifyAuditChain` and deserve separate assertions.

### AA-CHAIN-N04 — alter a record and re-link it (keep links consistent)
- **Pre:** 5 entries.
- **Input:** rewrite entry 3's record **and** recompute entry 3's `Hash`
  correctly, leaving entries 4 and 5 untouched.
- **Expected:** entry 3 passes its own hash check; entry 4 fails the `Prev` check
  with reason "entry does not follow the one before it"
  (`internal/store/audit.go:177-181`), `Seq == 4`.
- **Layer:** **L1**.
- **Coverage:** GAP. This is the *link* branch of the chain, and no test reaches
  it — every existing negative test lands on the sequence branch or the
  self-hash branch. The link check is the whole reason the structure is a chain
  rather than a list of individually-hashed records.

### AA-CHAIN-N05 — full re-chain from entry 3 onward
- **Pre:** 5 entries.
- **Input:** rewrite entry 3's record and recompute entries 3, 4 and 5 so the
  chain is internally perfect over all 5.
- **Expected:** `VerifyAuditChain` returns **nil error** over 5 entries with a
  *different* head. `AuditCount` still reports 5, so L2 also passes.
- **Layer:** **none locally** — this is the "attacker who can recompute the
  chain" case of `internal/audit/audit.go:6-12`, caught only by L4 once a
  checkpoint over the old head has been witnessed (see AA-WIT-N02).
- **Coverage:** GAP at the store layer. This is the single most important
  *negative-negative* scenario in §2: it pins down that the chain is not claimed
  to catch it.

### AA-CHAIN-N06 — corrupt an entry into unparseable bytes
- **Input:** overwrite entry 3's stored value with `[]byte("{")`.
- **Expected:** `*AuditBreak` with reason prefixed "entry is unreadable"
  (`internal/store/audit.go:167-170`), `Seq == 3`.
- **Layer:** **L1**.
- **Coverage:** GAP. Also worth pairing with AA-API-05: `ScanAudit` *silently
  skips* unparseable entries (`internal/store/audit.go:203-205`), so
  `AuditEntries` and `VerifyAuditChain` disagree about the same store.

### AA-CHAIN-N07 — appending after tampering does not heal the chain
- **Pre:** 3 entries, entry 2 tampered.
- **Input:** append 2 more entries normally.
- **Expected:** still broken at entry 2.
- **Layer:** **L1**.
- **Coverage:** COVERED — `internal/store/audit_test.go:216-246`.

### AA-CHAIN-N08 — reorder two entries by swapping their storage keys
- **Pre:** 5 entries.
- **Input:** swap the stored values of entries 3 and 4.
- **Expected:** break at scan position 3 with `Found: 4`.
- **Layer:** **L1**.
- **Coverage:** GAP.

---

## 3. Chain negative cases — what the chain does NOT catch (L2 / none)

These exist to assert the *limits* out loud, in the order
`docs/11-operations.md:98-103` claims them.

### AA-TRUNC-01 — truncate the newest entries; the chain still verifies
- **Pre:** 5 entries.
- **Input:** delete entries 4 and 5.
- **Expected:** `VerifyAuditChain` returns **nil error** with count 3.
  `AuditCount` still returns 5.
- **Layer:** **L2 only** — the mismatch is the sole local trace
  (`internal/kernel/audit.go:39-44`).
- **Coverage:** COVERED at the store layer —
  `internal/store/audit_test.go:168-213`.

### AA-TRUNC-02 — `kernel.VerifyAudit` reports the truncation as a count mismatch
- **Pre:** as AA-TRUNC-01, through a kernel.
- **Expected:** error text "the audit chain verifies over 3 entries but this store
  recorded 5" (`internal/kernel/audit.go:40-43`), and the returned `count`/`head`
  are still the walked values so an operator can see where it stopped.
- **Layer:** **L2**.
- **Coverage:** GAP. The store-level half is tested; the kernel wrapper that
  turns it into an operator-facing signal is not tested anywhere.

### AA-TRUNC-03 — truncation with the counter also edited defeats L2
- **Pre:** as AA-TRUNC-01.
- **Input:** additionally `Put(BucketMeta, "audit_count", "3")`.
- **Expected:** `kernel.VerifyAudit` returns **nil error**, count 3.
  `signet audit verify` prints "audit chain intact".
- **Layer:** **none locally** — L4 only.
- **Coverage:** GAP. Asserting this is what makes the L2 check honest rather than
  reassuring; `internal/store/audit.go:41-46` already says it in prose.

### AA-TRUNC-04 — wholesale wipe and restart from genesis
- **Pre:** 5 entries.
- **Input:** delete every audit key, reset `audit_head` and `audit_count`, append
  3 fresh entries.
- **Expected:** `VerifyAuditChain` → `(3, head', nil)`; L2 agrees.
- **Layer:** **none locally**; L4 catches it as a count regression
  (`internal/audit/audit.go:170-178`) and L5 catches the common real-world form
  where the audit key did not survive.
- **Coverage:** GAP at the unit level; the end-to-end form is covered by
  `test/audit/run.sh:136-163`.

### AA-E2E-01 — the ordering claim, end to end
- **Pre:** two domains; `home` witnessed by `aws` at N entries.
- **Input:** roll `home` back to a genuine earlier state (keys, seal, audit key
  and token all intact), re-run different work, then (a) run `signet audit verify`
  locally and (b) re-present to the witness.
- **Expected, in this order:** (a) exits **0** and prints "audit chain intact";
  (b) exits non-zero with a CONFLICT.
- **Layer:** (a) L1 passes correctly; (b) **L4**.
- **Coverage:** COVERED — `test/audit/run.sh:90-115`, and it asserts the order.
  This is the load-bearing acceptance test for the whole milestone.

---

## 4. Atomicity with the mutation (L0)

`internal/store/audit.go:80-84` and `docs/15` contract 3 claim a mutation without
its audit record is *impossible*, not unlikely. The only write path in production
is `fsm.Apply` (`internal/fsm/fsm.go:57-70`) — verified by inspection: the only
non-test callers of `store.Update` are `store.Open` (bucket creation,
`internal/store/store.go:67`), `RestoreRaw`
(`internal/store/snapshot.go:41`), and `fsm.Apply`.

### AA-ATOM-01 — one applied Op appends exactly one audit entry
- **Pre:** a node from `internal/fsm/fsm_test.go:16-29`.
- **Input:** a sequence of 6 kernel calls that each propose exactly one Op.
- **Expected:** `AuditCount` increases by exactly 1 per Op; final count equals the
  number of Ops proposed since genesis.
- **Layer:** **L0**.
- **Coverage:** GAP.

### AA-ATOM-02 — a rejected Op still writes its audit record
- **Pre:** bootstrapped domain.
- **Input:** each rejection from `internal/kernel/apply_test.go:284-290`
  (bad path, bad type, missing subject, unknown role, missing principal).
- **Expected:** the Op fails, domain state is unchanged, **and** the chain grew by
  one entry per rejection with `accepted: false` and a non-empty `error`
  (`internal/kernel/apply.go:332-335`).
- **Layer:** **L0**.
- **Coverage:** PARTIAL — `internal/kernel/apply_test.go:276-306` asserts *no
  state change* but says nothing about the audit record. That test runs
  `kernel.Apply` directly and never calls `AppendAudit`, so the property in the
  comment at `internal/kernel/apply.go:28-29` ("the transaction then carries only
  the audit record") is asserted nowhere. This is the highest-value atomicity gap.

### AA-ATOM-03 — a rejected Op leaves no partial state
- As `internal/kernel/apply_test.go:276-306`, kept here because it is the
  precondition that lets AA-ATOM-02 commit a rejection's audit record in the same
  transaction.
- **Layer:** L0. **Coverage:** COVERED.

### AA-ATOM-04 — audit append failure rolls back the mutation
- **Pre:** a store whose `AppendAudit` fails (fault injection at the bolt or
  barrier layer).
- **Input:** any mutating Op.
- **Expected:** `fsm.Apply` returns an error, the mutation is **absent** from the
  store, and the applied index did not advance.
- **Layer:** **L0**.
- **Coverage:** GAP, and currently **not reachable without a seam** — `store.Tx`
  has no injectable failure point. See Q7.

### AA-ATOM-05 — an undecodable log entry produces no audit record at all
- **Pre:** a Raft log entry whose ciphertext fails `Barrier().Open`, or whose
  plaintext fails `op.Decode`.
- **Input:** apply it.
- **Expected (today):** `fsm.Apply` returns early at
  `internal/fsm/fsm.go:47-54`, writing **no** audit record and **not** advancing
  the applied index.
- **Layer:** **none** — a hole in L0.
- **Coverage:** GAP. See §12 bug (F). The design intent stated at
  `internal/fsm/fsm.go:58-60` ("rejections are recorded, not silently dropped")
  does not hold for this class of rejection.

### AA-ATOM-06 — no production code path writes state without audit
- **Input:** an architectural assertion — enumerate callers of `store.Update`
  outside `internal/store` and `_test.go`, assert the set is exactly
  `{internal/fsm/fsm.go}`.
- **Expected:** pass.
- **Layer:** **L0**.
- **Coverage:** GAP. Cheap to write, and it is the only test that keeps the
  "single write path" claim (`internal/kernel/apply.go:12-14`) true as the code
  grows.

### AA-ATOM-07 — audit entry and mutation share one transaction key position
- **Input:** apply one `PutSecret`; read the audit entry's storage key.
- **Expected:** the key's term/index components equal the Raft entry's
  `(l.Term, l.Index)` (`internal/store/audit.go:104`,
  `internal/fsm/fsm.go:57`), so an entry can be tied back to the log position that
  produced it.
- **Layer:** L0. **Coverage:** GAP.

---

## 5. Idempotence, replay, and the applied-index watermark (L0)

### AA-IDEM-01 — restart does not re-apply, and does not re-append audit
- **Pre:** the exact setup of `internal/fsm/fsm_test.go:37-89`.
- **Input:** close and reopen the node twice.
- **Expected:** secret still at version 1 (already asserted) **and** `AuditCount`
  and the chain head are byte-identical across all three opens.
- **Layer:** **L0** (`internal/fsm/fsm.go:44-46`).
- **Coverage:** PARTIAL — the version half is COVERED at
  `internal/fsm/fsm_test.go:79-81`; the audit half is a GAP. Without it, a
  regression in the watermark would double every audit entry on restart, changing
  the head and putting every witness into conflict — the loudest possible
  false positive.

### AA-IDEM-02 — an entry at or below the watermark writes nothing
- **Input:** call `FSM.Apply` directly with `l.Index` equal to the current
  applied index.
- **Expected:** returns an empty `op.Result` immediately; `AuditCount` unchanged.
- **Layer:** **L0**.
- **Coverage:** GAP.

### AA-IDEM-03 — snapshot/restore preserves the chain exactly
- **Input:** `SnapshotRaw` after N entries, `RestoreRaw` into a second store
  opened with the same barrier key.
- **Expected:** `VerifyAuditChain` on the restored store returns the identical
  `(count, head)`; `AppliedIndex` matches (`internal/fsm/fsm.go:94-101`).
- **Layer:** **L0**.
- **Coverage:** GAP. `BucketAudit` and `BucketMeta` are both in `allBuckets`
  (`internal/store/store.go:39-45`), so this should hold; nothing asserts it.

### AA-IDEM-04 — restore then continue: the chain continues, it does not restart
- **Input:** restore a snapshot at count 5, then apply 2 more Ops.
- **Expected:** entries 6 and 7 chain from entry 5's hash; `VerifyAuditChain` → 7.
- **Layer:** **L0**.
- **Coverage:** GAP.

### AA-IDEM-05 — two nodes replaying the same Op sequence reach the same head
- **Pre:** two nodes, separate data dirs, same seal key not required (the barrier
  affects storage, not `ChainHash` input).
- **Input:** the identical ordered sequence of Ops at the identical
  `(term, index)` pairs.
- **Expected:** identical `VerifyAuditChain` heads.
- **Layer:** **L0/L1**.
- **Coverage:** GAP. `internal/store/audit_test.go:56-77` proves determinism given
  identical *record bytes*; this proves the records themselves are deterministic,
  which is a property of `NewAuditRecord` (`internal/kernel/apply.go:331-379`)
  and therefore of every `Apply` error string. That is the part that can actually
  drift.

### AA-IDEM-06 — rejection error strings are deterministic
- **Input:** the same rejected Op applied on two nodes.
- **Expected:** identical `error` field bytes, hence identical chain hashes.
- **Layer:** **L0/L1**.
- **Coverage:** GAP. `AuditRecord.Error` is `res.Err.Error()`
  (`internal/kernel/apply.go:333-335`); any error text that embeds a map
  iteration, a pointer, or a filesystem path silently forks replicas' audit
  chains. See Q1.

---

## 6. Audit-record content per Op kind (L0)

`internal/kernel/apply.go:315-328` states the record must carry "what was
proposed, by whom, at which log position, and whether it was accepted — enough
provenance to distinguish a legitimately issued change from a forged one".

All 20 Op kinds in `internal/op/op.go:29-51` have a case in `NewAuditRecord`
(`internal/kernel/apply.go:336-377`) — there is no kind that falls through to
`Kind`-only. The gaps are in *content quality*, not coverage.

### AA-REC-01 — every Op kind produces a record with a non-empty Kind and a position
- **Input:** table over all 20 kinds; construct a minimal instance of each and
  call `NewAuditRecord(term, index, o, res)`.
- **Expected:** `kind` decodes to the string in `internal/op/op.go:53-97` (never
  `Kind(n)`), `term`/`index` match, `accepted` reflects `res.Err == nil`.
- **Layer:** L0.
- **Coverage:** GAP. A table test here is the guard that a new Op kind cannot be
  added without an audit case — today, adding one and forgetting the `switch` arm
  produces a record with no actor and no subject and nothing fails.

### AA-REC-02 — every Op kind records a non-empty Actor when one was supplied
- **Input:** as AA-REC-01 with `Header{Actor: "p-1", AtSec: 1000}`.
- **Expected:** `actor == "p-1"` and `at == 1000` for all 20 kinds.
- **Layer:** L0.
- **Coverage:** GAP.

### AA-REC-03 — subject quality per kind
Assert the specific subject string per kind. Current behaviour, from
`internal/kernel/apply.go:337-377`:

| Op | Subject recorded | Adequate? |
|---|---|---|
| `PutPrincipal` | `v.Path` | yes |
| `PutBinding` | `v.Scope` **only** | **no** — see AA-REC-N01 |
| `PutSecret` | `v.Path` | partial — no version; see AA-REC-N03 |
| `CreateSession` | principal ID | yes |
| `RevokeSession` | **nothing** | **no** — see AA-REC-N02 |
| `PutIssuer` | `v.Name` | yes |
| `PutMapping` | `v.Name` | partial — not the target principal |
| `VersionAction` | `v.Path` | **no** — mode omitted; see AA-REC-N04 |
| `DestroySecret` | `v.Path` | yes |
| `PutSecretMeta` | `v.Path` | yes |
| `PutCA` | `v.Name` | yes |
| `PutPKIRole` | `v.Name` | yes |
| `RecordIssuance` | `v.Serial` | partial — see AA-REC-N05 |
| `PutRolePolicy` | `v.Role` | yes |
| `PutKey` | `purpose/id` | partial — `Active` omitted |
| `PutSSHRole` | `v.Name` | yes |
| `PutTrustBundle` | `domain epoch N` | yes |
| `PutWitness` | `witness <domain>` | partial — no count/head |
| `RequestActivation` | `activation <id>: <reason>` | yes |
| `ActivationAction` | `activation <verb> <id>` | partial — `Actor2` omitted |

- **Coverage:** GAP for all rows.

### AA-REC-N01 — a grant records who was granted what
- **Pre:** none.
- **Input:** `PutBinding{Actor: "grantor", Subject: "attacker", Role:
  "domain-admin", Scope: "/"}`.
- **Expected (desired):** the record names subject and role.
  **Expected (today):** subject is `"/"` and nothing else; the record for
  granting `domain-admin` at `/` to an attacker is byte-identical, apart from
  actor and timestamp, to granting `kv-reader` at `/` to a service account.
- **Layer:** L0.
- **Coverage:** GAP, and a **content bug** — see §12 (D). The audit log's stated
  job is distinguishing a legitimate change from a forged one; for the single
  highest-value Op in the system it cannot distinguish two legitimate changes.

### AA-REC-N02 — a session revocation records which session
- **Input:** `RevokeSession{Actor: "admin", TokenHash: "h…"}`.
- **Expected (today):** `subject` empty (`internal/kernel/apply.go:375-376`).
- **Layer:** L0. **Coverage:** GAP; see §12 (E). A truncated token-hash prefix
  would be sufficient and non-disclosing.

### AA-REC-N03 — a secret write records the version it produced
- **Input:** `PutSecret` on an existing path; `res.Version == 4`.
- **Expected (today):** version absent, though `res` is passed into
  `NewAuditRecord` and `op.Result.Version` (`internal/op/op.go:386-390`) holds it.
- **Layer:** L0. **Coverage:** GAP.

### AA-REC-N04 — destroy and delete are distinguishable
- **Input:** `VersionAction{Mode: destroy, Versions: [3]}` and
  `VersionAction{Mode: delete, Versions: [3]}` on the same path.
- **Expected (today):** identical records apart from timestamp
  (`internal/kernel/apply.go:367`). An irreversible destroy and a reversible
  delete are indistinguishable in the audit log.
- **Layer:** L0. **Coverage:** GAP.

### AA-REC-N05 — an issuance records enough provenance to detect a diamond ticket
- **Input:** `RecordIssuance{Serial, Subject, SANs, Requester}`.
- **Expected (today):** only the serial. `docs/11-operations.md:76-78` claims the
  log "records enough issuance provenance to distinguish a legitimately-issued
  credential from a tampered-but-real one"; correlating a serial to a subject
  requires a second lookup into `BucketIssuance`, which the same attacker can
  edit.
- **Layer:** L0. **Coverage:** GAP.

### AA-REC-06 — the record is opaque to the chain
- **Input:** append a record containing arbitrary JSON, including one with a
  `hash`/`prev` field of its own.
- **Expected:** the chain treats it as bytes
  (`internal/store/audit.go:53-58`); no schema coupling.
- **Layer:** L1. **Coverage:** GAP (an explicit test for the documented
  independence property).

---

## 7. Checkpoint signing and verification (L3)

### AA-CP-01 — sign/open round trip preserves the claim
- **Coverage:** COVERED — `internal/audit/audit_test.go:57-70`.

### AA-CP-02 — a checkpoint from another key does not verify
- **Coverage:** COVERED — `internal/audit/audit_test.go:72-75`.

### AA-CP-03 — an edited payload does not verify
- **Input:** replace `Payload` with a re-encoded, different `Checkpoint`.
- **Expected:** refusal mentioning "signature does not verify"
  (`internal/audit/audit.go:90-94`).
- **Coverage:** COVERED — `internal/audit/audit_test.go:77-82`.

### AA-CP-04 — a malformed base64 payload is refused before parsing
- **Input:** `Signed{Payload: "!!!!"}`.
- **Expected:** "not valid base64" (`internal/audit/audit.go:86-88`).
- **Layer:** L3. **Coverage:** GAP.

### AA-CP-05 — a truncated or empty signature is refused
- **Input:** `Signature: nil` and `Signature: sig[:10]`.
- **Expected:** signature refusal, no panic.
- **Layer:** L3. **Coverage:** GAP.

### AA-CP-06 — `Claim()` does not verify, and is documented as such
- **Input:** a `Signed` with a garbage signature but valid payload.
- **Expected:** `Claim()` returns the checkpoint; `Open()` refuses it
  (`internal/audit/audit.go:102-115`).
- **Layer:** L3. **Coverage:** GAP. Worth an explicit test because
  `cmd/signet/audit.go:132,177` calls `Claim()` on freshly fetched network data —
  correctly, since it is only used for display and to size the entry fetch, but
  that is exactly the kind of use that drifts.

### AA-CP-07 — the kernel verifies the chain before signing
- **Pre:** a store with a broken chain (AA-CHAIN-N01 applied through a kernel).
- **Input:** `Kernel.Checkpoint(ctx, domain, node)`.
- **Expected:** error "refusing to checkpoint a chain that does not verify"
  (`internal/kernel/audit.go:70-73`); **no** `Signed` returned.
- **Layer:** L3 + L1.
- **Coverage:** GAP. This is the "a corrupted store cannot launder itself into an
  authoritative statement" claim (`internal/kernel/audit.go:64-68`) and nothing
  tests it — not `internal/audit`, not the kernel, not `test/audit/run.sh`.
  Top-5 gap.

### AA-CP-08 — a truncated chain with an edited counter still refuses to checkpoint
- **Pre:** AA-TRUNC-01 (entries deleted, counter left at 5).
- **Expected:** `Checkpoint` refuses via the L2 mismatch.
- **Pre (variant):** AA-TRUNC-03 (counter also edited).
- **Expected:** `Checkpoint` **succeeds** and signs the shortened chain — which is
  correct and is precisely why the witness exists.
- **Layer:** L2 then none. **Coverage:** GAP.

### AA-CP-09 — a domain with no audit key gets an actionable error
- **Pre:** a domain initialised without a `PurposeAudit` key.
- **Input:** `Kernel.Checkpoint`.
- **Expected:** error naming the remedy (`internal/kernel/audit.go:80-84`).
- **Layer:** L3.
- **Coverage:** GAP — and the remedy the message names, `signet audit init-key`,
  **does not exist** (`cmd/signet/audit.go:43-57` handles only
  verify/checkpoint/witness/witnessed). See §12 (A).

### AA-CP-10 — the checkpoint commits to count and head together
- **Input:** two checkpoints taken at counts 5 and 8.
- **Expected:** `Count` and `Head` both advance; `Index` is the applied index and
  `AtSec` the node clock (`internal/kernel/audit.go:89-92`).
- **Layer:** L3. **Coverage:** GAP.

### AA-CP-11 — `AuditPublicKey` returns the key that verifies the checkpoint
- **Input:** `Checkpoint` then `AuditPublicKey`; `Open` the first with the second.
- **Expected:** verifies; `kid` equals `Signed.KeyID`.
- **Layer:** L3. **Coverage:** GAP. Nothing asserts the served pubkey
  (`internal/dialect/vaultkv/handler.go:206-221`) matches the signing key, which
  is the single fact the entire witness protocol bootstraps from.

### AA-CP-12 — `Open` ignores `Alg` and `KeyID`
- **Input:** a `Signed` with `Alg: "none"` and `KeyID: "someone-else"` but a
  valid ES256 signature.
- **Expected (today):** accepted — `Open` (`internal/audit/audit.go:84-100`)
  never reads either field.
- **Layer:** L3. **Coverage:** GAP; benign today (the key, not the label, decides)
  but it should be an asserted decision rather than an omission. See Q4.

---

## 8. The witness protocol (L4)

Preconditions common to §8: `chain()` from `internal/audit/audit_test.go:26-36`
builds a real chain from `store.GenesisHead()`.

### AA-WIT-01 — accepts an extension it verifies by replay
- **Input:** fresh `Witnessed{}`, checkpoint at count 5, all 5 entries.
- **Expected:** accepted; `w.Count == 5`, `w.Head == head`;
  `w.History` gains one `HeadAtN`.
- **Coverage:** COVERED — `internal/audit/audit_test.go:86-96`. `History` is not
  asserted (GAP, minor).

### AA-WIT-02 — continues from where it left off
- **Input:** a second checkpoint at count 8 with entries 6–8 only.
- **Expected:** accepted; `w.Count == 8`.
- **Coverage:** COVERED — `internal/audit/audit_test.go:97-105`.

### AA-WIT-03 — re-witnessing identical state raises no conflict
- **Input:** same count, same head, **no** entries.
- **Expected:** `nil` error, `w.Conflict == nil`, no history growth
  (`internal/audit/audit.go:182-193`).
- **Coverage:** COVERED — `internal/audit/audit_test.go:224-236`. Directly guards
  the scheduled-witness false-positive.

### AA-WIT-04 — history is trimmed but keeps the earliest entry
- **Input:** 40 successful sequential extensions.
- **Expected:** `len(w.History) == 32`, `History[0]` is the first ever recorded
  (`internal/audit/audit.go:238-242`).
- **Layer:** L4. **Coverage:** GAP. The trim uses
  `append(w.History[:1], w.History[len-31:]...)`, an aliasing pattern that is
  correct here but fragile; the "keep the earliest as evidence" claim is
  untested.

### AA-WIT-05 — one witness record per domain
- **Input:** a record advanced for `home.example.net`, then a checkpoint for
  `aws.example.net`.
- **Expected:** refusal "never combined" (`internal/audit/audit.go:162-166`).
- **Coverage:** COVERED — `internal/audit/audit_test.go:212-220`.

### AA-WIT-06 — records are keyed by domain in the store
- **Input:** witness two domains through a kernel; read `BucketWitness`.
- **Expected:** two independent records; `AllWitnessed` returns both
  (`internal/kernel/audit.go:214-226`).
- **Layer:** L4. **Coverage:** GAP (Go); exercised end-to-end by
  `test/audit/run.sh:136-163`.

### AA-WIT-N01 — refuses an unjustified extension (no entries)
- **Input:** witnessed at 5; checkpoint claiming 9 with `nil` entries.
- **Expected:** refusal "entries are needed to justify it"
  (`internal/audit/audit.go:196-201`); `w.Count` stays 5; **no conflict recorded**
  (this is a malformed request, not proof of tampering).
- **Coverage:** COVERED — `internal/audit/audit_test.go:110-121`.

### AA-WIT-N02 — same count, different head → rewrite, no entries needed
- **Input:** witnessed at 5 over the real chain; checkpoint at 5 over a forged
  chain built from genesis.
- **Expected:** refusal "The log was rewritten"; `w.Conflict` names both heads;
  `w.Head` unchanged (`internal/audit/audit.go:182-191`).
- **Coverage:** COVERED — `internal/audit/audit_test.go:126-152`. The headline
  case.

### AA-WIT-N03 — forked history on replay
- **Input:** witnessed at 5; a forged 8-entry chain from genesis, offering
  entries 6–8 of *that* chain.
- **Expected:** refusal "have diverged"; conflict recorded at the diverging
  sequence number; witness keeps count 5 (`internal/audit/audit.go:213-222`).
- **Coverage:** COVERED — `internal/audit/audit_test.go:156-174`.

### AA-WIT-N04 — truncation claim
- **Input:** witnessed at 5; checkpoint claiming 3.
- **Expected:** refusal "this is a truncation"; conflict recorded
  (`internal/audit/audit.go:170-178`).
- **Coverage:** COVERED — `internal/audit/audit_test.go:178-190`.

### AA-WIT-N05 — an altered entry inside an otherwise valid extension
- **Input:** 3 chained entries, entry 2's `Record` swapped without rehashing.
- **Expected:** refusal "does not match its own hash"
  (`internal/audit/audit.go:223-227`); **no conflict recorded** — a malformed
  extension is not proof of a rewrite.
- **Coverage:** COVERED — `internal/audit/audit_test.go:194-200`.

### AA-WIT-N06 — a checkpoint whose head does not match the entries offered
- **Input:** 3 valid entries, checkpoint head `"sha256:something-else"`.
- **Expected:** refusal "does not describe the entries offered"
  (`internal/audit/audit.go:230-234`).
- **Coverage:** COVERED — `internal/audit/audit_test.go:204-209`.

### AA-WIT-N07 — a non-contiguous run
- **Input:** witnessed at 5; entries numbered 6, 8, 9 (count arithmetic satisfied
  by supplying 3 entries for a move 5→8).
- **Expected:** refusal "the extension is not a contiguous run"
  (`internal/audit/audit.go:209-212`); no conflict recorded.
- **Layer:** L4. **Coverage:** GAP. Reachable in practice because `ScanAudit`
  silently drops unparseable entries (`internal/store/audit.go:203-205`), so a
  subject with one corrupt entry produces exactly this shape.

### AA-WIT-N08 — too many entries supplied
- **Input:** witnessed at 5; checkpoint at 8; 5 entries supplied.
- **Expected:** the count-arithmetic refusal at
  `internal/audit/audit.go:196-201` (`3 entries are needed and 5 were supplied`).
- **Layer:** L4. **Coverage:** GAP.

### AA-WIT-N09 — entries that chain correctly but whose first entry does not
  follow the witnessed head, at count 1
- **Input:** a fresh witness (`Head == ""`), entries whose entry 1 has
  `Prev != GenesisHead()`.
- **Expected:** refusal "have diverged", with `Was` = the genesis constant
  (`internal/audit/audit.go:202-205, 213-222`).
- **Layer:** L4. **Coverage:** GAP. This is the only path that exercises the
  genesis fallback, and it is the path every first-ever witnessing takes.

### AA-WIT-N10 — a witness in conflict refuses to be reset by asking again
- **Pre:** a witness holding a conflict for domain D.
- **Input:** re-present the same rewritten checkpoint; then present a *valid*
  checkpoint for D.
- **Expected:** both refused with "already holds proof that … rewrote its log"
  (`internal/kernel/audit.go:138-142`); the record is **not** re-persisted, so the
  original `Conflict.DetectedAt` survives.
- **Coverage:** COVERED end-to-end — `test/audit/run.sh:131-134` — for the first
  half only. GAP for: (a) the Go-level assertion, (b) that a *legitimate* later
  checkpoint is also refused (fail-closed, which is the intended behaviour and
  the operational cost of it), (c) that `DetectedAt` is not overwritten.

### AA-WIT-N11 — an extension that would advance past a conflict is not applied
- **Pre:** conflict held.
- **Expected:** `w.Count`/`w.Head` unchanged after the refusal; `Extend` is never
  reached (`internal/kernel/audit.go:138-142` returns before line 172).
- **Layer:** L4/L5. **Coverage:** GAP.

### AA-WIT-N12 — a checkpoint naming no domain
- **Input:** `Signed` over a `Checkpoint` with `Domain: ""`, correctly signed.
- **Expected:** refusal "names no domain, so there is nothing to witness it for"
  (`internal/kernel/audit.go:127-129`) — **before** anything is pinned or stored.
- **Layer:** L4. **Coverage:** GAP. Reachable today from a node started without
  `-domain`: `vaultkv.Config.Domain` defaults to empty
  (`internal/dialect/vaultkv/handler.go:55-57`, used at
  `internal/dialect/vaultkv/handler.go:198`), so the HTTP checkpoint of a
  misconfigured node is unwitnessable. Worth asserting the error is the
  domain one and not something downstream.

### AA-WIT-N13 — witnessing an empty chain
- **Input:** a checkpoint with `Count: 0, Head: <genesis>` and no entries, against
  a fresh witness.
- **Expected (today):** accepted with `nil` error via the equal-count branch
  (`internal/audit/audit.go:182-193`), but `w.Domain` is **never set** (only the
  growth branch assigns it, `internal/audit/audit.go:236`). The kernel then
  persists a record keyed by the domain whose `domain` field is empty
  (`internal/kernel/audit.go:174-180`), so `signet audit witnessed` prints a blank
  domain (`cmd/signet/audit.go:298`).
- **Layer:** L4. **Coverage:** GAP; see §12 (C).

### AA-WIT-N14 — a signed checkpoint replayed to a *different* witness
- **Input:** the same `Signed` presented to two independent witnesses.
- **Expected:** both accept — checkpoints are not bound to a recipient. Assert
  this is intended, since it means a checkpoint is a bearer statement about the
  domain and carries no anti-replay nonce.
- **Layer:** L3/L4. **Coverage:** GAP; see Q5.

---

## 9. Checkpoint key pinning (L5)

### AA-PIN-01 — the key is pinned on first successful witness
- **Input:** first witness of domain D with key K.
- **Expected:** `w.PinnedKey` is K in PKIX PEM
  (`internal/kernel/audit.go:145-153`, `:228-234`); `w.First` holds the first
  `Signed` as evidence.
- **Layer:** L5. **Coverage:** GAP (Go); implied by
  `test/audit/run.sh:136-163`.

### AA-PIN-02 — the same key on later witnessings is accepted silently
- **Input:** second and third witnessings with K.
- **Expected:** no conflict; `PinnedKey` unchanged.
- **Layer:** L5. **Coverage:** PARTIAL — `test/audit/run.sh:66-76` exercises it
  without asserting the pin.

### AA-PIN-N01 — a changed key is recorded as evidence, not merely refused
- **Pre:** D witnessed with key K.
- **Input:** a correctly-signed checkpoint for D under key K'.
- **Expected:** `Conflict` with reason "now signs its checkpoints with a different
  key" (`internal/kernel/audit.go:155-170`); the conflict is **persisted** before
  the error returns; `Extend` is never called, so `Count`/`Head` are untouched.
- **Layer:** **L5**.
- **Coverage:** COVERED end-to-end — `test/audit/run.sh:149-163` asserts both the
  refusal and the recorded reason. GAP at the Go level.

### AA-PIN-N02 — a legitimate audit-key rotation is indistinguishable from a wipe
- **Input:** rotate D's `PurposeAudit` key deliberately, then witness.
- **Expected (today):** permanent conflict, and there is **no** command to clear
  it — `internal/kernel/audit.go:141` says "until that is resolved deliberately"
  but `cmd/signet/audit.go:43-57` offers no resolution verb.
- **Layer:** L5. **Coverage:** GAP. See Q2.

### AA-PIN-N03 — a non-ECDSA or malformed pinned key is rejected at parse
- **Input:** `ParsePublicKeyPEM` with (a) non-PEM bytes, (b) an RSA PKIX key,
  (c) a PEM block with a corrupt body.
- **Expected:** "not PEM" / "this is a *rsa.PublicKey key; audit checkpoints are
  ECDSA-signed" / parse error (`internal/kernel/audit.go:238-252`).
- **Layer:** L5. **Coverage:** GAP.

### AA-PIN-N04 — pinning happens on a *failed* first witness
- **Pre:** no record for domain D.
- **Input:** a witness request for D with attacker key K' and an extension that
  fails verification (e.g. no entries).
- **Expected (today):** `PinnedKey = K'` and `First = <attacker checkpoint>` are
  set at `internal/kernel/audit.go:145-153`, **before** `Extend` runs at line 172,
  and persisted regardless of the failure at lines 178-180. Every subsequent
  honest checkpoint for D then trips AA-PIN-N01 and is permanently refused.
- **Layer:** L5 — misfiring.
- **Coverage:** GAP; see §12 (C). Requires only write authority at `/` on the
  witness (`internal/dialect/vaultkv/handler.go:254-257`), i.e. a legitimate
  witness operator or anyone who takes one, and it poisons a domain name the
  witness has never seen. Top-5 gap.

### AA-PIN-N05 — a stored witness record with an empty `Domain` field
- **Input:** after AA-PIN-N04 or AA-WIT-N13, call `AllWitnessed`.
- **Expected (today):** a record whose `Domain` is `""` is returned and printed as
  a blank row by `signet audit witnessed` (`cmd/signet/audit.go:291-299`), while
  the bucket key holds the real domain.
- **Layer:** L5. **Coverage:** GAP.

---

## 10. HTTP and CLI surface

### AA-API-01 — `GET /v1/audit/checkpoint` is unauthenticated and returns a `Signed`
- **Expected:** 200, JSON decodes as `audit.Signed`, verifies under the key from
  `/v1/audit/pubkey` (`internal/dialect/vaultkv/handler.go:136-137, 197-221`).
- **Layer:** L3. **Coverage:** GAP. `newServer`
  (`internal/dialect/vaultkv/handler_test.go:27-74`) does not set `Config.Domain`,
  so an HTTP test must set it or it will exercise AA-WIT-N12 instead.

### AA-API-02 — `GET /v1/audit/entries` requires read authority at `/`
- **Input:** (a) no token, (b) a `kv-reader` token scoped below `/`, (c) the root
  token.
- **Expected:** (a) 403 "permission denied", (b) 403 "reading audit entries needs
  read authority at /", (c) 200 with entries
  (`internal/dialect/vaultkv/handler.go:223-244`).
- **Layer:** authz. **Coverage:** GAP. The asymmetry — public checkpoint, private
  entries (`internal/dialect/vaultkv/handler.go:132-135`) — is a deliberate
  design decision with no test.

### AA-API-03 — `POST /v1/audit/witness` requires write authority at `/`
- **Expected:** 403 without it (`internal/dialect/vaultkv/handler.go:248-257`).
- **Layer:** authz. **Coverage:** GAP.

### AA-API-04 — a conflict is reported as 409 with the evidence in the body
- **Input:** a rewritten checkpoint against a witness holding an earlier head.
- **Expected:** HTTP 409, body carries `conflict` and `witnessed{count,head}`
  (`internal/dialect/vaultkv/handler.go:277-288`); a merely malformed extension
  gets 400 with `errors` and **no** `conflict` key.
- **Layer:** L4. **Coverage:** PARTIAL — `cmd/signet/audit.go:230-240` and
  `test/audit/run.sh:112-114` depend on the 409, so a regression to 400 would be
  caught indirectly; the 400-vs-409 split itself is untested.

### AA-API-05 — `AuditEntries` window semantics
- **Input:** a chain of 10; request `(after, upTo)` of `(0,0)`, `(0,10)`,
  `(5,10)`, `(9,10)`, `(10,10)`, `(12,20)`, `(5,3)`.
- **Expected:** `(0,0)` → all 10 (`upTo == 0` means "to the end",
  `internal/kernel/audit.go:54-57`); `(5,10)` → entries 6–10; `(10,10)` → empty;
  `(12,20)` → empty; `(5,3)` → empty (degenerate window, must not error or hang).
- **Layer:** L4 input. **Coverage:** GAP.

### AA-API-06 — `GET /v1/audit/witnessed?domain=` for an unknown domain
- **Expected:** 200 with `{"domain": d, "count": 0}`
  (`internal/dialect/vaultkv/handler.go:404-407`), which is what
  `cmd/signet/audit.go:195-200` relies on to decide `from = 0`.
- **Layer:** none. **Coverage:** GAP; the CLI silently treats *any* failure of
  this GET as `from = 0` (`cmd/signet/audit.go:196`), so a broken witness looks
  like a fresh one.

### AA-API-07 — `signet audit verify` exit codes
- **Input:** an intact chain, then a broken one.
- **Expected:** exit 0 with "audit chain intact"; exit non-zero with "audit chain
  FAILED" plus the "compare against a witness" advice
  (`cmd/signet/audit.go:76-88`).
- **Layer:** L1/L2. **Coverage:** COVERED for the intact case —
  `test/audit/run.sh:82-88` and `:101-107` — and for the *deliberately* intact
  rewritten case. GAP for the failing case: no acceptance test ever runs
  `audit verify` against a chain that actually breaks.

### AA-API-08 — `signet audit witness` refuses to guess when entries are needed
- **Input:** omit `-subject-token` while the witness is behind.
- **Expected:** the explicit refusal at `cmd/signet/audit.go:203-209` rather than
  a silent zero-entry request that the witness would reject with a less useful
  message.
- **Layer:** CLI. **Coverage:** GAP.

### AA-API-09 — `signet audit witnessed` exits non-zero on a conflict
- **Expected:** table printed, conflict reasons printed, exit non-zero
  (`cmd/signet/audit.go:291-309`).
- **Layer:** L4 reporting. **Coverage:** PARTIAL — `test/audit/run.sh:117` runs it
  with `|| true`, so the exit code is deliberately ignored there.

### AA-API-10 — a node that witnesses nobody says so
- **Input:** `signet audit witnessed` on a fresh node.
- **Expected:** "this node witnesses no domains" plus the "hash chain and nothing
  anchoring it" warning (`cmd/signet/audit.go:285-290`), exit 0.
- **Layer:** none — reporting. **Coverage:** GAP. It is the only signal a domain
  gets that it is unanchored, and `docs/11-operations.md:124-126` treats it as
  part of the milestone's claim.

### AA-API-11 — witnessing writes an audit entry on the witness
- **Input:** a successful witness call; compare the witness's own `AuditCount`
  before and after.
- **Expected:** +1, kind `PutWitness`, subject `witness <domain>`
  (`internal/kernel/audit.go:189-192`, `internal/kernel/apply.go:345-346`).
- **Layer:** L0. **Coverage:** GAP. Note the consequence for scheduling: a no-op
  re-witness (AA-WIT-03) still calls `storeWitness`
  (`internal/kernel/audit.go:174-180`), so a witness polled every minute grows its
  own audit chain by one entry per poll per domain forever.

---

## 11. Residual risk — what an attacker who fully controls a node can still do

These are **not gaps**. They are the honest edge of the design and should be
stated in `docs/11-operations.md` next to the attack table, which currently reads
as though the witness column closes every row.

### RR-1 — stop being witnessed (the strongest and simplest attack)
Nothing in the system requires a domain to present checkpoints on a schedule.
The witness has no notion of an expected cadence: `Witnessed.AtSec`
(`internal/audit/audit.go:123`) records when it last accepted, but nothing reads
it, no staleness threshold exists, and `signet audit witnessed`
(`cmd/signet/audit.go:291-299`) prints `DOMAIN ENTRIES STATE HEAD` with no age
column. An attacker who takes a node rewrites freely and simply never calls
`signet audit witness` again. The witness sits at "ok" indefinitely.
`docs/11-operations.md:122-124` lists scheduling as open; the security
consequence — that *absence of a conflict is not evidence of integrity* — is not
stated.

### RR-2 — forge everything after the last witnessed head
The witness verifies structure, not truth. An attacker who holds the node,
the audit key and the last witnessed head H at count N can synthesise any
entries N+1…M that chain from H, sign a checkpoint over them, and the witness
will accept them by replay (`internal/audit/audit.go:207-229`). Everything
after the last witness point is freely rewritable, forever, with no trace.
The guarantee is exactly the one stated at `internal/audit/audit.go:26-28` — a
prefix property — and nothing more. The window is the witness interval, which is
today "whenever an operator remembers" (RR-1).

### RR-3 — the audit key is on the node
`Kernel.Checkpoint` signs with the domain's own `PurposeAudit` key
(`internal/kernel/audit.go:79-92`), material the attacker holds. Key pinning
(L5) detects a *change* of key, never misuse of the real one. The wipe-and-restart
row of `docs/11-operations.md:96` is caught only because the attacker was
careless enough to lose the key; a sophisticated attacker keeps it, which is
exactly what `test/audit/run.sh:90-99` models and the reason that scenario is the
important one.

### RR-4 — a single witness is a single point of failure
There is no quorum. Take the witness as well and every conflict record can be
rewritten, since a witness's records are ordinary FSM state
(`internal/op/op.go:282-290`) protected by nothing stronger than the witness
node's own audit chain — which the same attacker now also controls.

### RR-5 — no trusted time anywhere in the evidence
`Checkpoint.AtSec` is the subject's own clock (`internal/kernel/audit.go:91`);
`Conflict.DetectedAt` and `HeadAtN.AtSec` are the witness's
(`internal/audit/audit.go:236-237`). Nothing is countersigned by a timestamp
authority, so "when did the rewrite happen" can only ever be bounded by "between
two witnessings", and only if the witness's own clock is trusted.

### RR-6 — a modified binary writes no audit at all
Every guarantee in §4 is a property of the shipped `fsm.Apply`. An attacker with
code execution on the node can apply mutations with the audit append removed;
the chain stays perfectly valid and simply omits events. Only an external
observer counting expected-vs-recorded activity, or attestation of the running
binary, would see it. This is the `Vault CVE-2025-6000` shape cited at
`docs/11-operations.md:73-75` and the design does not close it — it makes the
*result* detectable only if the attacker also needs the count to move, which they
do not.

### RR-7 — an unauthenticated, unbounded checkpoint endpoint
`GET /v1/audit/checkpoint` is public (`internal/dialect/vaultkv/handler.go:136`)
and each call walks the entire audit chain and performs an ECDSA signature
(`internal/kernel/audit.go:69-92`). On a domain with a large log this is a free
CPU amplifier for any unauthenticated caller. Similarly `AuditEntries`
(`internal/kernel/audit.go:50-61`) has no result cap, and the witness endpoint
accepts a 32 MiB body (`internal/dialect/vaultkv/handler.go:263`) that it will
replay entry by entry.

### RR-8 — cross-version chain divergence on restore
`AuditRecord` (`internal/kernel/apply.go:319-328`) is JSON-serialised into the
chain. Adding, renaming, or reordering a field — or changing any `Apply` error
string — changes the record bytes for the *same* log entry. Since restore replays
backup segments through the same `Apply` path (`internal/kernel/apply.go:17-21`),
a domain restored under a newer binary reconstructs a **different chain head** for
an identical history, and every witness holding a checkpoint over the old head
reports a rewrite. This is a self-inflicted conflict that looks exactly like an
attack. It is a design consequence, not a bug, but it needs a stated policy (Q1).

### RR-9 — the witness accepts whoever asks first for a name
Pinning is trust-on-first-use over a domain *string*. There is no binding from
the domain name in a checkpoint to the trust bundle or the PKI that would say
which key legitimately speaks for that name — `internal/trust` exists and is not
consulted by `internal/kernel/audit.go` at all.

---

## 12. Suspected live bugs

Ordered by risk. Each is a finding about existing code, not a test gap.

**(A) `signet audit init-key` does not exist.**
`internal/kernel/audit.go:80-84` tells an operator whose domain has no audit key
to run `signet audit init-key`. `cmd/signet/audit.go:43-57` dispatches only
`verify`, `checkpoint`, `witness`, `witnessed`. `Kernel.EnsureAuditKey`
(`internal/kernel/audit.go:264-274`) — which would implement it — has **no
callers anywhere in the tree**. A domain in this state (any domain created before
the audit key was added to genesis, `cmd/signet/main.go:260-272`) cannot be
checkpointed and the error tells it to run a command that does not exist.
*Reproduce:* AA-CP-09.

**(B) Witness record update is a read-modify-write outside `Apply`.**
`Kernel.Witness` reads the prior record (`internal/kernel/audit.go:131-134`),
mutates it in memory, and proposes a whole-blob overwrite
(`internal/kernel/audit.go:184-193`); `applyPutWitness`
(`internal/kernel/audit.go:254-262`) does a blind `Put` with no compare. Two
concurrent `POST /v1/audit/witness` calls for the same domain therefore race:
the later `Propose` wins and can **erase a conflict** the earlier one recorded, or
roll the witnessed head backwards. This directly contradicts the rule stated in
`internal/kernel/apply.go:22-26` — state-dependent invariants belong inside
`Apply`, where the serialized single writer makes them race-free. It is also the
one place where losing the write loses *evidence*, which
`internal/kernel/audit.go:116-119` calls the entire point of a witness.
*Reproduce:* two goroutines, one presenting a valid extension and one a rewritten
checkpoint, against the same domain.

**(C) The checkpoint key is pinned before the extension is verified, and the
record is persisted on failure.**
`internal/kernel/audit.go:145-153` sets `PinnedKey` and `First`; `Extend` runs at
line 172; the record is persisted either way at lines 178-180. Consequences:
(i) a first-contact request that fails verification still pins the key it
presented, so an attacker with write authority at `/` on a witness can
permanently poison a domain name the witness has never legitimately seen —
every later honest checkpoint trips the key-change conflict at lines 155-170;
(ii) because `Extend` only assigns `w.Domain` on the growth path
(`internal/audit/audit.go:236`), the persisted record carries `domain: ""` while
being stored under the real domain key, so `AllWitnessed` and
`signet audit witnessed` (`cmd/signet/audit.go:291-299`) show a blank row.
*Reproduce:* AA-PIN-N04, AA-PIN-N05, AA-WIT-N13.

**(D) A grant's audit record does not say who was granted, or what.**
`internal/kernel/apply.go:363-364` records `Subject = v.Scope` for `PutBinding`
and nothing else. `v.Subject` (the grantee), `v.Role`, `v.NotAfter` and the PAM
flags are all dropped. Granting `domain-admin` at `/` and granting `kv-reader` at
`/` produce identical audit records. This is the highest-value security event in
the system and the record is not sufficient to reconstruct it.
*Reproduce:* AA-REC-N01.

**(E) A session revocation records no subject.**
`internal/kernel/apply.go:375-376` sets only actor and timestamp; the token hash
is dropped entirely. You cannot tell from the audit log which session was
revoked, or how many distinct ones were.
*Reproduce:* AA-REC-N02.

**(F) An undecodable log entry is silently absent from the audit chain.**
`internal/fsm/fsm.go:47-54` returns before the transaction opens, so a committed
Raft entry that fails to decrypt or decode leaves no audit record — despite the
comment at `internal/fsm/fsm.go:58-60` promising that rejections are recorded
rather than dropped. The applied index also does not advance for it. A downgraded
binary meeting a newer `op.Kind` (`internal/op/op.go:483-485`) takes exactly this
path.
*Reproduce:* AA-ATOM-05.

**(G) `Open` ignores the `Alg` and `KeyID` a checkpoint declares.**
`internal/audit/audit.go:84-100` verifies against the caller's key and never
reads `s.Alg` or `s.KeyID`. Harmless today (the pinned key is what decides), but
it means `Signed.KeyID` is decorative and the witness's `PinnedKey` is never
cross-checked against the `kid` the subject advertises at `/v1/audit/pubkey`.
*Reproduce:* AA-CP-12.

**(H) Checkpoint `Count`/`Head` and `Index` are read in different transactions.**
`internal/kernel/audit.go:70` verifies inside one `View`; `:74` reads
`AppliedIndex` in another. On a busy node the signed `Index` can be ahead of the
`Count`. Cosmetic — the field is documented as "for operator orientation"
(`internal/audit/audit.go:54`) — but it makes the checkpoint an inconsistent
snapshot of two facts.

---

## 13. Coverage summary

| Section | Scenarios | Covered | Partial | Gap |
|---|---|---|---|---|
| §1 chain construction | 7 | 3 | 0 | 4 |
| §2 chain negatives (caught) | 8 | 3 | 0 | 5 |
| §3 chain negatives (not caught) | 5 | 2 | 0 | 3 |
| §4 atomicity | 7 | 1 | 1 | 5 |
| §5 idempotence / replay | 6 | 0 | 1 | 5 |
| §6 record content | 9 | 0 | 0 | 9 |
| §7 checkpoints | 12 | 3 | 0 | 9 |
| §8 witness protocol | 20 | 10 | 1 | 9 |
| §9 key pinning | 7 | 1 | 1 | 5 |
| §10 HTTP / CLI | 11 | 0 | 3 | 8 |
| **Total** | **92** | **23** | **7** | **62** |

Covered = 23/92 (25%); counting PARTIAL as half, effective coverage is ~29%.

The distribution is informative: the two layers with real coverage are the ones
with dedicated unit-test files (`internal/store/audit_test.go`,
`internal/audit/audit_test.go`), and both test their layer in isolation. Every
scenario that crosses a boundary — kernel over store, FSM over kernel, HTTP over
kernel — is a gap, except the ones `test/audit/run.sh` happens to walk through
end to end.

### Top 5 gaps by risk

1. **AA-CP-07** — nothing tests that `Kernel.Checkpoint` refuses to sign a chain
   that does not verify (`internal/kernel/audit.go:70-73`). A regression here
   lets a corrupted store launder itself into a validly-signed false claim that
   every witness will accept, which inverts the entire trust direction of the
   milestone.
2. **AA-ATOM-02** — nothing anywhere asserts that a rejected Op writes its audit
   record. `internal/kernel/apply_test.go:276-306` tests the state half only, and
   it calls `kernel.Apply` directly, never `AppendAudit`. The "a mutation without
   its audit record is impossible" contract (`internal/store/audit.go:80-84`) is
   untested for the rejection case, and rejected Ops are where attack attempts
   show up.
3. **AA-PIN-N04 / §12 (C)** — pinning before verification, persisted on failure.
   A live poisoning vector against any witness, plus a corrupted record shape,
   with no test in the way.
4. **AA-IDEM-01** — restart must not re-append audit entries. The version-drift
   half is guarded (`internal/fsm/fsm_test.go:79-81`); the audit half is not. A
   regression would silently double the chain on every restart, changing the head
   and putting every witness into conflict — a false positive indistinguishable
   from a real attack.
5. **AA-CHAIN-N04 / AA-CHAIN-N05** — the `Prev`-link branch of
   `VerifyAuditChain` (`internal/store/audit.go:177-181`) is reached by no test,
   and no test asserts that a fully re-chained log verifies *cleanly*. The first
   leaves the chain's core mechanism unexercised; the second is the negative
   claim the entire witness design is justified by.

---

## 14. Questions for the maintainer

**Q1 — Is the audit record format frozen?** `AuditRecord`
(`internal/kernel/apply.go:319-328`) is hashed into the chain, and restore
replays through `Apply`. Adding a field, or changing any error string returned by
any `apply*` function, changes the chain head for an identical history (RR-8).
Does the record format need the same "never reused, envelope-versioned" discipline
as `op.Kind` (`internal/op/op.go:20-27`)? If so, should `NewAuditRecord` emit a
schema version, and should restore under a newer binary be *required* to produce
the same bytes? If not, what is an operator meant to do when a restore puts every
witness into conflict?

**Q2 — How is a conflict resolved?** `internal/kernel/audit.go:139-142` says
"until that is resolved deliberately" and nothing implements resolution. Is the
intended answer (a) a new CLI verb, (b) delete the witness record out of band,
or (c) never — a conflict is terminal for that domain-witness pair? The same
question decides what a legitimate audit-key rotation costs (AA-PIN-N02): today
it is permanent, which effectively makes the audit key non-rotatable once
witnessed.

**Q3 — Should `PutWitness` be authorised inside `Apply`?** Every other
authority-bearing Op checks in `Apply` (`applyPutIssuer`,
`internal/kernel/apply.go:210-212`; `applyPutMapping`, `:248-257`).
`applyPutWitness` (`internal/kernel/audit.go:254-262`) checks nothing — the only
gate is the HTTP handler (`internal/dialect/vaultkv/handler.go:254-257`). Since
the Op is what persists and what replays, is that deliberate?

**Q4 — What is `Signed.KeyID` for?** It is set (`internal/audit/audit.go:79`),
served (`internal/dialect/vaultkv/handler.go:218`), and never checked
(§12 G). Should `Open` require `KeyID` to match the thumbprint of the key it was
handed, and should the witness store and compare it alongside `PinnedKey`?

**Q5 — Are checkpoints meant to be replayable to arbitrary witnesses?** A
`Checkpoint` names `Domain` and `Node` but no audience (`internal/audit/audit.go:45-56`).
Anyone who fetches one from the public endpoint can present it to any witness. I
believe this is intended (a checkpoint is a public statement about a public fact),
but it should be an asserted decision — AA-WIT-N14.

**Q6 — Should a witness track expected cadence?** RR-1 is, in my reading, the
largest residual risk and the cheapest to reduce: a `MaxSilenceSec` on the
witness record turning "not heard from since T" into a reportable state would
make `signet audit witnessed` mean something in the absence of an attack. Is
that in scope for the scheduling work `docs/11-operations.md:122-124` defers, or
a separate decision?

**Q7 — Is there an intended seam for fault injection in `store.Tx`?** AA-ATOM-04
(audit append fails ⇒ mutation rolls back) is the only way to test the atomicity
contract directly, and there is no way to make `AppendAudit` fail from a test
today. Would a build-tagged hook, or an interface at the `Tx` boundary, be
acceptable?

**Q8 — Is the `(term, index, seq)` audit key order guaranteed to match sequence
order?** `internal/store/audit.go:104` sorts term-major. This is equivalent to
sequence order only because Raft terms never decrease as index increases. Is
there any restore or migration path that could write an entry under a lower term
than one already present? If so, `VerifyAuditChain` would report a spurious
`AuditBreak` (AA-CHAIN-06) and it would be indistinguishable from tampering.

**Q9 — What does `Witnessed.First` mean after §12 (C)?** It is documented as
"the earliest one still held, as evidence" (`internal/audit/audit.go:129`) but is
assigned from the first *request*, verified or not
(`internal/kernel/audit.go:145-147`). Should it be assigned only on the first
successful `Extend`?

**Q10 — Should a no-op re-witness write to the log at all?** AA-API-11: the
equal-count path returns `nil` (`internal/audit/audit.go:192`) and the kernel
still proposes a `PutWitness` (`internal/kernel/audit.go:174-180`), so a polled
witness grows its own audit chain one entry per poll per domain. Under the
scheduling work in Q6 that becomes the dominant source of audit volume on a
witness node.
