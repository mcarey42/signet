package store

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// These tests act as an attacker who holds the node: they open the store with
// its own barrier key and edit it directly. That is the right adversary — a
// tamper-evidence claim that only survives an attacker without the keys would
// not be worth making.

func openTestStore(t *testing.T) *Store {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	s, err := Open(filepath.Join(t.TempDir(), "state.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// appendN writes n audit records, each in its own transaction, as the FSM does.
func appendN(t *testing.T, s *Store, n int) {
	t.Helper()
	for i := 1; i <= n; i++ {
		rec, _ := json.Marshal(map[string]any{"kind": "PutSecret", "subject": "/secrets/app", "seq": i})
		if err := s.Update(1, uint64(i), func(tx *Tx) error {
			return tx.AppendAudit(rec)
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func verify(t *testing.T, s *Store) (uint64, string, error) {
	t.Helper()
	var count uint64
	var head string
	var vErr error
	if err := s.View(func(tx *Tx) error {
		count, head, vErr = tx.VerifyAuditChain()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return count, head, vErr
}

func TestChainVerifiesAndIsDeterministic(t *testing.T) {
	a, b := openTestStore(t), openTestStore(t)
	appendN(t, a, 5)
	appendN(t, b, 5)

	ca, ha, err := verify(t, a)
	if err != nil {
		t.Fatalf("chain should verify: %v", err)
	}
	if ca != 5 {
		t.Fatalf("expected 5 entries, got %d", ca)
	}
	// Two independent stores fed identical records must arrive at the identical
	// head, or replicas could not agree on what their own history was.
	_, hb, err := verify(t, b)
	if err != nil {
		t.Fatal(err)
	}
	if ha != hb {
		t.Fatalf("identical inputs produced different heads:\n  %s\n  %s", ha, hb)
	}
}

// Editing a record in place must break the chain at that entry.
func TestEditedRecordIsDetected(t *testing.T) {
	s := openTestStore(t)
	appendN(t, s, 5)

	// Rewrite entry 3's record — the classic "make that grant disappear" edit —
	// keeping its hash and links so only the record itself is wrong.
	var targetKey string
	if err := s.View(func(tx *Tx) error {
		return tx.ScanAudit(func(key string, e AuditEntry) bool {
			if e.Seq == 3 {
				targetKey = key
				return false
			}
			return true
		})
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Update(9, 99, func(tx *Tx) error {
		raw, _, err := tx.Get(BucketAudit, targetKey)
		if err != nil {
			return err
		}
		var e AuditEntry
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		e.Record = json.RawMessage(`{"kind":"PutSecret","subject":"/secrets/innocuous","seq":3}`)
		blob, _ := json.Marshal(e)
		return tx.Put(BucketAudit, targetKey, blob)
	}); err != nil {
		t.Fatal(err)
	}

	_, _, err := verify(t, s)
	if err == nil {
		t.Fatal("an edited audit record went undetected")
	}
	brk, ok := err.(*AuditBreak)
	if !ok {
		t.Fatalf("expected an AuditBreak, got %T: %v", err, err)
	}
	if brk.Seq != 3 {
		t.Fatalf("the break should point at entry 3, got %d", brk.Seq)
	}
	if !strings.Contains(brk.Reason, "record was altered") {
		t.Fatalf("unhelpful reason: %s", brk.Reason)
	}
}

// Removing an entry from the middle must break the chain.
func TestRemovedEntryIsDetected(t *testing.T) {
	s := openTestStore(t)
	appendN(t, s, 5)

	var targetKey string
	if err := s.View(func(tx *Tx) error {
		return tx.ScanAudit(func(key string, e AuditEntry) bool {
			if e.Seq == 3 {
				targetKey = key
				return false
			}
			return true
		})
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Update(9, 99, func(tx *Tx) error {
		return tx.Delete(BucketAudit, targetKey)
	}); err != nil {
		t.Fatal(err)
	}

	_, _, err := verify(t, s)
	if err == nil {
		t.Fatal("a removed audit record went undetected")
	}
	// Entry 4 now sits where 3 should be, so the sequence check fires first.
	brk := err.(*AuditBreak)
	if brk.Seq != 3 {
		t.Fatalf("the break should point at the gap (entry 3), got %d", brk.Seq)
	}
}

// Truncation is the case a hash chain CANNOT catch on its own: what remains is
// a valid chain. Only the recorded count reveals it locally, and an attacker
// who can delete entries can edit that too — which is precisely why checkpoints
// are witnessed off the node (internal/audit).
func TestTruncationLeavesAValidChain(t *testing.T) {
	s := openTestStore(t)
	appendN(t, s, 5)

	var lastTwo []string
	if err := s.View(func(tx *Tx) error {
		return tx.ScanAudit(func(key string, e AuditEntry) bool {
			if e.Seq >= 4 {
				lastTwo = append(lastTwo, key)
			}
			return true
		})
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Update(9, 99, func(tx *Tx) error {
		for _, k := range lastTwo {
			if err := tx.Delete(BucketAudit, k); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	count, _, err := verify(t, s)
	if err != nil {
		t.Fatalf("a truncated chain is still internally consistent, so it should verify: %v", err)
	}
	if count != 3 {
		t.Fatalf("expected 3 surviving entries, got %d", count)
	}
	// The recorded count still says 5. That mismatch is the only local trace.
	var claimed uint64
	if err := s.View(func(tx *Tx) error {
		var e error
		claimed, e = tx.AuditCount()
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if claimed != 5 {
		t.Fatalf("the recorded count should still be 5, got %d", claimed)
	}
}

// Appending after tampering must not repair the chain.
func TestChainDoesNotHealAfterTampering(t *testing.T) {
	s := openTestStore(t)
	appendN(t, s, 3)
	var key string
	if err := s.View(func(tx *Tx) error {
		return tx.ScanAudit(func(k string, e AuditEntry) bool {
			if e.Seq == 2 {
				key = k
				return false
			}
			return true
		})
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Update(9, 98, func(tx *Tx) error {
		raw, _, _ := tx.Get(BucketAudit, key)
		var e AuditEntry
		_ = json.Unmarshal(raw, &e)
		e.Record = json.RawMessage(`{"tampered":true}`)
		blob, _ := json.Marshal(e)
		return tx.Put(BucketAudit, key, blob)
	}); err != nil {
		t.Fatal(err)
	}
	appendN(t, s, 2) // keep writing as if nothing happened

	if _, _, err := verify(t, s); err == nil {
		t.Fatal("later entries repaired a broken chain")
	}
}

// The hash must bind the previous hash and the record unambiguously, so that
// shifting the boundary between them cannot produce a collision.
func TestChainHashIsUnambiguous(t *testing.T) {
	a := ChainHash("sha256:AB", []byte("CD"))
	b := ChainHash("sha256:A", []byte("BCD"))
	if a == b {
		t.Fatal("hashing is ambiguous: two different (prev, record) pairs collide")
	}
	if ChainHash("x", []byte("y")) != ChainHash("x", []byte("y")) {
		t.Fatal("hashing is not deterministic")
	}
}
