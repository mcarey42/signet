package store

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"

	bolt "go.etcd.io/bbolt"
	"testing"
)

// The nonce derivation is a bijection, not a hash.
//
// It used to be a truncated HMAC, which made uniqueness a collision-resistance
// argument over 96 bits. It did not need to be an argument: index and seq fit
// exactly, so distinct positions give distinct nonces by construction.
func TestDerivedNoncesAreInjective(t *testing.T) {
	b := testBarrier(t)
	seen := map[string][2]uint64{}
	for _, index := range []uint64{0, 1, 2, 255, 256, 1 << 20, 1<<56 - 1} {
		for _, seq := range []uint32{0, 1, 2, 255, 1 << 16, maxSeq} {
			n, err := b.deriveNonce(index, seq)
			if err != nil {
				t.Fatalf("index=%d seq=%d: %v", index, seq, err)
			}
			k := string(n)
			if prev, dup := seen[k]; dup {
				t.Fatalf("nonce collision: (%d,%d) and (%d,%d) both give %x",
					prev[0], prev[1], index, seq, n)
			}
			seen[k] = [2]uint64{index, uint64(seq)}

			// And it is genuinely the position, recoverable from the nonce.
			if got := binary.BigEndian.Uint64(n[1:9]); got != index {
				t.Fatalf("index not recoverable: got %d want %d", got, index)
			}
		}
	}
}

// A random nonce can never collide with a derived one — they are separated by
// construction rather than by probability.
func TestRandomAndDerivedNoncesCannotCollide(t *testing.T) {
	b := testBarrier(t)
	derived, err := b.deriveNonce(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ {
		ct, err := b.SealRandom([]byte("x"), nil)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(ct[:12], derived) {
			t.Fatal("a random nonce collided with a derived one")
		}
		if ct[0] != nonceRandom {
			t.Fatalf("random nonces must carry their domain tag, got %#x", ct[0])
		}
	}
}

// Exhausting seq must refuse rather than wrap, since wrapping would reuse a
// nonce inside one transaction.
func TestSeqOverflowIsRefused(t *testing.T) {
	b := testBarrier(t)
	if _, err := b.deriveNonce(1, maxSeq+1); err == nil {
		t.Fatal("seq overflow silently wrapped instead of refusing")
	}
}

// The high-water mark stops a replay over durable state EVEN IF the encrypted
// applied-index watermark is deleted outright.
//
// This is the case that defeated the first fix: AppliedIndex returns (0, nil)
// for an ABSENT key, so deleting it reset the guard and let the whole log
// replay — re-deriving every nonce against different plaintext. The mark is
// plaintext and separate precisely so losing the thing it guards does not lose
// it too.
func TestSealHighWaterMarkSurvivesLosingTheAppliedIndex(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 7)
	}
	path := filepath.Join(dir, "state.db")

	s, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 5; i++ {
		if err := s.Update(1, uint64(i), func(tx *Tx) error {
			if err := tx.Put(BucketSecretData, "app", []byte("value-original")); err != nil {
				return err
			}
			return tx.SetAppliedIndex(uint64(i))
		}); err != nil {
			t.Fatal(err)
		}
	}

	// The attacker deletes the encrypted watermark — one key, no barrier
	// access needed.
	if err := s.DB().Update(func(btx *bolt.Tx) error {
		return btx.Bucket([]byte(BucketMeta)).Delete([]byte(metaAppliedIndex))
	}); err != nil {
		t.Fatal(err)
	}
	if idx, err := s.AppliedIndex(); err != nil || idx != 0 {
		t.Fatalf("precondition: a deleted watermark should read as 0, got %d (%v)", idx, err)
	}

	// Replaying entry 1 with DIFFERENT plaintext would reuse nonce (1, n).
	err = s.Update(1, 1, func(tx *Tx) error {
		return tx.Put(BucketSecretData, "app", []byte("value-attacker"))
	})
	if err == nil {
		t.Fatal("the log replayed over durable state: nonce reuse was possible")
	}
	s.Close()
}

func testBarrier(t *testing.T) *Barrier {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 3)
	}
	b, err := NewBarrier(key)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A snapshot from another domain must be refused BEFORE anything is destroyed.
//
// RestoreRaw wiped every bucket and then wrote the incoming values, so a
// foreign snapshot — one sealed under a different barrier — left the node with
// neither its old state nor readable new state. Bricked, permanently, by a
// recovery attempt. Recovery is when a system must be at its most careful:
// whoever is running it has already had one bad day.
func TestForeignSnapshotIsRefusedBeforeDestroyingAnything(t *testing.T) {
	mine := openStoreWithKey(t, 11)
	theirs := openStoreWithKey(t, 99)

	// Both domains hold a secret at the same path.
	if err := mine.Update(1, 1, func(tx *Tx) error {
		return tx.Put(BucketSecretData, "app", []byte("mine-original"))
	}); err != nil {
		t.Fatal(err)
	}
	if err := theirs.Update(1, 1, func(tx *Tx) error {
		return tx.Put(BucketSecretData, "app", []byte("theirs"))
	}); err != nil {
		t.Fatal(err)
	}
	foreign, err := theirs.SnapshotRaw()
	if err != nil {
		t.Fatal(err)
	}

	if err := mine.RestoreRaw(foreign); err == nil {
		t.Fatal("a snapshot from another domain was restored")
	}

	// And the original state is untouched, which is the property that matters.
	if err := mine.View(func(tx *Tx) error {
		got, ok, err := tx.Get(BucketSecretData, "app")
		if err != nil {
			return err
		}
		if !ok || string(got) != "mine-original" {
			t.Fatalf("the store was damaged by a refused restore: ok=%v got=%q", ok, got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// A snapshot from THIS domain still restores, or the check would be useless.
func TestOwnSnapshotStillRestores(t *testing.T) {
	s := openStoreWithKey(t, 11)
	if err := s.Update(1, 1, func(tx *Tx) error {
		return tx.Put(BucketSecretData, "app", []byte("v1"))
	}); err != nil {
		t.Fatal(err)
	}
	snap, err := s.SnapshotRaw()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Update(1, 2, func(tx *Tx) error {
		return tx.Put(BucketSecretData, "app", []byte("v2"))
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.RestoreRaw(snap); err != nil {
		t.Fatalf("a snapshot of this domain must restore: %v", err)
	}
	if err := s.View(func(tx *Tx) error {
		got, _, err := tx.Get(BucketSecretData, "app")
		if err != nil {
			return err
		}
		if string(got) != "v1" {
			t.Fatalf("restore did not take effect: %q", got)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func openStoreWithKey(t *testing.T, seed byte) *Store {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = seed + byte(i)
	}
	s, err := Open(filepath.Join(t.TempDir(), "state.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// A bbolt file shorter than its own header says must be refused, not handed to
// bbolt.
//
// bbolt trusts the page count in its meta page and memory-maps accordingly, so
// a file shorter than that faults on the first freelist read: SIGSEGV, fatal
// error, no recover() possible and no deferred handler. Every command against
// the directory died the same way, INCLUDING the diagnostics an operator would
// reach for.
//
// The check is deliberately NARROW. bbolt over-allocates, so a file can be
// meaningfully shorter than its full length and still open cleanly — and
// refusing a file bbolt would have handled is a false positive that stops a
// healthy node, which is worse than the crash it would prevent. So this asserts
// the boundary precisely: one byte below the header's own requirement is
// refused, exactly at it is accepted.
func TestBoltFileShorterThanItsHeaderIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 5)
	}
	s, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 20; i++ {
		if err := s.Update(1, uint64(i), func(tx *Tx) error {
			return tx.Put(BucketSecretData, "k", make([]byte, 4096))
		}); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()

	if err := CheckBoltFile(path); err != nil {
		t.Fatalf("a healthy file was rejected — a false positive here stops a good node: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	needed := boltRequiredSize(t, raw)
	if needed <= 0 || needed > int64(len(raw)) {
		t.Fatalf("could not derive the required size (%d of %d)", needed, len(raw))
	}

	atBoundary := filepath.Join(dir, "at.db")
	if err := os.WriteFile(atBoundary, raw[:needed], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckBoltFile(atBoundary); err != nil {
		t.Errorf("a file exactly as long as its header requires was refused: %v", err)
	}

	below := filepath.Join(dir, "below.db")
	if err := os.WriteFile(below, raw[:needed-1], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckBoltFile(below); err == nil {
		t.Error("a file one byte shorter than its header requires was accepted; opening it would fault")
	}
}

// boltRequiredSize reads the meta page the same way CheckBoltFile does, so the
// test pins the boundary rather than restating the arithmetic.
func boltRequiredSize(t *testing.T, raw []byte) int64 {
	t.Helper()
	m := raw[boltPageHeader:]
	if binary.LittleEndian.Uint32(m[0:4]) != boltMagic {
		t.Fatal("test fixture is not a bbolt file")
	}
	pageSize := int64(binary.LittleEndian.Uint32(m[8:12]))
	return int64(binary.LittleEndian.Uint64(m[40:48])) * pageSize
}

// A file that is not a bbolt database at all is refused with a different, and
// more useful, message than "truncated".
func TestNonBoltFileIsRefused(t *testing.T) {
	p := filepath.Join(t.TempDir(), "not-a-db")
	if err := os.WriteFile(p, []byte("this is a text file, not a database at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := CheckBoltFile(p)
	if err == nil {
		t.Fatal("a non-database file was accepted")
	}
	if !strings.Contains(err.Error(), "does not look like a bbolt database") {
		t.Fatalf("expected a not-a-database message, got: %v", err)
	}
}
