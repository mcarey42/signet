package store

import (
	"bytes"
	"encoding/binary"
	"path/filepath"

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
