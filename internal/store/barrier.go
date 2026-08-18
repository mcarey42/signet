package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Barrier is the at-rest encryption layer. Every value crosses it before
// touching bbolt, and Op payloads cross it before entering the Raft log — so
// the log store and every shipped backup segment inherit protection
// (docs/03).
type Barrier struct {
	aead cipher.AEAD
	key  []byte
}

const barrierInfo = "signet/barrier/v1"

// NewBarrier derives the at-rest key from the seal-held root key. Deriving
// rather than using the root directly means the same root can protect other
// things later without those uses sharing a key.
func NewBarrier(rootKey []byte) (*Barrier, error) {
	key, err := hkdf.Key(sha256.New, rootKey, nil, barrierInfo, 32)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return &Barrier{aead: aead, key: key}, nil
}

// Nonce layout. Both modes share one key, so they are domain-separated by
// their first byte: a random nonce can never collide with a derived one, rather
// than merely being unlikely to.
const (
	nonceDerived = 0x00 // byte 0 of a position-derived nonce
	nonceRandom  = 0x01 // byte 0 of a propose-time random nonce
	maxSeq       = 1<<24 - 1
)

// SealRandom encrypts with a random nonce. It is for propose-time use only
// (Op payloads), where nondeterminism is allowed and expected.
func (b *Barrier) SealRandom(plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	nonce[0] = nonceRandom
	return b.seal(nonce, plaintext, aad), nil
}

// SealDeterministic encrypts with a nonce derived from the log position of the
// entry being applied. Apply must be a pure function of (op, prior state), so
// it cannot draw randomness; deriving from the position keeps Apply
// deterministic while giving nonce uniqueness, since committed entries never
// change position and seq is unique within one entry's transaction.
//
// The derivation is a BIJECTION, not a hash. It was a truncated HMAC, which
// meant uniqueness of the nonce rested on the collision resistance of a 96-bit
// truncation — an argument, where an argument was not needed. index and seq fit
// exactly, so distinct positions now give distinct nonces by construction and
// there is nothing left to reason about.
//
// term is deliberately absent: a committed Raft entry's index identifies it
// uniquely, and an entry is only applied once committed, so term adds nothing
// to uniqueness.
//
// Returns an error rather than wrapping when seq exhausts its field. Silently
// wrapping would reuse a nonce inside a single transaction, which is precisely
// the failure this function exists to make impossible.
func (b *Barrier) SealDeterministic(index uint64, seq uint32, plaintext, aad []byte) ([]byte, error) {
	nonce, err := b.deriveNonce(index, seq)
	if err != nil {
		return nil, err
	}
	return b.seal(nonce, plaintext, aad), nil
}

func (b *Barrier) seal(nonce, plaintext, aad []byte) []byte {
	out := make([]byte, 0, len(nonce)+len(plaintext)+b.aead.Overhead())
	out = append(out, nonce...)
	return b.aead.Seal(out, nonce, plaintext, aad)
}

// Open reverses either Seal. The nonce travels with the ciphertext, so reads
// never need to know how it was chosen.
func (b *Barrier) Open(ct, aad []byte) ([]byte, error) {
	n := b.aead.NonceSize()
	if len(ct) < n {
		return nil, errors.New("barrier: ciphertext too short")
	}
	pt, err := b.aead.Open(nil, ct[:n], ct[n:], aad)
	if err != nil {
		return nil, fmt.Errorf("barrier: open: %w", err)
	}
	return pt, nil
}

// deriveNonce maps (index, seq) injectively onto the 12-byte nonce:
//
//	byte 0     domain tag (0x00 = derived)
//	bytes 1-8  index, big endian
//	bytes 9-11 seq, big endian (24 bits)
//
// A previous format derived the nonce by HMAC and is still readable, because
// the nonce travels with the ciphertext — only new writes use this layout.
func (b *Barrier) deriveNonce(index uint64, seq uint32) ([]byte, error) {
	if seq > maxSeq {
		return nil, fmt.Errorf(
			"barrier: %d writes in one log entry exceeds the %d this nonce layout can distinguish; "+
				"refusing rather than reusing a nonce", seq, maxSeq)
	}
	if index>>56 != 0 {
		return nil, fmt.Errorf("barrier: log index %d does not fit the nonce layout", index)
	}
	nonce := make([]byte, b.aead.NonceSize())
	nonce[0] = nonceDerived
	binary.BigEndian.PutUint64(nonce[1:9], index)
	nonce[9] = byte(seq >> 16)
	nonce[10] = byte(seq >> 8)
	nonce[11] = byte(seq)
	return nonce, nil
}

// aad binds a ciphertext to its location so a value cannot be moved between
// buckets or keys.
func aad(bucket, key string) []byte {
	out := make([]byte, 0, len(bucket)+len(key)+1)
	out = append(out, bucket...)
	out = append(out, 0)
	return append(out, key...)
}
