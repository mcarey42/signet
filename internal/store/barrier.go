package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
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

func NewBarrier(key []byte) (*Barrier, error) {
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

// SealRandom encrypts with a random nonce. It is for propose-time use only
// (Op payloads), where nondeterminism is allowed and expected.
func (b *Barrier) SealRandom(plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return b.seal(nonce, plaintext, aad), nil
}

// SealDeterministic encrypts with a nonce derived from the log position of the
// entry being applied. Apply must be a pure function of (op, prior state), so
// it cannot draw randomness; deriving from (term, index, seq) keeps Apply
// deterministic while guaranteeing nonce uniqueness, since committed entries
// never change position and seq is unique within one entry's transaction.
func (b *Barrier) SealDeterministic(term, index uint64, seq uint32, plaintext, aad []byte) []byte {
	return b.seal(b.deriveNonce(term, index, seq), plaintext, aad)
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

func (b *Barrier) deriveNonce(term, index uint64, seq uint32) []byte {
	var msg [20]byte
	binary.BigEndian.PutUint64(msg[0:8], term)
	binary.BigEndian.PutUint64(msg[8:16], index)
	binary.BigEndian.PutUint32(msg[16:20], seq)
	mac := hmac.New(sha256.New, b.key)
	mac.Write([]byte("signet/nonce/v1"))
	mac.Write(msg[:])
	return mac.Sum(nil)[:b.aead.NonceSize()]
}

// aad binds a ciphertext to its location so a value cannot be moved between
// buckets or keys.
func aad(bucket, key string) []byte {
	out := make([]byte, 0, len(bucket)+len(key)+1)
	out = append(out, bucket...)
	out = append(out, 0)
	return append(out, key...)
}
