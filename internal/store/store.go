// Package store is the persistence adapter: bbolt for state, the barrier for
// at-rest encryption, and the audit bucket. It knows nothing about principals,
// bindings, or dialects — callers hand it buckets, keys, and bytes.
package store

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Logical buckets. Keys are plaintext (range scans need them); values are
// always barrier ciphertext.
const (
	BucketPrincipals = "principals"
	BucketPathIndex  = "path_index"  // path -> principal ID
	BucketBindings   = "bindings"    // "<subjectID>/<bindingID>" -> binding
	BucketSecretMeta = "secret_meta" // path -> version history + policy
	BucketSecretData = "secret_data" // "<path>\x00<version>" -> values
	BucketSessions   = "sessions"    // token hash -> session
	BucketIssuers    = "issuers"     // name -> pinned attestation trust anchor
	BucketMappings   = "mappings"    // name -> evidence->principal rule
	BucketAudit      = "audit"       // "<term>:<index>:<seq>" -> record
	BucketCA         = "ca"          // name -> CA material
	BucketPKIRoles   = "pki_roles"   // name -> signing role
	BucketIssuance   = "issuance"    // serial -> issuance record
	BucketRolePolicy = "role_policy" // role -> security floor
	BucketKeys       = "keys"        // "<purpose>/<kid>" -> signing key
	BucketSSHRoles   = "ssh_roles"   // name -> ssh signing role
	BucketTrust      = "trust"       // domain -> root-signed trust bundle
	BucketWitness    = "witness"     // domain -> what we have witnessed of its audit chain
	BucketActivation = "activations" // "<subjectID>/<activationID>" -> PAM activation
	BucketMeta       = "meta"
)

var allBuckets = []string{
	BucketPrincipals, BucketPathIndex, BucketBindings, BucketSecretMeta, BucketSecretData,
	BucketSessions, BucketIssuers, BucketMappings,
	BucketCA, BucketPKIRoles, BucketIssuance,
	BucketRolePolicy, BucketKeys, BucketSSHRoles, BucketTrust, BucketWitness,
	BucketActivation, BucketAudit, BucketMeta,
}

var ErrReadOnly = errors.New("store: write attempted in a read-only transaction")

type Store struct {
	db *bolt.DB
	b  *Barrier
}

// Open attaches to a store, deriving the barrier from a root key the caller
// obtained from the seal. The store deliberately knows nothing about seals:
// persistence and key custody are separate concerns, and keeping them apart is
// what let a hardware seal drop in without touching this file.
func Open(path string, rootKey []byte) (*Store, error) {
	b, err := NewBarrier(rootKey)
	if err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, n := range allBuckets {
			if _, err := tx.CreateBucketIfNotExists([]byte(n)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, b: b}, nil
}

func (s *Store) Close() error      { return s.db.Close() }
func (s *Store) Barrier() *Barrier { return s.b }
func (s *Store) DB() *bolt.DB      { return s.db }

// Update runs fn in a write transaction stamped with the log position of the
// entry being applied. The position feeds deterministic nonce derivation and
// audit keys, which is why it is required rather than optional.
func (s *Store) Update(term, index uint64, fn func(*Tx) error) error {
	return s.db.Update(func(btx *bolt.Tx) error {
		return fn(&Tx{tx: btx, b: s.b, term: term, index: index, write: true})
	})
}

// View runs fn in a read transaction — a consistent snapshot, no writer
// blocking.
func (s *Store) View(fn func(*Tx) error) error {
	return s.db.View(func(btx *bolt.Tx) error {
		return fn(&Tx{tx: btx, b: s.b})
	})
}

type Tx struct {
	tx    *bolt.Tx
	b     *Barrier
	term  uint64
	index uint64
	seq   uint32
	write bool
}

func (t *Tx) Put(bucket, key string, val []byte) error {
	if !t.write {
		return ErrReadOnly
	}
	ct := t.b.SealDeterministic(t.term, t.index, t.seq, val, aad(bucket, key))
	t.seq++
	return t.tx.Bucket([]byte(bucket)).Put([]byte(key), ct)
}

func (t *Tx) Get(bucket, key string) ([]byte, bool, error) {
	ct := t.tx.Bucket([]byte(bucket)).Get([]byte(key))
	if ct == nil {
		return nil, false, nil
	}
	pt, err := t.b.Open(ct, aad(bucket, key))
	if err != nil {
		return nil, false, err
	}
	return pt, true, nil
}

func (t *Tx) Delete(bucket, key string) error {
	if !t.write {
		return ErrReadOnly
	}
	return t.tx.Bucket([]byte(bucket)).Delete([]byte(key))
}

// ScanPrefix visits every decrypted value whose key starts with prefix, in key
// order. Returning false from fn stops the scan.
func (t *Tx) ScanPrefix(bucket, prefix string, fn func(key string, val []byte) bool) error {
	c := t.tx.Bucket([]byte(bucket)).Cursor()
	p := []byte(prefix)
	for k, ct := c.Seek(p); k != nil && hasPrefix(k, p); k, ct = c.Next() {
		key := string(k)
		pt, err := t.b.Open(ct, aad(bucket, key))
		if err != nil {
			return err
		}
		if !fn(key, pt) {
			return nil
		}
	}
	return nil
}

// Position reports the log entry this transaction is applying.
func (t *Tx) Position() (term, index uint64) { return t.term, t.index }

// metaAppliedIndex records how far the log has been applied into this store.
const metaAppliedIndex = "applied_index"

// SetAppliedIndex advances the applied watermark as part of the same
// transaction as the mutation it describes.
//
// Signet's state is durable, but Raft replays committed entries from the last
// snapshot on every restart. Without a persisted watermark those entries would
// be applied a second time on top of their own results — harmless for a plain
// overwrite, wrong for anything that accumulates (a version counter, a
// balance). Apply is deterministic; this is what additionally makes it
// idempotent.
func (t *Tx) SetAppliedIndex(i uint64) error {
	return t.Put(BucketMeta, metaAppliedIndex, EncodeUint(i))
}

// AppliedIndex reports the highest log index durably applied to this store.
func (s *Store) AppliedIndex() (uint64, error) {
	var idx uint64
	err := s.View(func(tx *Tx) error {
		raw, ok, err := tx.Get(BucketMeta, metaAppliedIndex)
		if err != nil || !ok {
			return err
		}
		if len(raw) != 8 {
			return fmt.Errorf("store: applied index is %d bytes, want 8", len(raw))
		}
		idx = binary.BigEndian.Uint64(raw)
		return nil
	})
	return idx, err
}

func hasPrefix(b, prefix []byte) bool {
	if len(b) < len(prefix) {
		return false
	}
	for i := range prefix {
		if b[i] != prefix[i] {
			return false
		}
	}
	return true
}

// EncodeUint is a small helper for meta counters.
func EncodeUint(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}
