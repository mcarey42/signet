package store

import (
	"errors"
	"fmt"
	"sort"

	bolt "go.etcd.io/bbolt"
)

// Snapshot and restore move values in their sealed form. Ciphertext is copied
// verbatim, so snapshots and the backup segments built from them inherit the
// barrier without a second encryption pass — and a snapshot is as inert as the
// store it came from.

// SnapshotRaw copies every bucket's ciphertext under a single read transaction.
func (s *Store) SnapshotRaw() (map[string]map[string][]byte, error) {
	out := make(map[string]map[string][]byte, len(allBuckets))
	err := s.db.View(func(tx *bolt.Tx) error {
		for _, name := range allBuckets {
			b := tx.Bucket([]byte(name))
			if b == nil {
				continue
			}
			m := make(map[string][]byte)
			if err := b.ForEach(func(k, v []byte) error {
				cp := make([]byte, len(v))
				copy(cp, v)
				m[string(k)] = cp
				return nil
			}); err != nil {
				return err
			}
			out[name] = m
		}
		return nil
	})
	return out, err
}

// RestoreRaw replaces all state with the contents of a snapshot. It is
// destructive by design: Raft calls it when this node's log has diverged or
// been truncated away, and partial state would be worse than none.
//
// The snapshot is checked BEFORE anything is destroyed. Values travel in their
// sealed form, so a snapshot from a different domain — or from the same domain
// before a root-key change — is undecryptable here. Restoring it used to wipe
// the store first and discover that afterwards, leaving a node with neither its
// old state nor usable new state: bricked, permanently, by a recovery attempt.
// Recovery is exactly when a system must be at its most careful, since whoever
// is running it has already had one bad day.
func (s *Store) RestoreRaw(data map[string]map[string][]byte) error {
	if unknown := UnknownBuckets(data); len(unknown) > 0 {
		return fmt.Errorf(
			"store: refusing to restore a snapshot containing buckets this build does not know: %v. "+
				"They would be silently dropped and the node would come up looking healthy with "+
				"state missing. This snapshot is probably from a newer Signet", unknown)
	}
	if err := s.validateSnapshot(data); err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		for _, name := range allBuckets {
			if tx.Bucket([]byte(name)) != nil {
				if err := tx.DeleteBucket([]byte(name)); err != nil {
					return err
				}
			}
			b, err := tx.CreateBucket([]byte(name))
			if err != nil {
				return err
			}
			for k, v := range data[name] {
				if err := b.Put([]byte(k), v); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// validateSnapshot confirms the incoming state belongs to this barrier, by
// opening a value from it.
//
// One successful decryption is proof enough: the barrier key is domain-wide, so
// a snapshot with one openable value is one whose values are all openable by
// construction. An empty snapshot is accepted — there is nothing to be wrong
// about, and refusing would block the legitimate restore of a fresh domain.
func (s *Store) validateSnapshot(data map[string]map[string][]byte) error {
	// An EMPTY snapshot must not be able to wipe a populated store.
	//
	// The decryption check below cannot catch this: an empty snapshot has no
	// values to disagree about, so it passed and the wipe proceeded. `null`
	// decodes to a nil map and erased every bucket. A snapshot legitimately
	// covering an empty domain exists only before that domain has ever been
	// written, which the seal high-water mark records.
	if snapshotIsEmpty(data) {
		_, everWritten, err := s.SealHighWaterMark()
		if err != nil {
			return err
		}
		if everWritten {
			return errors.New(
				"store: refusing to restore an empty snapshot over a store that has been written " +
					"to. An empty snapshot describes a domain with no history; this one has some, " +
					"and restoring would erase it")
		}
		return nil
	}

	var tried int
	// Prefer the applied-index watermark: every non-empty store has one, and it
	// is small and cheap to open.
	if v, ok := data[BucketMeta][metaAppliedIndex]; ok {
		if _, err := s.b.Open(v, aad(BucketMeta, metaAppliedIndex)); err == nil {
			return nil
		}
		tried++
	}
	// Otherwise take any encrypted value at all. The meta bucket is skipped
	// because the seal high-water mark lives there in PLAINTEXT and would not
	// prove anything about the barrier.
	for _, bucket := range allBuckets {
		if bucket == BucketMeta {
			continue
		}
		for k, v := range data[bucket] {
			if _, err := s.b.Open(v, aad(bucket, k)); err == nil {
				return nil
			}
			tried++
			if tried > 8 {
				break
			}
		}
		if tried > 8 {
			break
		}
	}
	if tried == 0 {
		return nil // nothing sealed in it; nothing to disagree with
	}
	return fmt.Errorf(
		"store: refusing to restore this snapshot — none of its values decrypt under this "+
			"domain's barrier (tried %d). It belongs to a different domain, or to this one before "+
			"its root key changed. Restoring would destroy the state already here and replace it "+
			"with state this node cannot read", tried)
}

func snapshotIsEmpty(data map[string]map[string][]byte) bool {
	for _, b := range data {
		if len(b) > 0 {
			return false
		}
	}
	return true
}

// UnknownBuckets reports buckets in a snapshot this build does not know about.
//
// RestoreRaw only copies buckets it knows, so an unknown one was silently
// dropped — which means restoring a snapshot from a NEWER Signet would quietly
// discard whatever that version added, and the node would come up looking fine
// with state missing. Better to refuse and say which.
func UnknownBuckets(data map[string]map[string][]byte) []string {
	known := make(map[string]bool, len(allBuckets))
	for _, b := range allBuckets {
		known[b] = true
	}
	var out []string
	for name, contents := range data {
		if !known[name] && len(contents) > 0 {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
