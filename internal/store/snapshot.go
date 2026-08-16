package store

import (
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
func (s *Store) RestoreRaw(data map[string]map[string][]byte) error {
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
