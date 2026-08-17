package kernel

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/mcarey42/signet/internal/ca"
	"github.com/mcarey42/signet/internal/keys"
	"github.com/mcarey42/signet/internal/op"
	"github.com/mcarey42/signet/internal/seal"
	"github.com/mcarey42/signet/internal/store"
)

// Seal rotation moves custody of private key material from one seal to another
// — a file seal to an HSM, or one HSM key to its successor.
//
// It is a rewrap, not a re-key. Every key keeps its identity and every
// credential already issued under it stays valid, because changing who holds
// the wrapping key says nothing about the keys being wrapped. Conflating the
// two would turn a custody change into an outage.
//
// Rotation is O(number of signing keys), which is a handful. That cost is the
// deliberate price of wrapping envelopes with the seal *directly* rather than
// under an intermediate key-encryption key: an attacker who has taken over the
// running process still has to ask the device to open each key, and loses that
// ability the moment the process dies. A KEK would make rotation a single blob
// rewrite and hand that same attacker everything at once.

// SealedItem is one piece of material the seal holds.
type SealedItem struct {
	Kind     string // "key" or "ca"
	Name     string
	SealedBy string // "<seal>/<key id>", empty if unsealed
}

// SealInventory lists everything the seal is responsible for, and by which
// wrapping key. A mixed result means a rotation was interrupted.
func (k *Kernel) SealInventory(ctx context.Context) ([]SealedItem, error) {
	var out []SealedItem
	err := k.store.View(func(tx *store.Tx) error {
		if err := tx.ScanPrefix(store.BucketKeys, "", func(name string, val []byte) bool {
			// Skip the active-key pointers; they hold an id, not material.
			if len(val) == 0 || val[0] != '{' {
				return true
			}
			var key keys.Key
			if json.Unmarshal(val, &key) == nil && key.ID != "" {
				out = append(out, SealedItem{Kind: "key", Name: name, SealedBy: key.SealedBy()})
			}
			return true
		}); err != nil {
			return err
		}
		return tx.ScanPrefix(store.BucketCA, "", func(name string, val []byte) bool {
			var m ca.Material
			if json.Unmarshal(val, &m) == nil {
				out = append(out, SealedItem{Kind: "ca", Name: name, SealedBy: m.SealedBy()})
			}
			return true
		})
	})
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Name < out[j].Name
	})
	return out, err
}

// RotateSeal rewraps every piece of sealed material from one seal to another.
//
// It is idempotent and resumable: material already wrapped by the destination
// is left alone, so a ceremony interrupted halfway can simply be run again.
// Until it completes and is verified, the domain needs *both* seals — which is
// why the old one must not be destroyed until the caller has confirmed the
// result.
func (k *Kernel) RotateSeal(ctx context.Context, actor op.ID, from, to seal.Seal) (rewrapped []SealedItem, err error) {
	items, err := k.SealInventory(ctx)
	if err != nil {
		return nil, err
	}
	target := to.Name() + "/" + to.KeyID()

	for _, item := range items {
		if item.SealedBy == target {
			continue // already moved by an earlier, interrupted run
		}
		switch item.Kind {
		case "key":
			if err := k.rewrapKey(ctx, actor, item.Name, from, to); err != nil {
				return rewrapped, fmt.Errorf("rewrap key %s: %w", item.Name, err)
			}
		case "ca":
			if err := k.rewrapCA(ctx, actor, item.Name, from, to); err != nil {
				return rewrapped, fmt.Errorf("rewrap ca %s: %w", item.Name, err)
			}
		}
		rewrapped = append(rewrapped, item)
	}
	return rewrapped, nil
}

func (k *Kernel) rewrapKey(ctx context.Context, actor op.ID, name string, from, to seal.Seal) error {
	var key keys.Key
	if err := k.store.View(func(tx *store.Tx) error {
		raw, ok, err := tx.Get(store.BucketKeys, name)
		if err != nil || !ok {
			if err == nil {
				err = ErrNotFound
			}
			return err
		}
		return json.Unmarshal(raw, &key)
	}); err != nil {
		return err
	}
	moved, err := key.Rewrap(from, to)
	if err != nil {
		return err
	}
	blob, err := json.Marshal(moved)
	if err != nil {
		return err
	}
	// Rewriting the record does not disturb which key is active: the active
	// pointer holds an id, and the id has not changed.
	_, err = k.prop.Propose(ctx, &op.PutKey{
		Header: k.header(actor), ID: moved.ID, Purpose: string(moved.Purpose),
		Key: blob, Active: false, Grantor: actor,
	})
	return err
}

func (k *Kernel) rewrapCA(ctx context.Context, actor op.ID, name string, from, to seal.Seal) error {
	var m ca.Material
	if err := k.store.View(func(tx *store.Tx) error {
		raw, ok, err := tx.Get(store.BucketCA, name)
		if err != nil || !ok {
			if err == nil {
				err = ErrNotFound
			}
			return err
		}
		return json.Unmarshal(raw, &m)
	}); err != nil {
		return err
	}
	moved, err := m.Rewrap(from, to)
	if err != nil {
		return err
	}
	blob, err := json.Marshal(moved)
	if err != nil {
		return err
	}
	_, err = k.prop.Propose(ctx, &op.PutCA{
		Header: k.header(actor), Name: name, Material: blob, Grantor: actor,
	})
	return err
}

// VerifySealedMaterial opens every piece of sealed material with the given
// seal, which is how a rotation proves it finished before the old seal is
// destroyed. Opening is the only honest test: a record that merely *claims* to
// be wrapped by the new seal proves nothing.
func (k *Kernel) VerifySealedMaterial(ctx context.Context, s seal.Seal) error {
	items, err := k.SealInventory(ctx)
	if err != nil {
		return err
	}
	for _, item := range items {
		switch item.Kind {
		case "key":
			var key keys.Key
			if err := k.store.View(func(tx *store.Tx) error {
				raw, _, err := tx.Get(store.BucketKeys, item.Name)
				if err != nil {
					return err
				}
				return json.Unmarshal(raw, &key)
			}); err != nil {
				return err
			}
			if _, err := key.Signer(s); err != nil {
				return fmt.Errorf("key %s does not open under this seal: %w", item.Name, err)
			}
		case "ca":
			var m ca.Material
			if err := k.store.View(func(tx *store.Tx) error {
				raw, _, err := tx.Get(store.BucketCA, item.Name)
				if err != nil {
					return err
				}
				return json.Unmarshal(raw, &m)
			}); err != nil {
				return err
			}
			if _, err := ca.Load(m, s); err != nil {
				return fmt.Errorf("ca %s does not open under this seal: %w", item.Name, err)
			}
		}
	}
	return nil
}
