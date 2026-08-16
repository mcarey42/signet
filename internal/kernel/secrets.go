package kernel

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/mcarey42/signet/internal/op"
	"github.com/mcarey42/signet/internal/store"
)

// Secret storage keeps metadata and values apart: the version history lives in
// one record per path, each version's values in their own. Reading history
// therefore never decrypts a secret, and trimming an old version is a single
// bounded delete rather than a rewrite of everything under the path.

func secretDataKey(path string, version uint64) string {
	return fmt.Sprintf("%s\x00%020d", path, version)
}

func loadSecretMeta(tx *store.Tx, path string) (SecretMeta, bool, error) {
	var m SecretMeta
	raw, ok, err := tx.Get(store.BucketSecretMeta, path)
	if err != nil || !ok {
		return m, ok, err
	}
	return m, true, json.Unmarshal(raw, &m)
}

func saveSecretMeta(tx *store.Tx, m SecretMeta) error {
	blob, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return tx.Put(store.BucketSecretMeta, m.Path, blob)
}

func applyPutSecret(tx *store.Tx, o *op.PutSecret) op.Result {
	if err := ValidatePath(o.Path); err != nil {
		return op.Result{Err: err}
	}
	m, existed, err := loadSecretMeta(tx, o.Path)
	if err != nil {
		return op.Result{Err: err}
	}
	if !existed {
		m = SecretMeta{
			Path: o.Path, CreatedSec: o.AtSec,
			MaxVersions: DefaultMaxVersions,
			Versions:    map[uint64]VersionMeta{},
		}
	}
	if m.Versions == nil {
		m.Versions = map[uint64]VersionMeta{}
	}
	// Check-and-set is a state-dependent invariant, so it is decided here — in
	// the serialized writer — where two concurrent proposals cannot both pass.
	if m.CASRequired && o.CAS == nil {
		return op.Result{Err: errors.New("check-and-set parameter required for this call")}
	}
	if o.CAS != nil && *o.CAS != m.CurrentVersion {
		return op.Result{Err: errors.New("check-and-set parameter did not match the current version")}
	}

	next := m.CurrentVersion + 1
	blob, err := json.Marshal(o.Data)
	if err != nil {
		return op.Result{Err: err}
	}
	if err := tx.Put(store.BucketSecretData, secretDataKey(o.Path, next), blob); err != nil {
		return op.Result{Err: err}
	}
	m.Versions[next] = VersionMeta{CreatedSec: o.AtSec}
	m.CurrentVersion = next
	m.UpdatedSec = o.AtSec
	if m.OldestVersion == 0 {
		m.OldestVersion = next
	}

	// Trim history to MaxVersions. Trimming destroys — the value is gone, not
	// merely hidden — so it is recorded that way.
	if m.MaxVersions > 0 {
		for uint32(len(liveVersions(m))) > m.MaxVersions {
			oldest := lowestVersion(m)
			if oldest == 0 {
				break
			}
			if err := tx.Delete(store.BucketSecretData, secretDataKey(o.Path, oldest)); err != nil {
				return op.Result{Err: err}
			}
			delete(m.Versions, oldest)
			m.OldestVersion = lowestVersion(m)
		}
	}
	if err := saveSecretMeta(tx, m); err != nil {
		return op.Result{Err: err}
	}
	return op.Result{Version: next}
}

func applyVersionAction(tx *store.Tx, o *op.VersionAction) op.Result {
	if err := ValidatePath(o.Path); err != nil {
		return op.Result{Err: err}
	}
	m, ok, err := loadSecretMeta(tx, o.Path)
	if err != nil {
		return op.Result{Err: err}
	}
	if !ok {
		return op.Result{Err: ErrNotFound}
	}
	versions := o.Versions
	if len(versions) == 0 {
		versions = []uint64{m.CurrentVersion}
	}
	for _, v := range versions {
		vm, ok := m.Versions[v]
		if !ok {
			continue // a version that no longer exists needs no action
		}
		switch o.Mode {
		case op.VersionDelete:
			vm.DeletionSec = o.AtSec
		case op.VersionUndelete:
			// Destruction is final; only soft deletion can be undone.
			if vm.Destroyed {
				continue
			}
			vm.DeletionSec = 0
		case op.VersionDestroy:
			vm.Destroyed = true
			if err := tx.Delete(store.BucketSecretData, secretDataKey(o.Path, v)); err != nil {
				return op.Result{Err: err}
			}
		default:
			return op.Result{Err: fmt.Errorf("unknown version action %q", o.Mode)}
		}
		m.Versions[v] = vm
	}
	m.UpdatedSec = o.AtSec
	if err := saveSecretMeta(tx, m); err != nil {
		return op.Result{Err: err}
	}
	return op.Result{Version: m.CurrentVersion}
}

func applyDestroySecret(tx *store.Tx, o *op.DestroySecret) op.Result {
	if err := ValidatePath(o.Path); err != nil {
		return op.Result{Err: err}
	}
	m, ok, err := loadSecretMeta(tx, o.Path)
	if err != nil {
		return op.Result{Err: err}
	}
	if !ok {
		return op.Result{} // already gone; deleting twice is not an error
	}
	for v := range m.Versions {
		if err := tx.Delete(store.BucketSecretData, secretDataKey(o.Path, v)); err != nil {
			return op.Result{Err: err}
		}
	}
	if err := tx.Delete(store.BucketSecretMeta, o.Path); err != nil {
		return op.Result{Err: err}
	}
	return op.Result{}
}

func applyPutSecretMeta(tx *store.Tx, o *op.PutSecretMeta) op.Result {
	if err := ValidatePath(o.Path); err != nil {
		return op.Result{Err: err}
	}
	m, existed, err := loadSecretMeta(tx, o.Path)
	if err != nil {
		return op.Result{Err: err}
	}
	if !existed {
		// Vault allows metadata to precede any value, so policy can be set
		// before a secret is first written.
		m = SecretMeta{Path: o.Path, CreatedSec: o.AtSec, MaxVersions: DefaultMaxVersions, Versions: map[uint64]VersionMeta{}}
	}
	if o.CustomMetadata != nil {
		m.CustomMetadata = o.CustomMetadata
	}
	if o.MaxVersions > 0 {
		m.MaxVersions = o.MaxVersions
	}
	m.CASRequired = o.CASRequired
	m.UpdatedSec = o.AtSec
	if err := saveSecretMeta(tx, m); err != nil {
		return op.Result{Err: err}
	}
	return op.Result{Version: m.CurrentVersion}
}

func liveVersions(m SecretMeta) []uint64 {
	out := make([]uint64, 0, len(m.Versions))
	for v := range m.Versions {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func lowestVersion(m SecretMeta) uint64 {
	var lowest uint64
	for v := range m.Versions {
		if lowest == 0 || v < lowest {
			lowest = v
		}
	}
	return lowest
}

// listChildren returns the immediate children of a prefix, directories marked
// with a trailing slash — the shape every Vault client expects from a list.
func listChildren(tx *store.Tx, prefix string) ([]string, error) {
	if prefix != "/" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	seen := map[string]bool{}
	var keys []string
	err := tx.ScanPrefix(store.BucketSecretMeta, prefix, func(key string, _ []byte) bool {
		rest := strings.TrimPrefix(key, prefix)
		if rest == "" {
			return true
		}
		if i := strings.Index(rest, "/"); i >= 0 {
			rest = rest[:i+1] // a directory
		}
		if !seen[rest] {
			seen[rest] = true
			keys = append(keys, rest)
		}
		return true
	})
	sort.Strings(keys)
	return keys, err
}

// jsonUnmarshal keeps the test helpers from importing encoding/json directly.
func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
