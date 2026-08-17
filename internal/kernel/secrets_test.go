package kernel

import (
	"testing"

	"github.com/mcarey42/signet/internal/op"
	"github.com/mcarey42/signet/internal/store"
)

func readVersion(t *testing.T, s *store.Store, path string, version uint64) (map[string]string, bool) {
	t.Helper()
	var (
		data  map[string]string
		found bool
	)
	if err := s.View(func(tx *store.Tx) error {
		m, ok, err := loadSecretMeta(tx, path)
		if err != nil || !ok {
			return err
		}
		if version == 0 {
			version = m.CurrentVersion
		}
		vm, ok := m.Versions[version]
		if !ok || !vm.Readable() {
			return nil
		}
		raw, ok, err := tx.Get(store.BucketSecretData, secretDataKey(path, version))
		if err != nil || !ok {
			return err
		}
		found = true
		return jsonUnmarshal(raw, &data)
	}); err != nil {
		t.Fatal(err)
	}
	return data, found
}

func meta(t *testing.T, s *store.Store, path string) SecretMeta {
	t.Helper()
	var m SecretMeta
	if err := s.View(func(tx *store.Tx) error {
		var err error
		m, _, err = loadSecretMeta(tx, path)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestSecretVersionHistory(t *testing.T) {
	s := newStore(t, newSeal(t))
	bootstrap(t, s)
	const p = "/secrets/app"

	for i, val := range []string{"v1", "v2", "v3"} {
		res := mustApply(t, s, uint64(10+i), &op.PutSecret{
			Header: op.Header{AtSec: int64(100 + i)}, Path: p, Data: map[string]string{"k": val},
		})
		if res.Version != uint64(i+1) {
			t.Fatalf("write %d produced version %d", i+1, res.Version)
		}
	}

	// Every version is independently readable — that is the point of history.
	for v, want := range map[uint64]string{1: "v1", 2: "v2", 3: "v3"} {
		got, ok := readVersion(t, s, p, v)
		if !ok || got["k"] != want {
			t.Errorf("version %d = %v (found=%v), want %q", v, got, ok, want)
		}
	}
	if got, _ := readVersion(t, s, p, 0); got["k"] != "v3" {
		t.Errorf("current version = %v, want v3", got)
	}
	if m := meta(t, s, p); m.CurrentVersion != 3 || m.OldestVersion != 1 {
		t.Errorf("meta current=%d oldest=%d, want 3/1", m.CurrentVersion, m.OldestVersion)
	}
}

// Soft delete hides a version and can be undone; destroy erases the data and
// cannot. The distinction is the whole reason both exist.
func TestSoftDeleteIsReversibleAndDestroyIsNot(t *testing.T) {
	s := newStore(t, newSeal(t))
	bootstrap(t, s)
	const p = "/secrets/app"
	mustApply(t, s, 10, &op.PutSecret{Header: op.Header{AtSec: 100}, Path: p, Data: map[string]string{"k": "v1"}})
	mustApply(t, s, 11, &op.PutSecret{Header: op.Header{AtSec: 101}, Path: p, Data: map[string]string{"k": "v2"}})

	mustApply(t, s, 12, &op.VersionAction{Header: op.Header{AtSec: 102}, Path: p, Versions: []uint64{1}, Mode: op.VersionDelete})
	if _, ok := readVersion(t, s, p, 1); ok {
		t.Error("a soft-deleted version is still readable")
	}
	mustApply(t, s, 13, &op.VersionAction{Header: op.Header{AtSec: 103}, Path: p, Versions: []uint64{1}, Mode: op.VersionUndelete})
	if got, ok := readVersion(t, s, p, 1); !ok || got["k"] != "v1" {
		t.Error("undelete did not restore the version")
	}

	mustApply(t, s, 14, &op.VersionAction{Header: op.Header{AtSec: 104}, Path: p, Versions: []uint64{1}, Mode: op.VersionDestroy})
	if _, ok := readVersion(t, s, p, 1); ok {
		t.Error("a destroyed version is still readable")
	}
	// Undelete must not resurrect destroyed data — the bytes are gone.
	mustApply(t, s, 15, &op.VersionAction{Header: op.Header{AtSec: 105}, Path: p, Versions: []uint64{1}, Mode: op.VersionUndelete})
	if _, ok := readVersion(t, s, p, 1); ok {
		t.Error("undelete resurrected a destroyed version")
	}
	if m := meta(t, s, p); !m.Versions[1].Destroyed {
		t.Error("destroyed flag not recorded")
	}

	// The current version is untouched by all of this.
	if got, ok := readVersion(t, s, p, 0); !ok || got["k"] != "v2" {
		t.Error("the current version was affected by operations on version 1")
	}
}

// An empty version list means "the current version" — the shape a plain DELETE
// on the data path takes.
func TestDeleteLatestDefaultsToCurrentVersion(t *testing.T) {
	s := newStore(t, newSeal(t))
	bootstrap(t, s)
	const p = "/secrets/app"
	mustApply(t, s, 10, &op.PutSecret{Header: op.Header{AtSec: 100}, Path: p, Data: map[string]string{"k": "v1"}})
	mustApply(t, s, 11, &op.PutSecret{Header: op.Header{AtSec: 101}, Path: p, Data: map[string]string{"k": "v2"}})
	mustApply(t, s, 12, &op.VersionAction{Header: op.Header{AtSec: 102}, Path: p, Mode: op.VersionDelete})

	if _, ok := readVersion(t, s, p, 2); ok {
		t.Error("the current version was not deleted")
	}
	if got, ok := readVersion(t, s, p, 1); !ok || got["k"] != "v1" {
		t.Error("an older version was affected")
	}
}

// History is bounded: past max_versions the oldest data is dropped, so a secret
// cannot grow without limit just by being rewritten.
func TestMaxVersionsTrimsOldest(t *testing.T) {
	s := newStore(t, newSeal(t))
	bootstrap(t, s)
	const p = "/secrets/app"
	mustApply(t, s, 10, &op.PutSecretMeta{Header: op.Header{AtSec: 100}, Path: p, MaxVersions: 3})
	for i := 0; i < 5; i++ {
		mustApply(t, s, uint64(20+i), &op.PutSecret{Header: op.Header{AtSec: int64(101 + i)}, Path: p, Data: map[string]string{"n": string(rune('a' + i))}})
	}

	m := meta(t, s, p)
	if len(m.Versions) != 3 {
		t.Fatalf("kept %d versions, want 3", len(m.Versions))
	}
	if m.CurrentVersion != 5 || m.OldestVersion != 3 {
		t.Errorf("current=%d oldest=%d, want 5/3", m.CurrentVersion, m.OldestVersion)
	}
	if _, ok := readVersion(t, s, p, 1); ok {
		t.Error("a trimmed version is still readable")
	}
	if _, ok := readVersion(t, s, p, 5); !ok {
		t.Error("the current version was trimmed")
	}
}

func TestDestroySecretRemovesEverything(t *testing.T) {
	s := newStore(t, newSeal(t))
	bootstrap(t, s)
	const p = "/secrets/app"
	mustApply(t, s, 10, &op.PutSecret{Header: op.Header{AtSec: 100}, Path: p, Data: map[string]string{"k": "v1"}})
	mustApply(t, s, 11, &op.PutSecret{Header: op.Header{AtSec: 101}, Path: p, Data: map[string]string{"k": "v2"}})
	mustApply(t, s, 12, &op.DestroySecret{Header: op.Header{AtSec: 102}, Path: p})

	if m := meta(t, s, p); m.Path != "" {
		t.Error("metadata survived a destroy")
	}
	if err := s.View(func(tx *store.Tx) error {
		return tx.ScanPrefix(store.BucketSecretData, p, func(key string, _ []byte) bool {
			t.Errorf("version data survived a destroy: %q", key)
			return false
		})
	}); err != nil {
		t.Fatal(err)
	}
	// Destroying an absent secret is not an error: the caller's intent is met.
	if res := apply(t, s, 13, &op.DestroySecret{Header: op.Header{AtSec: 103}, Path: p}); res.Err != nil {
		t.Errorf("destroying an absent secret errored: %v", res.Err)
	}
}

func TestCASRequiredForcesCallersToDeclareIntent(t *testing.T) {
	s := newStore(t, newSeal(t))
	bootstrap(t, s)
	const p = "/secrets/app"
	mustApply(t, s, 10, &op.PutSecretMeta{Header: op.Header{AtSec: 100}, Path: p, CASRequired: true})

	if res := apply(t, s, 11, &op.PutSecret{Header: op.Header{AtSec: 101}, Path: p, Data: map[string]string{"k": "v"}}); res.Err == nil {
		t.Error("a blind write was accepted where check-and-set is required")
	}
	zero := uint64(0)
	if res := apply(t, s, 12, &op.PutSecret{Header: op.Header{AtSec: 102}, Path: p, Data: map[string]string{"k": "v"}, CAS: &zero}); res.Err != nil {
		t.Errorf("create-only write rejected: %v", res.Err)
	}
}

func TestListReturnsImmediateChildren(t *testing.T) {
	s := newStore(t, newSeal(t))
	bootstrap(t, s)
	for i, p := range []string{
		"/secrets/cluster-svc/apps/litellm",
		"/secrets/cluster-svc/apps/grafana",
		"/secrets/cluster-svc/platform/harbor",
		"/secrets/cluster-lab/apps/thing",
	} {
		mustApply(t, s, uint64(10+i), &op.PutSecret{Header: op.Header{AtSec: 100}, Path: p, Data: map[string]string{"k": "v"}})
	}

	var keys []string
	if err := s.View(func(tx *store.Tx) error {
		var err error
		keys, err = listChildren(tx, "/secrets/cluster-svc")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// Directories carry a trailing slash; siblings outside the prefix are absent.
	want := map[string]bool{"apps/": true, "platform/": true}
	if len(keys) != len(want) {
		t.Fatalf("keys = %v, want %v", keys, want)
	}
	for _, k := range keys {
		if !want[k] {
			t.Errorf("unexpected key %q", k)
		}
	}

	if err := s.View(func(tx *store.Tx) error {
		var err error
		keys, err = listChildren(tx, "/secrets/cluster-svc/apps")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0] != "grafana" || keys[1] != "litellm" {
		t.Errorf("leaf listing = %v, want [grafana litellm]", keys)
	}
}
