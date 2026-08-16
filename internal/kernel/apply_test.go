package kernel

import (
	"bytes"
	"fmt"
	"math/rand"
	"path/filepath"
	"testing"

	"github.com/mcarey/signet/internal/op"
	"github.com/mcarey/signet/internal/store"
)

func newStore(t *testing.T, keyPath string) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "state.db"), store.KeyFileSeal{Path: keyPath})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func newSealKey(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "seal.key")
	if err := store.GenerateKeyFile(p); err != nil {
		t.Fatalf("seal key: %v", err)
	}
	return p
}

// apply runs one Op at a fixed log position, the way the FSM does.
func apply(t *testing.T, s *store.Store, index uint64, o op.Op) op.Result {
	t.Helper()
	var res op.Result
	if err := s.Update(1, index, func(tx *store.Tx) error {
		res = Apply(tx, o)
		return nil
	}); err != nil {
		t.Fatalf("update: %v", err)
	}
	return res
}

func mustApply(t *testing.T, s *store.Store, index uint64, o op.Op) op.Result {
	t.Helper()
	res := apply(t, s, index, o)
	if res.Err != nil {
		t.Fatalf("apply %s: %v", o.OpKind(), res.Err)
	}
	return res
}

// bootstrap installs the root admin the way genesis does.
func bootstrap(t *testing.T, s *store.Store) op.ID {
	t.Helper()
	mustApply(t, s, 1, &op.PutPrincipal{Header: op.Header{AtSec: 1000}, ID: "root", Path: "/people/root", Type: "human"})
	mustApply(t, s, 2, &op.PutBinding{Header: op.Header{AtSec: 1000}, ID: "b-root", Subject: "root", Role: "domain-admin", Scope: "/"})
	return "root"
}

// The determinism contract: Apply is a pure function of (op, prior state), so
// replaying the same entries at the same log positions onto a fresh store —
// which is exactly what restore does — must reconstruct byte-identical state.
// This is the test that would catch a stray time.Now() or rand.Read() in Apply.
func TestApplyIsDeterministicUnderReplay(t *testing.T) {
	key := newSealKey(t)
	seq := []op.Op{
		&op.PutPrincipal{Header: op.Header{AtSec: 10}, ID: "p1", Path: "/people/root", Type: "human"},
		&op.PutBinding{Header: op.Header{AtSec: 11}, ID: "b1", Subject: "p1", Role: "domain-admin", Scope: "/"},
		&op.PutSecret{Header: op.Header{AtSec: 12}, Path: "/secrets/app", Data: map[string]string{"k": "v1"}},
		&op.PutSecret{Header: op.Header{AtSec: 13}, Path: "/secrets/app", Data: map[string]string{"k": "v2"}},
		&op.CreateSession{Header: op.Header{AtSec: 14}, ID: "s1", TokenHash: "hash1", Principal: "p1", AuthTime: 14, Expiry: 999},
	}

	run := func() map[string]map[string][]byte {
		s := newStore(t, key)
		for i, o := range seq {
			mustApply(t, s, uint64(i+1), o)
		}
		snap, err := s.SnapshotRaw()
		if err != nil {
			t.Fatalf("snapshot: %v", err)
		}
		return snap
	}

	a, b := run(), run()
	for bucket, want := range a {
		got := b[bucket]
		if len(got) != len(want) {
			t.Fatalf("bucket %s: %d keys on replay, %d originally", bucket, len(got), len(want))
		}
		for k, wv := range want {
			if !bytes.Equal(got[k], wv) {
				t.Errorf("bucket %s key %s: replay produced different bytes — Apply is not deterministic", bucket, k)
			}
		}
	}
}

// Delegation only narrows: no binding a delegated admin can write escapes the
// scope they were delegated. Randomized over the shape of the tree rather than
// asserted on a few hand-picked paths.
func TestDelegationOnlyNarrows(t *testing.T) {
	s := newStore(t, newSealKey(t))
	root := bootstrap(t, s)

	const delegated = "/clusters/lab"
	mustApply(t, s, 3, &op.PutPrincipal{Header: op.Header{AtSec: 1000}, ID: "labadmin", Path: "/people/labadmin", Type: "human"})
	mustApply(t, s, 4, &op.PutBinding{Header: op.Header{Actor: root, AtSec: 1000}, ID: "b-lab", Subject: "labadmin", Role: "domain-admin", Scope: delegated, Grantor: root})
	mustApply(t, s, 5, &op.PutPrincipal{Header: op.Header{AtSec: 1000}, ID: "victim", Path: "/people/victim", Type: "human"})

	segs := []string{"clusters", "lab", "lab-2", "svc", "apps", "secrets", "people", "a", "b"}
	rng := rand.New(rand.NewSource(20260816))
	index := uint64(10)

	for i := 0; i < 400; i++ {
		// Build a random absolute path, sometimes rooted at the delegated scope.
		var scope string
		if rng.Intn(2) == 0 {
			scope = delegated
			for n := rng.Intn(3); n > 0; n-- {
				scope += "/" + segs[rng.Intn(len(segs))]
			}
		} else {
			scope = ""
			for n := rng.Intn(4); n > 0; n-- {
				scope += "/" + segs[rng.Intn(len(segs))]
			}
			if scope == "" {
				scope = "/"
			}
		}

		index++
		res := apply(t, s, index, &op.PutBinding{
			Header:  op.Header{Actor: "labadmin", AtSec: 1000},
			ID:      op.ID(fmt.Sprintf("b-%d", i)),
			Subject: "victim", Role: "kv-admin", Scope: scope, Grantor: "labadmin",
		})

		wantAllowed := ScopeCovers(delegated, scope)
		if gotAllowed := res.Err == nil; gotAllowed != wantAllowed {
			t.Fatalf("binding at scope %q: allowed=%v, want %v (delegated at %q) err=%v",
				scope, gotAllowed, wantAllowed, delegated, res.Err)
		}
	}
}

// Bootstrap — the one binding with no grantor — is legal exactly once, while
// the domain holds no bindings at all.
func TestBootstrapIsSingleUse(t *testing.T) {
	s := newStore(t, newSealKey(t))
	bootstrap(t, s)

	mustApply(t, s, 3, &op.PutPrincipal{Header: op.Header{AtSec: 1000}, ID: "attacker", Path: "/people/attacker", Type: "human"})
	res := apply(t, s, 4, &op.PutBinding{
		Header: op.Header{AtSec: 1000}, ID: "b-evil",
		Subject: "attacker", Role: "domain-admin", Scope: "/", // no grantor
	})
	if res.Err == nil {
		t.Fatal("a second grantorless binding was accepted; bootstrap must be single-use")
	}
}

// A rejected Op must leave no partial state — this is what lets the FSM commit
// the audit record for a rejection in the same transaction.
func TestRejectedOpWritesNothing(t *testing.T) {
	s := newStore(t, newSealKey(t))
	bootstrap(t, s)
	before, err := s.SnapshotRaw()
	if err != nil {
		t.Fatal(err)
	}

	rejects := []op.Op{
		&op.PutPrincipal{Header: op.Header{AtSec: 1}, ID: "x", Path: "/People/Bad", Type: "human"},
		&op.PutPrincipal{Header: op.Header{AtSec: 1}, ID: "x", Path: "/people/ok", Type: "wombat"},
		&op.PutBinding{Header: op.Header{AtSec: 1}, ID: "b", Subject: "ghost", Role: "kv-reader", Scope: "/", Grantor: "root"},
		&op.PutBinding{Header: op.Header{AtSec: 1}, ID: "b", Subject: "root", Role: "not-a-role", Scope: "/", Grantor: "root"},
		&op.CreateSession{Header: op.Header{AtSec: 1}, ID: "s", TokenHash: "h", Principal: "ghost"},
	}
	for i, o := range rejects {
		if res := apply(t, s, uint64(100+i), o); res.Err == nil {
			t.Fatalf("%s was accepted, expected rejection", o.OpKind())
		}
	}

	after, err := s.SnapshotRaw()
	if err != nil {
		t.Fatal(err)
	}
	for bucket, w := range before {
		if len(after[bucket]) != len(w) {
			t.Errorf("bucket %s changed across rejected ops: %d keys -> %d", bucket, len(w), len(after[bucket]))
		}
	}
}

// CAS is a state-dependent invariant, so it is checked inside Apply where the
// serialized single writer makes it race-free.
func TestSecretVersioningAndCAS(t *testing.T) {
	s := newStore(t, newSealKey(t))
	bootstrap(t, s)

	if got := mustApply(t, s, 3, &op.PutSecret{Header: op.Header{AtSec: 1}, Path: "/secrets/a", Data: map[string]string{"k": "1"}}).Version; got != 1 {
		t.Fatalf("first write version = %d, want 1", got)
	}
	if got := mustApply(t, s, 4, &op.PutSecret{Header: op.Header{AtSec: 2}, Path: "/secrets/a", Data: map[string]string{"k": "2"}}).Version; got != 2 {
		t.Fatalf("second write version = %d, want 2", got)
	}

	stale := uint64(1)
	if res := apply(t, s, 5, &op.PutSecret{Header: op.Header{AtSec: 3}, Path: "/secrets/a", Data: map[string]string{"k": "3"}, CAS: &stale}); res.Err == nil {
		t.Error("stale CAS was accepted")
	}
	current := uint64(2)
	if res := apply(t, s, 6, &op.PutSecret{Header: op.Header{AtSec: 4}, Path: "/secrets/a", Data: map[string]string{"k": "3"}, CAS: &current}); res.Err != nil {
		t.Errorf("current CAS rejected: %v", res.Err)
	}
	createOnly := uint64(0)
	if res := apply(t, s, 7, &op.PutSecret{Header: op.Header{AtSec: 5}, Path: "/secrets/a", Data: map[string]string{"k": "4"}, CAS: &createOnly}); res.Err == nil {
		t.Error("cas=0 (create-only) accepted against an existing secret")
	}
}

// Authority is evaluated component-wise and honors JIT expiry.
func TestHasAuthority(t *testing.T) {
	s := newStore(t, newSealKey(t))
	root := bootstrap(t, s)
	mustApply(t, s, 3, &op.PutPrincipal{Header: op.Header{AtSec: 1000}, ID: "reader", Path: "/people/reader", Type: "service"})
	mustApply(t, s, 4, &op.PutBinding{Header: op.Header{Actor: root, AtSec: 1000}, ID: "b-r", Subject: "reader", Role: "kv-reader", Scope: "/secrets/lab", Grantor: root})
	mustApply(t, s, 5, &op.PutBinding{Header: op.Header{Actor: root, AtSec: 1000}, ID: "b-jit", Subject: "reader", Role: "kv-writer", Scope: "/secrets/jit", Grantor: root, NotAfter: 2000})

	check := func(v Verb, path string, now int64, want bool) {
		t.Helper()
		if err := s.View(func(tx *store.Tx) error {
			got, err := HasAuthority(tx, "reader", v, path, now)
			if err != nil {
				return err
			}
			if got != want {
				t.Errorf("HasAuthority(%s, %s, now=%d) = %v, want %v", v, path, now, got, want)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}

	check(VerbRead, "/secrets/lab/app", 1500, true)
	check(VerbRead, "/secrets/lab", 1500, true)
	check(VerbWrite, "/secrets/lab/app", 1500, false)  // reader cannot write
	check(VerbRead, "/secrets/lab-2/app", 1500, false) // sibling, not a child
	check(VerbRead, "/secrets", 1500, false)           // parent, not covered
	check(VerbWrite, "/secrets/jit/x", 1500, true)     // JIT grant live
	check(VerbWrite, "/secrets/jit/x", 2001, false)    // JIT grant lapsed
}
