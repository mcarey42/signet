package kernel

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/mcarey42/signet/internal/seal"

	"github.com/mcarey42/signet/internal/op"
	"github.com/mcarey42/signet/internal/store"
)

// Benchmarks for the authorization path, which is on every request and is
// therefore the system's latency floor.
//
// The question these answer is whether the "RBAC tree walk" needs to become
// cleverer — an index, a cache — or whether it is already far below the noise
// floor of a network round trip. Measuring first is the point: a cache over an
// authorization decision is a correctness hazard (docs/13 says every renewal
// re-evaluates policy), so it should only be built if the numbers demand it.

// benchSeal/benchRootKey mirror the test helpers but take testing.TB so the
// benchmarks can share them.
func benchRootKey(tb testing.TB) []byte {
	tb.Helper()
	p := filepath.Join(tb.TempDir(), "seal.key")
	if err := seal.GenerateKeyFile(p); err != nil {
		tb.Fatal(err)
	}
	sl, err := seal.OpenFile(p)
	if err != nil {
		tb.Fatal(err)
	}
	root, err := seal.LoadOrCreateRootKey(sl, tb.TempDir())
	if err != nil {
		tb.Fatal(err)
	}
	return root
}

func jsonMarshalB(v any) ([]byte, error) { return json.Marshal(v) }

func benchStore(b *testing.B, bindings int, activationRequired bool) (*store.Store, op.ID) {
	b.Helper()
	root := benchRootKey(b)
	s, err := store.Open(b.TempDir()+"/state.db", root)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { s.Close() })

	subject := op.ID("subject-under-test")
	if err := s.Update(1, 1, func(tx *store.Tx) error {
		for i := 0; i < bindings; i++ {
			bd := Binding{
				ID: op.ID(fmt.Sprintf("b-%04d", i)), Subject: subject,
				Role: "kv-reader", Scope: fmt.Sprintf("/secrets/tenant-%04d", i),
				ActivationRequired: activationRequired,
			}
			blob, err := jsonMarshalB(bd)
			if err != nil {
				return err
			}
			if err := tx.Put(store.BucketBindings, bindingKey(subject, bd.ID), blob); err != nil {
				return err
			}
			if activationRequired {
				a := Activation{
					ID: op.ID(fmt.Sprintf("a-%04d", i)), Subject: subject, Binding: bd.ID,
					Role: bd.Role, Scope: bd.Scope, State: ActivationActive, Expiry: 1 << 40,
				}
				ablob, err := jsonMarshalB(a)
				if err != nil {
					return err
				}
				if err := tx.Put(store.BucketActivation, activationKey(subject, a.ID), ablob); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		b.Fatal(err)
	}
	return s, subject
}

// The realistic shape: a principal with a handful of grants, asking about a
// path the LAST one covers (worst case within that set).
func BenchmarkHasAuthority(b *testing.B) {
	for _, n := range []int{1, 8, 64, 512} {
		b.Run(fmt.Sprintf("bindings=%d", n), func(b *testing.B) {
			s, subject := benchStore(b, n, false)
			path := fmt.Sprintf("/secrets/tenant-%04d/app", n-1)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := s.View(func(tx *store.Tx) error {
					ok, err := HasAuthority(tx, subject, VerbRead, path, 1000)
					if err != nil || !ok {
						b.Fatalf("ok=%v err=%v", ok, err)
					}
					return nil
				}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// A denial walks every binding without short-circuiting, so it is the true
// worst case — and denials are common, which makes this the number that
// matters for a system under attack.
func BenchmarkHasAuthorityDenied(b *testing.B) {
	for _, n := range []int{8, 64, 512} {
		b.Run(fmt.Sprintf("bindings=%d", n), func(b *testing.B) {
			s, subject := benchStore(b, n, false)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := s.View(func(tx *store.Tx) error {
					ok, err := HasAuthority(tx, subject, VerbRead, "/nowhere/at/all", 1000)
					if err != nil || ok {
						b.Fatalf("expected denial: ok=%v err=%v", ok, err)
					}
					return nil
				}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// PAM adds a second scan, only for bindings that require activation.
func BenchmarkHasAuthorityWithActivations(b *testing.B) {
	for _, n := range []int{8, 64} {
		b.Run(fmt.Sprintf("bindings=%d", n), func(b *testing.B) {
			s, subject := benchStore(b, n, true)
			path := fmt.Sprintf("/secrets/tenant-%04d/app", n-1)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := s.View(func(tx *store.Tx) error {
					ok, err := HasAuthority(tx, subject, VerbRead, path, 1000)
					if err != nil || !ok {
						b.Fatalf("ok=%v err=%v", ok, err)
					}
					return nil
				}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// Concurrency: bbolt readers do not block each other, so this should scale with
// cores. If it does not, the read path is serializing somewhere it should not
// be — which is exactly the question worth answering before adding machinery.
func BenchmarkHasAuthorityParallel(b *testing.B) {
	s, subject := benchStore(b, 64, false)
	path := "/secrets/tenant-0063/app"
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := s.View(func(tx *store.Tx) error {
				ok, err := HasAuthority(tx, subject, VerbRead, path, 1000)
				if err != nil || !ok {
					return fmt.Errorf("ok=%v err=%v", ok, err)
				}
				return nil
			}); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// ScopeCovers on its own, with no storage in the way: the pure algebra.
func BenchmarkScopeCovers(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if !ScopeCovers("/secrets/tenant/app", "/secrets/tenant/app/sub/deep/deeper") {
			b.Fatal("expected coverage")
		}
	}
}

// A sanity check that concurrent readers see consistent results, run under
// -race. Correctness under concurrency is a precondition for caring about its
// speed.
func TestHasAuthorityIsSafeUnderConcurrency(t *testing.T) {
	s := newStoreWithRoot(t, benchRootKey(t))
	subject := op.ID("s1")
	if err := s.Update(1, 1, func(tx *store.Tx) error {
		bd := Binding{ID: "b1", Subject: subject, Role: "kv-reader", Scope: "/secrets"}
		blob, _ := jsonMarshalB(bd)
		return tx.Put(store.BucketBindings, bindingKey(subject, bd.ID), blob)
	}); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if err := s.View(func(tx *store.Tx) error {
					ok, err := HasAuthority(tx, subject, VerbRead, "/secrets/x", 1000)
					if err != nil {
						return err
					}
					if !ok {
						return fmt.Errorf("denied a grant that should hold")
					}
					return nil
				}); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// The same store, but asking about the FIRST binding's path. Paired with
// BenchmarkHasAuthority (which asks about the last) this brackets the range:
// early exit makes the cost proportional to where the match is, not to how much
// authority the principal holds.
func BenchmarkHasAuthorityFirstMatch(b *testing.B) {
	for _, n := range []int{64, 512} {
		b.Run(fmt.Sprintf("bindings=%d", n), func(b *testing.B) {
			s, subject := benchStore(b, n, false)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := s.View(func(tx *store.Tx) error {
					ok, err := HasAuthority(tx, subject, VerbRead, "/secrets/tenant-0000/app", 1000)
					if err != nil || !ok {
						b.Fatalf("ok=%v err=%v", ok, err)
					}
					return nil
				}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// Where the per-binding cost actually goes. Guessing between "decryption" and
// "JSON" would send any optimization in a direction the data may not support.
func BenchmarkBindingDecode(b *testing.B) {
	bd := Binding{
		ID: "b-0001", Subject: "subject-under-test", Role: "kv-reader",
		Scope: "/secrets/tenant-0001", Grantor: "grantor-id",
	}
	blob, err := jsonMarshalB(bd)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("json-unmarshal", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var out Binding
			if json.Unmarshal(blob, &out) != nil {
				b.Fatal("unmarshal")
			}
		}
	})
	b.Run("store-roundtrip", func(b *testing.B) {
		s, subject := benchStore(b, 1, false)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := s.View(func(tx *store.Tx) error {
				_, _, err := tx.Get(store.BucketBindings, bindingKey(subject, "b-0000"))
				return err
			}); err != nil {
				b.Fatal(err)
			}
		}
	})
}
