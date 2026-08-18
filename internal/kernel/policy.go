package kernel

import (
	"encoding/json"

	"github.com/mcarey42/signet/internal/metrics"
	"github.com/mcarey42/signet/internal/op"
	"github.com/mcarey42/signet/internal/store"
)

// LoadBindings returns every binding held by a subject. Bindings are keyed
// "<subjectID>/<bindingID>" so this is a prefix scan, not a table scan.
//
// Groups are deferred (docs/15), so a subject is always a principal today;
// when groups arrive, resolution expands here and stays flat at issuance.
func LoadBindings(tx *store.Tx, subject op.ID) ([]Binding, error) {
	var out []Binding
	err := tx.ScanPrefix(store.BucketBindings, string(subject)+"/", func(_ string, val []byte) bool {
		var b Binding
		if json.Unmarshal(val, &b) == nil {
			out = append(out, b)
		}
		return true
	})
	return out, err
}

// HasAuthority reports whether subject may exercise verb at path as of nowSec.
//
// This is a pure function over an in-memory view of the subject's bindings —
// deliberately not a query language — so it is equally callable from Apply
// (where determinism is mandatory, using the Op's timestamp) and from the
// service methods (using the leader's clock).
func HasAuthority(tx *store.Tx, subject op.ID, v Verb, path string, nowSec int64) (bool, error) {
	// This is on the path of every request, so it is measured: the duration
	// alone would say something got slower without saying why, and the scan
	// counts are what separate "this principal has many grants" from a
	// regression in the walk itself.
	defer metrics.Time(metrics.AuthzDuration)()
	allowed := false
	scanned := 0
	defer func() {
		metrics.AuthzBindingsScanned.Observe(float64(scanned))
		if allowed {
			metrics.AuthzAllowed.Inc()
		} else {
			metrics.AuthzDenied.Inc()
		}
	}()

	// Streamed rather than materialized. Every stored binding is individually
	// encrypted, so loading them all costs one AES-GCM open and one JSON
	// unmarshal each — measured at ~1.4µs per binding, which a principal with
	// hundreds of grants pays on EVERY request. Stopping at the first grant
	// that answers the question makes the common case proportional to where the
	// match is rather than to how much authority the principal holds.
	//
	// A denial is still O(n): to say no you genuinely must look at everything.
	var (
		acts     []Activation
		actsErr  error
		haveActs bool
	)
	err := tx.ScanPrefix(store.BucketBindings, string(subject)+"/", func(_ string, val []byte) bool {
		scanned++
		var b Binding
		if json.Unmarshal(val, &b) != nil {
			return true
		}
		if b.NotAfter != 0 && nowSec >= b.NotAfter {
			return true // expired JIT grant: simply stops being honored
		}
		if !ScopeCovers(b.Scope, path) || !roleGrants(b.Role, v) {
			return true
		}
		if !b.ActivationRequired {
			allowed = true
			return false
		}
		// Eligible, not holding. The authority exists but is switched off until
		// an activation says otherwise — and this is re-checked on every call,
		// so an activation expiring or being killed ends the access at the next
		// renewal without anything having to go and revoke it (docs/13).
		//
		// Activations are loaded at most once, and only if some binding
		// actually requires one, so domains that use no PAM pay nothing.
		if !haveActs {
			acts, actsErr = LoadActivations(tx, subject)
			haveActs = true
			if actsErr != nil {
				return false
			}
			metrics.AuthzActivationsScanned.Observe(float64(len(acts)))
		}
		for i := range acts {
			a := &acts[i]
			if a.Binding == b.ID && a.Live(nowSec) {
				allowed = true
				return false
			}
		}
		return true
	})
	if err != nil {
		return false, err
	}
	if actsErr != nil {
		return false, actsErr
	}
	return allowed, nil
}
