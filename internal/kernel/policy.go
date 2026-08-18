package kernel

import (
	"encoding/json"

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
	bs, err := LoadBindings(tx, subject)
	if err != nil {
		return false, err
	}
	var acts []Activation
	for _, b := range bs {
		if b.NotAfter != 0 && nowSec >= b.NotAfter {
			continue // expired JIT grant: simply stops being honored
		}
		if !ScopeCovers(b.Scope, path) {
			continue
		}
		if !roleGrants(b.Role, v) {
			continue
		}
		if !b.ActivationRequired {
			return true, nil
		}
		// Eligible, not holding. The authority exists but is switched off until
		// an activation says otherwise — and this is re-checked on every call,
		// so an activation expiring or being killed ends the access at the next
		// renewal without anything having to go and revoke it (docs/13).
		if acts == nil {
			var err error
			if acts, err = LoadActivations(tx, subject); err != nil {
				return false, err
			}
			if acts == nil {
				acts = []Activation{} // loaded, genuinely empty
			}
		}
		for i := range acts {
			a := &acts[i]
			if a.Binding == b.ID && a.Live(nowSec) {
				return true, nil
			}
		}
	}
	return false, nil
}
