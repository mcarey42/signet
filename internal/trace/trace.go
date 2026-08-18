// Package trace is diagnostic tracing that is inert until switched on.
//
// The purpose is narrow and specific: an operator hits something we cannot
// reproduce, turns tracing on, reproduces it, and sends us the log. Everything
// here follows from that one sentence.
//
// # It must be safe to send
//
// A trace from an identity and secrets authority is worthless if nobody dares
// share it. So this package cannot emit secret values, tokens, private keys,
// or the contents of anything sealed — not "tries not to", cannot: the only
// way to record a sensitive value is through Redact, which stores a salted
// digest rather than the value.
//
// The salt is per-process and random, so digests correlate WITHIN one trace —
// you can see that the same token appeared in three requests — and are useless
// across traces or against a guessed value. That is the property that makes a
// trace both diagnostic and safe: it preserves relationships without
// preserving contents.
//
// Paths and identifiers are a judgement call rather than an absolute. A secret
// PATH is not the secret, and without it most traces would be unreadable — so
// paths are recorded, and the doc for `signet trace` says so plainly, because
// an operator deciding whether to send a file deserves to know what is in it
// rather than to be reassured.
//
// # It must cost nothing when off
//
// The check is one atomic load. When tracing is off there is no formatting, no
// allocation, and no evaluation of the arguments — hence the closure form of
// Do, which is not called at all in the common case.
package trace

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Area names a subsystem, so an operator can trace the part that is
// misbehaving instead of everything.
type Area string

const (
	AreaAuthz   Area = "authz"   // authorization decisions
	AreaApply   Area = "apply"   // consensus and state machine
	AreaStore   Area = "store"   // transactions and sealing
	AreaSeal    Area = "seal"    // seal and key custody operations
	AreaHTTP    Area = "http"    // request routing and outcomes
	AreaTrust   Area = "trust"   // bundles, anchors, verification
	AreaAudit   Area = "audit"   // chain, checkpoints, witnessing
	AreaPAM     Area = "pam"     // activation lifecycle
	AreaAttest  Area = "attest"  // login and evidence verification
	AreaDialect Area = "dialect" // per-protocol serialization
)

// AllAreas is the set "all" expands to.
var AllAreas = []Area{
	AreaAuthz, AreaApply, AreaStore, AreaSeal, AreaHTTP,
	AreaTrust, AreaAudit, AreaPAM, AreaAttest, AreaDialect,
}

type tracer struct {
	mu      sync.Mutex
	w       io.Writer
	closer  io.Closer
	enabled atomic.Uint64 // bitmask of areas
	salt    []byte
	seq     atomic.Uint64
	started time.Time
}

var global = &tracer{}

// areaBit maps an area to its bit. Stable ordering matters only within a run.
func areaBit(a Area) uint64 {
	for i, known := range AllAreas {
		if known == a {
			return 1 << uint(i)
		}
	}
	return 0
}

// On reports whether an area is being traced. One atomic load.
func On(a Area) bool { return global.enabled.Load()&areaBit(a) != 0 }

// Start begins tracing the given areas to w. Passing no areas traces all.
func Start(w io.Writer, closer io.Closer, areas ...Area) error {
	if len(areas) == 0 {
		areas = AllAreas
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	global.mu.Lock()
	global.w, global.closer, global.salt, global.started = w, closer, salt, time.Now()
	global.mu.Unlock()

	var mask uint64
	names := make([]string, 0, len(areas))
	for _, a := range areas {
		mask |= areaBit(a)
		names = append(names, string(a))
	}
	global.enabled.Store(mask)

	Do(AreaHTTP, "trace.start", func(e *Event) {
		e.Str("areas", strings.Join(names, ","))
		e.Str("note", "values are redacted to salted digests; the salt is per-process")
	})
	return nil
}

// Stop ends tracing and closes the sink.
func Stop() {
	global.enabled.Store(0)
	global.mu.Lock()
	defer global.mu.Unlock()
	if global.closer != nil {
		_ = global.closer.Close()
	}
	global.w, global.closer, global.salt = nil, nil, nil
}

// Event is one traced moment. Fields are added fluently and written once.
type Event struct {
	fields []field
}

type field struct {
	k string
	v any
}

func (e *Event) Str(k, v string) *Event       { e.fields = append(e.fields, field{k, v}); return e }
func (e *Event) Int(k string, v int64) *Event { e.fields = append(e.fields, field{k, v}); return e }
func (e *Event) Bool(k string, v bool) *Event { e.fields = append(e.fields, field{k, v}); return e }
func (e *Event) Dur(k string, d time.Duration) *Event {
	e.fields = append(e.fields, field{k, d.String()})
	return e
}

// Err records an error, or nothing if there is none.
func (e *Event) Err(err error) *Event {
	if err != nil {
		e.fields = append(e.fields, field{"error", err.Error()})
	}
	return e
}

// Redact records a SENSITIVE value as a salted digest.
//
// The value never reaches the log. Equal values produce equal digests within
// one trace, so a reader can follow one token or one key through a sequence
// without ever learning what it was.
func (e *Event) Redact(k string, v []byte) *Event {
	e.fields = append(e.fields, field{k, Digest(v)})
	return e
}

// Digest is the redaction primitive: a salted, truncated HMAC.
func Digest(v []byte) string {
	global.mu.Lock()
	salt := global.salt
	global.mu.Unlock()
	if salt == nil {
		return "redacted"
	}
	m := hmac.New(sha256.New, salt)
	m.Write(v)
	return "r:" + base64.RawURLEncoding.EncodeToString(m.Sum(nil)[:9])
}

// Do emits an event if the area is being traced.
//
// The closure is not called when tracing is off, so building the event costs
// nothing in the common case — which is what lets these be left in hot paths
// like the authorization decision.
func Do(a Area, what string, build func(*Event)) {
	if !On(a) {
		return
	}
	e := &Event{}
	if build != nil {
		build(e)
	}
	global.emit(a, what, e)
}

func (t *tracer) emit(a Area, what string, e *Event) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.w == nil {
		return
	}
	rec := make(map[string]any, len(e.fields)+4)
	for _, f := range e.fields {
		rec[f.k] = f.v
	}
	rec["n"] = t.seq.Add(1)
	rec["t"] = time.Since(t.started).Round(time.Microsecond).String()
	rec["area"] = string(a)
	rec["what"] = what

	blob, err := json.Marshal(rec)
	if err != nil {
		fmt.Fprintf(t.w, `{"area":%q,"what":"trace.encode_failed"}`+"\n", a)
		return
	}
	t.w.Write(append(blob, '\n'))
}

// ParseAreas turns a comma-separated list into areas, rejecting unknown names
// rather than silently tracing less than was asked for.
func ParseAreas(s string) ([]Area, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "all" {
		return AllAreas, nil
	}
	var out []Area
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if areaBit(Area(part)) == 0 {
			return nil, fmt.Errorf(
				"trace: unknown area %q — known areas are %s, or \"all\"", part, joinAreas())
		}
		out = append(out, Area(part))
	}
	if len(out) == 0 {
		return AllAreas, nil
	}
	return out, nil
}

func joinAreas() string {
	names := make([]string, len(AllAreas))
	for i, a := range AllAreas {
		names[i] = string(a)
	}
	return strings.Join(names, ", ")
}

// StartFile opens a trace file, refusing to overwrite one.
func StartFile(path string, areas ...Area) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf(
			"trace: %w — refusing to overwrite an existing trace, since the one already there may "+
				"be the evidence somebody wanted", err)
	}
	return Start(f, f, areas...)
}
