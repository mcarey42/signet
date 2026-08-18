// Package metrics is a dependency-free Prometheus exposition.
//
// The project's dependency budget is deliberate (docs/09), and a metrics client
// library would be a large one for what amounts to atomic counters and a text
// serializer. So this is hand-rolled — about 200 lines, no allocation on the
// hot path, and no third-party code in the request path of an authority server.
//
// # Cost discipline
//
// Everything here must be cheap enough to leave switched on. Counters and
// histogram buckets are plain atomic int64s; observing a value is a bucket
// search and two atomic adds, with no locking and no allocation. Registration
// takes a mutex, but that happens once at startup.
//
// # Cardinality discipline
//
// Labels are fixed at registration. Nothing here lets a *request* invent a
// label value, because that is how a metrics endpoint becomes a memory leak
// with a remote trigger: a secret path per series, one series per path, and an
// attacker who can create paths.
package metrics

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// Registry holds every metric a process exposes.
type Registry struct {
	mu      sync.RWMutex
	metrics []metric
}

type metric interface {
	write(w io.Writer)
	name() string
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{} }

// Default is the process-wide registry.
var Default = NewRegistry()

func (r *Registry) register(m metric) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.metrics = append(r.metrics, m)
}

// WriteTo renders the registry in Prometheus text exposition format.
func (r *Registry) WriteTo(w io.Writer) {
	r.mu.RLock()
	ms := make([]metric, len(r.metrics))
	copy(ms, r.metrics)
	r.mu.RUnlock()
	sort.Slice(ms, func(i, j int) bool { return ms[i].name() < ms[j].name() })
	for _, m := range ms {
		m.write(w)
	}
}

// --- counters -------------------------------------------------------------

// Counter is a monotonically increasing value.
type Counter struct {
	n      atomic.Int64
	nm     string
	help   string
	labels string
}

// NewCounter registers a counter. Labels are fixed here, never per-observation.
func NewCounter(r *Registry, name, help string, labels ...string) *Counter {
	c := &Counter{nm: name, help: help, labels: formatLabels(labels)}
	r.register(c)
	return c
}

func (c *Counter) Inc()         { c.n.Add(1) }
func (c *Counter) Add(v int64)  { c.n.Add(v) }
func (c *Counter) Value() int64 { return c.n.Load() }
func (c *Counter) name() string { return c.nm }
func (c *Counter) write(w io.Writer) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s%s %d\n",
		c.nm, c.help, c.nm, c.nm, c.labels, c.n.Load())
}

// --- gauges ---------------------------------------------------------------

// Gauge is a value that goes up and down.
type Gauge struct {
	n      atomic.Int64
	nm     string
	help   string
	labels string
}

func NewGauge(r *Registry, name, help string, labels ...string) *Gauge {
	g := &Gauge{nm: name, help: help, labels: formatLabels(labels)}
	r.register(g)
	return g
}

func (g *Gauge) Set(v int64)  { g.n.Store(v) }
func (g *Gauge) Inc()         { g.n.Add(1) }
func (g *Gauge) Dec()         { g.n.Add(-1) }
func (g *Gauge) name() string { return g.nm }
func (g *Gauge) write(w io.Writer) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s%s %d\n",
		g.nm, g.help, g.nm, g.nm, g.labels, g.n.Load())
}

// --- histograms -----------------------------------------------------------

// DefaultBuckets spans the range this system actually operates in: an
// authorization decision should land in the tens of microseconds, a local
// request in single-digit milliseconds, and anything past a second is a
// pathology worth seeing distinctly rather than lumped into +Inf.
var DefaultBuckets = []float64{
	0.000_010, 0.000_025, 0.000_050, 0.000_100, 0.000_250, 0.000_500,
	0.001, 0.0025, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500,
	1.0, 2.5, 5.0, 10.0,
}

// Histogram counts observations into fixed buckets.
type Histogram struct {
	buckets []float64
	counts  []atomic.Int64
	sum     atomic.Uint64 // float64 bits, added via CAS
	total   atomic.Int64
	nm      string
	help    string
	labels  string
}

func NewHistogram(r *Registry, name, help string, buckets []float64, labels ...string) *Histogram {
	if len(buckets) == 0 {
		buckets = DefaultBuckets
	}
	h := &Histogram{
		buckets: buckets, counts: make([]atomic.Int64, len(buckets)),
		nm: name, help: help, labels: formatLabels(labels),
	}
	r.register(h)
	return h
}

// Observe records one value, in seconds. Allocation-free.
func (h *Histogram) Observe(v float64) {
	// Linear search: the bucket list is short and cache-resident, which beats
	// a binary search's branches at this size.
	for i, b := range h.buckets {
		if v <= b {
			h.counts[i].Add(1)
			break
		}
	}
	h.total.Add(1)
	for {
		old := h.sum.Load()
		nw := float64frombits(old) + v
		if h.sum.CompareAndSwap(old, float64bits(nw)) {
			return
		}
	}
}

func (h *Histogram) name() string { return h.nm }

func (h *Histogram) write(w io.Writer) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s histogram\n", h.nm, h.help, h.nm)
	var cum int64
	for i, b := range h.buckets {
		cum += h.counts[i].Load()
		fmt.Fprintf(w, "%s_bucket%s %d\n", h.nm, withLabel(h.labels, "le", formatFloat(b)), cum)
	}
	total := h.total.Load()
	fmt.Fprintf(w, "%s_bucket%s %d\n", h.nm, withLabel(h.labels, "le", "+Inf"), total)
	fmt.Fprintf(w, "%s_sum%s %g\n%s_count%s %d\n",
		h.nm, h.labels, float64frombits(h.sum.Load()), h.nm, h.labels, total)
}

// Count and Sum expose totals for tests and for the CLI's own reporting.
func (h *Histogram) Count() int64 { return h.total.Load() }
func (h *Histogram) Sum() float64 { return float64frombits(h.sum.Load()) }

// Quantile estimates a quantile from the bucket counts.
//
// It is an estimate by construction — bucket boundaries are the only
// resolution available — so it reports the bucket's upper bound, which is an
// upper bound on the true value rather than an interpolation that would look
// more precise than the data supports.
func (h *Histogram) Quantile(q float64) float64 {
	total := h.total.Load()
	if total == 0 {
		return 0
	}
	want := int64(float64(total) * q)
	var cum int64
	for i, b := range h.buckets {
		cum += h.counts[i].Load()
		if cum >= want {
			return b
		}
	}
	return h.buckets[len(h.buckets)-1]
}

// --- label helpers --------------------------------------------------------

func formatLabels(kv []string) string {
	if len(kv) == 0 {
		return ""
	}
	if len(kv)%2 != 0 {
		kv = append(kv, "")
	}
	var b strings.Builder
	b.WriteByte('{')
	for i := 0; i < len(kv); i += 2 {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%s=%q", kv[i], kv[i+1])
	}
	b.WriteByte('}')
	return b.String()
}

func withLabel(existing, k, v string) string {
	if existing == "" {
		return fmt.Sprintf("{%s=%q}", k, v)
	}
	return existing[:len(existing)-1] + fmt.Sprintf(",%s=%q}", k, v)
}

func formatFloat(f float64) string { return strconv.FormatFloat(f, 'g', -1, 64) }

// The histogram sum lives in an atomic word, so it is stored as its bit
// pattern and updated by compare-and-swap.
func float64bits(f float64) uint64     { return math.Float64bits(f) }
func float64frombits(b uint64) float64 { return math.Float64frombits(b) }
