package metrics

import (
	"net/http"
	"sync"
	"time"
)

// The metrics Signet actually exposes.
//
// Chosen to answer specific operational questions rather than to be
// comprehensive: how long an authorization decision takes and how much work it
// does, where request latency goes, and how much of it is consensus rather than
// anything we control. A metric nobody would act on is a metric not worth the
// line of code on the hot path.

var (
	// AuthzDuration is the cost of one authorization decision — the "RBAC tree
	// walk". This is the number to watch: it is on the path of every single
	// request, so its tail latency is the system's floor.
	AuthzDuration = NewHistogram(Default, "signet_authz_duration_seconds",
		"Time to reach one authorization decision.", nil)

	// AuthzBindingsScanned records how many bindings a decision had to decrypt
	// and examine. Paired with the duration it separates "slow because the
	// principal has many grants" from "slow for some other reason" — without
	// it, a latency regression tells you nothing about its cause.
	AuthzBindingsScanned = NewHistogram(Default, "signet_authz_bindings_scanned",
		"Bindings examined per authorization decision.",
		[]float64{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024})

	// AuthzActivationsScanned is the same for PAM activations, which are only
	// loaded when a binding requires activation.
	AuthzActivationsScanned = NewHistogram(Default, "signet_authz_activations_scanned",
		"Activations examined per authorization decision.",
		[]float64{1, 2, 4, 8, 16, 32, 64, 128})

	AuthzAllowed = NewCounter(Default, "signet_authz_allowed_total", "Authorization decisions that allowed.")
	AuthzDenied  = NewCounter(Default, "signet_authz_denied_total", "Authorization decisions that denied.")

	// ProposeDuration is time from proposing an Op to its commit and apply.
	// Separating this from request duration matters: consensus latency is not
	// something a faster handler can fix, and mistaking one for the other sends
	// you optimizing the wrong half.
	ProposeDuration = NewHistogram(Default, "signet_propose_duration_seconds",
		"Time from proposing an operation to it being applied.", nil)

	ApplyDuration = NewHistogram(Default, "signet_apply_duration_seconds",
		"Time to apply one committed log entry to the store.", nil)

	StoreReadDuration = NewHistogram(Default, "signet_store_read_duration_seconds",
		"Duration of a read transaction.", nil)
	StoreWriteDuration = NewHistogram(Default, "signet_store_write_duration_seconds",
		"Duration of a write transaction.", nil)

	AuditEntries = NewGauge(Default, "signet_audit_entries", "Entries in the audit chain.")

	// InFlight is the concurrency actually observed. Before adding machinery to
	// serve requests in parallel, this says whether anything is queueing.
	InFlight = NewGauge(Default, "signet_requests_in_flight", "Requests currently being served.")
)

// --- per-route request metrics --------------------------------------------

// routeMetrics are created per matched route pattern. The pattern comes from
// our own ServeMux registrations, so the label set is bounded by the code
// rather than by anything a request can invent.
type routeMetrics struct {
	dur   *Histogram
	total *Counter
	errs  *Counter
}

var (
	routeMu sync.RWMutex
	routes  = map[string]*routeMetrics{}
)

func forRoute(pattern string) *routeMetrics {
	routeMu.RLock()
	m, ok := routes[pattern]
	routeMu.RUnlock()
	if ok {
		return m
	}
	routeMu.Lock()
	defer routeMu.Unlock()
	if m, ok := routes[pattern]; ok {
		return m
	}
	m = &routeMetrics{
		dur: NewHistogram(Default, "signet_request_duration_seconds",
			"Request duration by route.", nil, "route", pattern),
		total: NewCounter(Default, "signet_requests_total", "Requests by route.", "route", pattern),
		errs:  NewCounter(Default, "signet_request_errors_total", "Non-2xx responses by route.", "route", pattern),
	}
	routes[pattern] = m
	return m
}

// statusRecorder captures the status code without buffering the body.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

// Middleware records duration, count and error rate per matched route.
//
// It wraps the mux rather than each handler so that a route added later is
// instrumented automatically — instrumentation you have to remember to add is
// instrumentation that will be missing from the one handler you needed it for.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		InFlight.Inc()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		InFlight.Dec()

		// r.Pattern is set by ServeMux after routing, so this is the route
		// template ("GET /v1/secrets/data/{path...}") and never the concrete
		// path — which would put a secret's name into a metric label.
		pattern := r.Pattern
		if pattern == "" {
			pattern = "unmatched"
		}
		m := forRoute(pattern)
		m.dur.Observe(time.Since(start).Seconds())
		m.total.Inc()
		if rec.status >= 400 || rec.status == 0 {
			m.errs.Inc()
		}
	})
}

// Handler serves the exposition format.
func Handler(r *Registry) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		r.WriteTo(w)
	})
}

// Time is the common "measure this block" helper.
//
//	defer metrics.Time(metrics.AuthzDuration)()
func Time(h *Histogram) func() {
	start := time.Now()
	return func() { h.Observe(time.Since(start).Seconds()) }
}
