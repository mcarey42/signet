// Package vaultkv speaks enough of the Vault HTTP API that External Secrets
// Operator, cert-manager, and the vault/bao CLI work against Signet unmodified.
//
// The compatibility line is evidence-based: every route here was derived from
// what those clients actually call, read from their source (docs/explorations/
// E-06). Several response details are bug-compatible on purpose — a wrong type
// in the wrong field panics real consumers — and each is marked below.
//
// This package is a pure serializer over kernel calls. It holds no policy, no
// storage, and no keys (charter principle 5).
package vaultkv

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/mcarey/signet/internal/kernel"
)

// Status is the server-side view sys/health reports. Sealing and consensus are
// server questions, so the dialect is handed them rather than asking the
// kernel, which knows nothing about either.
type Status struct {
	Initialized bool
	Sealed      bool
	Leader      bool
}

type Config struct {
	// Mount is the KV mount name clients address, e.g.
	// "secrets-home-solcore-dot-net".
	Mount string
	// TreePrefix is where that mount lands in the resource tree. Secrets are
	// tree nodes, so scope machinery applies to them for free (docs/13 F8).
	TreePrefix string
	Status     func() Status
}

type Handler struct {
	k   *kernel.Kernel
	cfg Config
}

func New(k *kernel.Kernel, cfg Config) *Handler {
	if cfg.TreePrefix == "" {
		cfg.TreePrefix = "/secrets"
	}
	return &Handler{k: k, cfg: cfg}
}

func (h *Handler) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/sys/health", h.health)
	mux.HandleFunc("GET /v1/sys/internal/ui/mounts/{path...}", h.mountPreflight)
	mux.HandleFunc("GET /v1/auth/token/lookup-self", h.lookupSelf)
	mux.HandleFunc("PUT /v1/auth/token/revoke-self", h.revokeSelf)
	mux.HandleFunc("POST /v1/auth/token/revoke-self", h.revokeSelf)
	mux.HandleFunc("GET /v1/{mount}/data/{path...}", h.readSecret)
	mux.HandleFunc("PUT /v1/{mount}/data/{path...}", h.writeSecret)
	mux.HandleFunc("POST /v1/{mount}/data/{path...}", h.writeSecret)
	return mux
}

// --- routes ---------------------------------------------------------------

func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	st := Status{Initialized: true}
	if h.cfg.Status != nil {
		st = h.cfg.Status()
	}
	// cert-manager branches on the status code alone, but this homelab's
	// monitoring asserts on the body's booleans — so both are contractual.
	writeJSON(w, http.StatusOK, map[string]any{
		"initialized": st.Initialized,
		"sealed":      st.Sealed,
		"standby":     !st.Leader,
		"version":     "signet-0.1.0-mvp",
	})
}

func (h *Handler) mountPreflight(w http.ResponseWriter, r *http.Request) {
	if _, err := h.session(r); err != nil {
		writeErr(w, http.StatusForbidden, "permission denied")
		return
	}
	requested := r.PathValue("path")
	if mountOf(requested) != h.cfg.Mount {
		writeErr(w, http.StatusNotFound, "no handler for route")
		return
	}
	writeJSON(w, http.StatusOK, envelope(map[string]any{
		"path": h.cfg.Mount + "/",
		"type": "kv",
		// The CLI asserts this is a STRING without checking; a number panics it.
		"options": map[string]any{"version": "2"},
	}))
}

func (h *Handler) lookupSelf(w http.ResponseWriter, r *http.Request) {
	s, err := h.session(r)
	if err != nil {
		writeErr(w, http.StatusForbidden, "permission denied")
		return
	}
	var ttl int64
	var expire any // key must always be present; null means non-expiring
	if s.Expiry != 0 {
		ttl = s.Expiry - time.Now().Unix()
		if ttl < 0 {
			ttl = 0
		}
		expire = time.Unix(s.Expiry, 0).UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, envelope(map[string]any{
		"id":            string(s.ID),
		"accessor":      string(s.ID),
		"type":          "service", // ESO refuses to reuse "batch" tokens
		"policies":      []string{},
		"meta":          nil,
		"ttl":           ttl, // must be a JSON NUMBER: ESO asserts json.Number
		"expire_time":   expire,
		"renewable":     false,
		"num_uses":      0,
		"creation_time": s.AuthTime,
	}))
}

func (h *Handler) revokeSelf(w http.ResponseWriter, r *http.Request) {
	tok := bearer(r)
	if tok == "" {
		writeErr(w, http.StatusForbidden, "permission denied")
		return
	}
	if err := h.k.RevokeSession(r.Context(), "", tok); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) readSecret(w http.ResponseWriter, r *http.Request) {
	s, err := h.session(r)
	if err != nil {
		writeErr(w, http.StatusForbidden, "permission denied")
		return
	}
	path, ok := h.treePath(r)
	if !ok {
		writeErr(w, http.StatusNotFound, "no handler for route")
		return
	}
	sec, err := h.k.GetSecret(r.Context(), s, path)
	switch {
	case errors.Is(err, kernel.ErrNotFound):
		// A missing secret is 404 with an EMPTY errors array — that exact shape
		// is what the Go client maps to "absent, not an error", which drives
		// ESO's whole absent-secret path.
		writeJSON(w, http.StatusNotFound, map[string]any{"errors": []string{}})
		return
	case errors.Is(err, kernel.ErrDenied):
		writeErr(w, http.StatusForbidden, "permission denied")
		return
	case err != nil:
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, envelope(map[string]any{
		"data": sec.Data,
		"metadata": map[string]any{
			"created_time":    time.Unix(sec.CreatedSec, 0).UTC().Format(time.RFC3339),
			"custom_metadata": nil,
			"deletion_time":   "",
			"destroyed":       false,
			"version":         sec.Version,
		},
	}))
}

func (h *Handler) writeSecret(w http.ResponseWriter, r *http.Request) {
	s, err := h.session(r)
	if err != nil {
		writeErr(w, http.StatusForbidden, "permission denied")
		return
	}
	path, ok := h.treePath(r)
	if !ok {
		writeErr(w, http.StatusNotFound, "no handler for route")
		return
	}
	var body struct {
		Data    map[string]string `json:"data"`
		Options struct {
			CAS *uint64 `json:"cas"`
		} `json:"options"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request body")
		return
	}
	version, err := h.k.PutSecret(r.Context(), s, path, body.Data, body.Options.CAS)
	switch {
	case errors.Is(err, kernel.ErrDenied):
		writeErr(w, http.StatusForbidden, "permission denied")
		return
	case err != nil:
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, envelope(map[string]any{
		"created_time":    time.Now().UTC().Format(time.RFC3339),
		"custom_metadata": nil,
		"deletion_time":   "",
		"destroyed":       false,
		"version":         version,
	}))
}

// --- helpers --------------------------------------------------------------

func (h *Handler) session(r *http.Request) (kernel.Session, error) {
	tok := bearer(r)
	if tok == "" {
		return kernel.Session{}, kernel.ErrNoSession
	}
	return h.k.LookupSession(r.Context(), tok)
}

// treePath maps the client's mount+path onto a node in the resource tree.
func (h *Handler) treePath(r *http.Request) (string, bool) {
	if r.PathValue("mount") != h.cfg.Mount {
		return "", false
	}
	rest := strings.Trim(r.PathValue("path"), "/")
	if rest == "" {
		return "", false
	}
	return h.cfg.TreePrefix + "/" + rest, true
}

func bearer(r *http.Request) string {
	if t := r.Header.Get("X-Vault-Token"); t != "" {
		return t
	}
	if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
		return strings.TrimPrefix(a, "Bearer ")
	}
	return ""
}

func mountOf(p string) string {
	if i := strings.Index(p, "/"); i >= 0 {
		return p[:i]
	}
	return p
}

// envelope wraps a data payload in the response shape every Vault client
// decodes. Fields consumers ignore are emitted as constants.
func envelope(data map[string]any) map[string]any {
	return map[string]any{
		"request_id":     "",
		"lease_id":       "",
		"renewable":      false,
		"lease_duration": 0,
		"data":           data,
		"wrap_info":      nil,
		"warnings":       nil,
		"auth":           nil,
	}
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"errors": []string{msg}})
}
