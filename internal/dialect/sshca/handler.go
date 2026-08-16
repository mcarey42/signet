package sshca

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mcarey42/signet/internal/kernel"
	"github.com/mcarey42/signet/internal/keys"
)

// The wire shape mirrors Vault's ssh secrets engine, so existing tooling and
// muscle memory carry over: POST ssh/sign/<role> with a public key, get a
// certificate back in `data.signed_key`.

type Config struct {
	// Mount is the path clients address, e.g. "ssh".
	Mount string
}

type Handler struct {
	k   *kernel.Kernel
	cfg Config
}

func New(k *kernel.Kernel, cfg Config) *Handler {
	if cfg.Mount == "" {
		cfg.Mount = "ssh"
	}
	return &Handler{k: k, cfg: cfg}
}

func (h *Handler) Register(mux *http.ServeMux) {
	m := "/v1/" + h.cfg.Mount
	mux.HandleFunc("POST "+m+"/sign/{role}", h.sign)
	mux.HandleFunc("PUT "+m+"/sign/{role}", h.sign)
	// The CA public key is meant to be distributed — it is what hosts put in
	// TrustedUserCAKeys — so it needs no session.
	mux.HandleFunc("GET "+m+"/public_key", h.publicKey)
}

func (h *Handler) sign(w http.ResponseWriter, r *http.Request) {
	s, err := h.session(r)
	if err != nil {
		writeErr(w, http.StatusForbidden, "permission denied")
		return
	}
	var body struct {
		PublicKey       string `json:"public_key"`
		ValidPrincipals string `json:"valid_principals"`
		TTL             string `json:"ttl"`
		CertType        string `json:"cert_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request body")
		return
	}
	if body.PublicKey == "" {
		writeErr(w, http.StatusBadRequest, "missing 'public_key'")
		return
	}
	if body.CertType != "" && body.CertType != "user" {
		writeErr(w, http.StatusBadRequest, "only user certificates are supported")
		return
	}
	ttl, err := parseTTL(body.TTL)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	roleName := r.PathValue("role")
	role, err := h.k.SSHRole(r.Context(), roleName)
	if err != nil {
		writeErr(w, http.StatusNotFound, "unknown role")
		return
	}
	// Authorization happens against the role's scope before any key is touched.
	if err := h.k.AuthorizeSign(r.Context(), s, role.Scope); err != nil {
		writeErr(w, http.StatusForbidden, "permission denied")
		return
	}
	if role.MaxTTLSec > 0 {
		if max := time.Duration(role.MaxTTLSec) * time.Second; ttl <= 0 || ttl > max {
			ttl = max
		}
	}

	ser := &Serializer{
		Role: role,
		Request: Request{
			PublicKey:  []byte(body.PublicKey),
			Principals: splitCSV(body.ValidPrincipals),
			TTL:        ttl,
		},
	}
	cred, claims, err := h.k.Issue(r.Context(), s, kernel.IssueRequest{
		Audience: "ssh", Scope: role.Scope, TTL: ttl, Purpose: keys.PurposeSSH,
	}, ser)
	switch {
	case errors.Is(err, kernel.ErrDenied):
		writeErr(w, http.StatusForbidden, "permission denied")
		return
	case err != nil:
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"request_id": "", "lease_id": "", "renewable": false, "lease_duration": 0,
		"data": map[string]any{
			"signed_key":    string(cred),
			"serial_number": strconv.FormatInt(claims.ExpirySec, 10),
		},
		"wrap_info": nil, "warnings": nil, "auth": nil,
	})
}

func (h *Handler) publicKey(w http.ResponseWriter, r *http.Request) {
	key, err := h.k.ActiveKey(r.Context(), keys.PurposeSSH)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no ssh certificate authority configured")
		return
	}
	pub, err := CAPublicKey(key)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pub)
}

func (h *Handler) session(r *http.Request) (kernel.Session, error) {
	tok := r.Header.Get("X-Vault-Token")
	if tok == "" {
		if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
			tok = strings.TrimPrefix(a, "Bearer ")
		}
	}
	if tok == "" {
		return kernel.Session{}, kernel.ErrNoSession
	}
	return h.k.LookupSession(r.Context(), tok)
}

func parseTTL(v string) (time.Duration, error) {
	if v == "" {
		return 0, nil
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d, nil
	}
	if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
		return time.Duration(secs) * time.Second, nil
	}
	return 0, errors.New("ttl must be a duration or a number of seconds")
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"errors": []string{msg}})
}
