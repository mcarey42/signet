package vaultkv

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mcarey42/signet/internal/ca"
	"github.com/mcarey42/signet/internal/kernel"
)

// The PKI routes cert-manager's Vault issuer calls. Its request shape is
// unusual and worth stating plainly: every value arrives as a STRING, including
// the TTL (a Go duration like "2160h0m0s") and the boolean-ish
// exclude_cn_from_sans, and alt_names / ip_sans / uri_sans are
// comma-separated strings rather than arrays (E-06 F3).

func (h *Handler) pkiRoutes(mux *http.ServeMux) {
	if h.cfg.PKIMount == "" {
		return
	}
	p := "/v1/" + h.cfg.PKIMount
	mux.HandleFunc("POST "+p+"/sign/{role}", h.signCertificate)
	mux.HandleFunc("PUT "+p+"/sign/{role}", h.signCertificate)
	// Trust material is public by design: a CA certificate is meant to be
	// distributed, so these need no session.
	mux.HandleFunc("GET "+p+"/ca/pem", h.caPEM(false))
	mux.HandleFunc("GET "+p+"/ca_chain", h.caPEM(true))
}

func (h *Handler) signCertificate(w http.ResponseWriter, r *http.Request) {
	s, err := h.session(r)
	if err != nil {
		writeErr(w, http.StatusForbidden, "permission denied")
		return
	}
	// Values are decoded permissively because clients send numbers, booleans,
	// and durations all as strings.
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed request body")
		return
	}
	csr := str(body["csr"])
	if csr == "" {
		writeErr(w, http.StatusBadRequest, "missing 'csr'")
		return
	}
	ttl, err := parseTTL(str(body["ttl"]))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	// Sign with this node's own issuing authority when it has one, so a domain
	// with several signing nodes uses the key each node actually holds.
	authority, err := h.k.SigningAuthority(r.Context(), h.cfg.NodeID)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	issued, err := h.k.SignCertificate(r.Context(), s, authority, r.PathValue("role"), ca.Request{
		CSRPEM:            []byte(csr),
		CommonName:        str(body["common_name"]),
		DNSNames:          csv(str(body["alt_names"])),
		IPs:               csv(str(body["ip_sans"])),
		URIs:              csv(str(body["uri_sans"])),
		TTL:               ttl,
		ExcludeCNFromSANs: truthy(body["exclude_cn_from_sans"]),
	})
	switch {
	case errors.Is(err, kernel.ErrDenied):
		writeErr(w, http.StatusForbidden, "permission denied")
		return
	case errors.Is(err, kernel.ErrNotFound):
		writeErr(w, http.StatusNotFound, err.Error())
		return
	case err != nil:
		// A refusal from the verification gate lands here. It is a client error:
		// the request asked for something the role does not permit.
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	// cert-manager reads certificate, issuing_ca, and ca_chain; it tolerates
	// extra fields and ignores the rest.
	writeJSON(w, http.StatusOK, envelope(map[string]any{
		"certificate":      string(issued.CertPEM),
		"issuing_ca":       string(issued.IssuingCAPEM),
		"ca_chain":         []string{string(issued.IssuingCAPEM), string(issued.ChainPEM)},
		"serial_number":    issued.Serial,
		"expiration":       issued.NotAfter.Unix(),
		"private_key_type": "",
	}))
}

func (h *Handler) caPEM(chain bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authority, err := h.k.SigningAuthority(r.Context(), h.cfg.NodeID)
		if err != nil {
			writeErr(w, http.StatusNotFound, "no certificate authority configured")
			return
		}
		root, full, err := h.k.CAChain(r.Context(), authority)
		if err != nil {
			writeErr(w, http.StatusNotFound, "no certificate authority configured")
			return
		}
		out := root
		if chain {
			out = full
		}
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(out)
	}
}

// parseTTL accepts a Go duration ("2160h0m0s"), a bare number of seconds, or an
// empty value meaning "the role's default".
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

func str(v any) string {
	switch s := v.(type) {
	case string:
		return s
	case float64:
		return strconv.FormatFloat(s, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(s)
	}
	return ""
}

func truthy(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t == "true" || t == "1"
	}
	return false
}

func csv(s string) []string {
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
