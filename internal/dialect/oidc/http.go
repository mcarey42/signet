package oidc

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
)

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

// writeErr uses OAuth 2.0's error shape (RFC 6749 §5.2), which is what clients
// parse — not the Vault-style envelope the KV dialect uses.
func writeErr(w http.ResponseWriter, code int, kind, description string) {
	writeJSON(w, code, map[string]string{"error": kind, "error_description": description})
}

func bearer(r *http.Request) string {
	if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
		return strings.TrimPrefix(a, "Bearer ")
	}
	return r.Header.Get("X-Signet-Token")
}

func decodeSegment(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
