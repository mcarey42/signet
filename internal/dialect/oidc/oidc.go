// Package oidc serves Signet's OpenID Connect surface: discovery, a public key
// set, and a token endpoint.
//
// The token endpoint implements RFC 8693 token exchange, which is not an
// arbitrary choice — it is precisely doc 06's session-to-role-credential step
// written in a standard. A caller presents the session it already holds and
// receives a short-lived, audience-scoped ID token carrying the roles it is
// allowed to carry offline. Nothing here decides policy; the kernel does, and
// this package serializes the result.
package oidc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mcarey42/signet/internal/kernel"
	"github.com/mcarey42/signet/internal/keys"
	"github.com/mcarey42/signet/internal/seal"
)

const (
	grantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	typeIDToken        = "urn:ietf:params:oauth:token-type:id_token"
	typeAccessToken    = "urn:ietf:params:oauth:token-type:access_token"
)

type Config struct {
	// Audiences bounds who this issuer will mint tokens for. Empty means the
	// exchange endpoint is closed, which is the safe default: an issuer that
	// will address anyone is a lateral-movement primitive.
	Audiences []string
	// MaxTTL caps every credential this dialect issues. Zero uses
	// DefaultMaxTokenTTL.
	MaxTTL time.Duration

	// Issuer is the externally reachable URL clients will see in the `iss`
	// claim and use to fetch discovery. It must match exactly what relying
	// parties are configured with — a Kubernetes API server compares strings.
	Issuer string
	// DefaultTTL bounds tokens when a caller asks for nothing specific.
	DefaultTTL time.Duration
}

type Handler struct {
	k   *kernel.Kernel
	cfg Config
}

func New(k *kernel.Kernel, cfg Config) *Handler {
	if cfg.DefaultTTL <= 0 {
		cfg.DefaultTTL = 15 * time.Minute
	}
	return &Handler{k: k, cfg: cfg}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/openid-configuration", h.discovery)
	mux.HandleFunc("GET /oidc/keys", h.jwks)
	mux.HandleFunc("POST /oidc/token", h.token)
}

// discovery is what a relying party fetches first. Only what Signet actually
// supports is advertised — claiming a flow it does not implement would send
// clients down paths that fail later and more confusingly.
func (h *Handler) discovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                h.cfg.Issuer,
		"jwks_uri":                              h.cfg.Issuer + "/oidc/keys",
		"token_endpoint":                        h.cfg.Issuer + "/oidc/token",
		"grant_types_supported":                 []string{grantTokenExchange},
		"response_types_supported":              []string{"token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256", "ES256"},
		"claims_supported":                      []string{"sub", "aud", "exp", "iat", "iss", "groups", "amr", "auth_time"},
	})
}

// jwks publishes every key, including retired ones: a token signed before a
// rotation must keep verifying until it expires, or rotation becomes an outage.
func (h *Handler) jwks(w http.ResponseWriter, r *http.Request) {
	ks, err := h.k.PublicKeys(r.Context(), keys.PurposeToken)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	out := make([]map[string]any, 0, len(ks))
	for _, k := range ks {
		jwk, err := k.JWK(h.k.Seal())
		if err != nil {
			continue
		}
		out = append(out, jwk)
	}
	// Relying parties cache this; a short max-age keeps a rotation visible
	// quickly without hammering the endpoint.
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, map[string]any{"keys": out})
}

func (h *Handler) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}
	if got := r.Form.Get("grant_type"); got != grantTokenExchange {
		writeErr(w, http.StatusBadRequest, "unsupported_grant_type",
			fmt.Sprintf("only %s is supported", grantTokenExchange))
		return
	}
	subject := r.Form.Get("subject_token")
	if subject == "" {
		// A bearer token in the header is accepted too: it is the same
		// credential, and it keeps the session out of request logs.
		subject = bearer(r)
	}
	if subject == "" {
		writeErr(w, http.StatusBadRequest, "invalid_request", "missing subject_token")
		return
	}
	audience := r.Form.Get("audience")
	if audience == "" {
		writeErr(w, http.StatusBadRequest, "invalid_request", "missing audience")
		return
	}
	// The audience must be one this issuer is willing to speak to.
	//
	// Any authenticated session could previously mint a Signet-signed token for
	// ANY audience it named — its own identity and roles, but addressed to the
	// Kubernetes API server, or to any other relying party that trusts this
	// issuer. That is not impersonation, but it is a confinement break, and it
	// becomes lateral movement the moment a second consumer trusts us.
	if !h.cfg.audienceAllowed(audience) {
		writeErr(w, http.StatusBadRequest, "invalid_target",
			"this issuer does not mint tokens for that audience; it is not in the configured set")
		return
	}

	s, err := h.k.LookupSession(r.Context(), subject)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid_grant", "the subject token is not valid")
		return
	}

	ttl := h.cfg.DefaultTTL
	if v := r.Form.Get("requested_token_lifetime"); v != "" {
		// RFC 8693 says this is a number of SECONDS. Parsing it as a Go
		// duration string meant "5m" became ParseDuration("5ms") — five
		// MILLISECONDS, not five minutes — and "1h" errored into a silent
		// fallback. Parse the integer the spec describes, and refuse anything
		// else rather than quietly substituting a different lifetime.
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			writeErr(w, http.StatusBadRequest, "invalid_request",
				"requested_token_lifetime is a whole number of seconds (RFC 8693 §2.1)")
			return
		}
		ttl = time.Duration(n) * time.Second
	}
	// A ceiling regardless of what was asked for. Without one a non-expiring
	// session could mint a decade-long offline credential that no relying party
	// would ever re-check with us.
	if max := h.cfg.maxTTL(); ttl > max {
		ttl = max
	}
	cred, claims, err := h.k.Issue(r.Context(), s, kernel.IssueRequest{
		Audience: audience,
		Scope:    r.Form.Get("scope_path"),
		TTL:      ttl,
		Purpose:  keys.PurposeToken,
		Issuer:   h.cfg.Issuer,
	}, jwtSerializer{})
	switch {
	case errors.Is(err, kernel.ErrDenied):
		writeErr(w, http.StatusForbidden, "access_denied", "permission denied")
		return
	case err != nil:
		writeErr(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":      string(cred),
		"issued_token_type": typeIDToken,
		"token_type":        "Bearer",
		"expires_in":        claims.ExpirySec - time.Now().Unix(),
		"scope":             strings.Join(claims.Roles, " "),
	})
}

// jwtSerializer renders filtered claims as a signed JWT and then re-reads what
// it produced.
//
// It receives claims that are already tier-filtered and has no access to the
// ones that were excluded, so "no online-only role in an offline token" is a
// property of the data it is handed rather than a rule it must remember.
type jwtSerializer struct{}

func (jwtSerializer) Serialize(c kernel.Claims, k *keys.Key, sl seal.Seal) ([]byte, error) {
	claims := map[string]any{
		"iss": c.Issuer, "sub": c.Subject, "aud": c.Audience,
		"exp": c.ExpirySec, "iat": c.IssuedSec, "nbf": c.NotBefore,
		"groups": c.Roles,
	}
	if len(c.AMR) > 0 {
		claims["amr"] = c.AMR
	}
	if c.AuthTime > 0 {
		claims["auth_time"] = c.AuthTime
	}
	for k, v := range c.Extra {
		if _, taken := claims[k]; !taken {
			claims[k] = v
		}
	}
	token, err := k.SignJWS(sl, claims)
	if err != nil {
		return nil, err
	}
	return []byte(token), nil
}

// Verify re-parses the token from its own bytes and checks that what came out
// is what was meant to go in — signature, issuer, audience, lifetime, and the
// exact role set the filter produced. An extra role here would mean the
// serializer invented one.
func (jwtSerializer) Verify(cred []byte, c kernel.Claims, k *keys.Key, sl seal.Seal) error {
	if err := k.VerifyJWSSelf(sl, string(cred)); err != nil {
		return err
	}
	parts := strings.Split(string(cred), ".")
	if len(parts) != 3 {
		return errors.New("token is malformed")
	}
	payload, err := decodeSegment(parts[1])
	if err != nil {
		return err
	}
	var got struct {
		Iss    string   `json:"iss"`
		Sub    string   `json:"sub"`
		Aud    string   `json:"aud"`
		Exp    int64    `json:"exp"`
		Groups []string `json:"groups"`
	}
	if err := json.Unmarshal(payload, &got); err != nil {
		return err
	}
	if got.Iss != c.Issuer || got.Sub != c.Subject || got.Aud != c.Audience {
		return errors.New("issuer, subject, or audience does not match what was authorized")
	}
	if got.Exp != c.ExpirySec {
		return errors.New("expiry does not match what was authorized")
	}
	if len(got.Groups) != len(c.Roles) {
		return fmt.Errorf("token carries %d roles, %d were authorized", len(got.Groups), len(c.Roles))
	}
	for i := range got.Groups {
		if got.Groups[i] != c.Roles[i] {
			return fmt.Errorf("token carries role %q, which was not authorized", got.Groups[i])
		}
	}
	return nil
}

// DefaultMaxTokenTTL bounds an offline credential when nothing else does.
//
// A non-expiring session could otherwise mint a decade-long token: Issue clamps
// to the session's own expiry, and a session with no expiry has nothing to
// clamp to. A relying party never re-checks an offline credential with us, so
// its lifetime is the real revocation window.
const DefaultMaxTokenTTL = 12 * time.Hour

func (c Config) maxTTL() time.Duration {
	if c.MaxTTL > 0 {
		return c.MaxTTL
	}
	return DefaultMaxTokenTTL
}

// audienceAllowed reports whether this issuer will speak to that relying party.
// An empty set closes the exchange endpoint, which is the safe default.
func (c Config) audienceAllowed(aud string) bool {
	for _, a := range c.Audiences {
		if a == aud {
			return true
		}
	}
	return false
}
