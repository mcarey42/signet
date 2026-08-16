package attest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

const (
	testIssuer = "https://kubernetes.default.svc.cluster.local"
	testAud    = "signet"
)

type signer struct {
	rsa  *rsa.PrivateKey
	ec   *ecdsa.PrivateKey
	jwks *JWKS
}

func newSigner(t *testing.T) *signer {
	t.Helper()
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwks := &JWKS{Keys: []JWK{
		{Kty: "RSA", Kid: "rsa-1", Alg: "RS256",
			N: b64enc(rk.N.Bytes()), E: b64enc(big.NewInt(int64(rk.E)).Bytes())},
		{Kty: "EC", Kid: "ec-1", Alg: "ES256", Crv: "P-256",
			X: b64enc(ek.X.Bytes()), Y: b64enc(ek.Y.Bytes())},
	}}
	return &signer{rsa: rk, ec: ek, jwks: jwks}
}

// mint builds a signed token. claims overrides let each test bend exactly one
// thing.
func (s *signer) mint(t *testing.T, alg string, claims map[string]any) string {
	t.Helper()
	kid := map[string]string{"RS256": "rsa-1", "ES256": "ec-1"}[alg]
	hdr := map[string]any{"alg": alg, "typ": "JWT"}
	if kid != "" {
		hdr["kid"] = kid
	}
	h, _ := json.Marshal(hdr)
	c, _ := json.Marshal(claims)
	signing := b64enc(h) + "." + b64enc(c)
	sum := sha256.Sum256([]byte(signing))

	var sig []byte
	var err error
	switch alg {
	case "RS256":
		sig, err = rsa.SignPKCS1v15(rand.Reader, s.rsa, crypto.SHA256, sum[:])
	case "ES256":
		var r, sv *big.Int
		r, sv, err = ecdsa.Sign(rand.Reader, s.ec, sum[:])
		if err == nil {
			sig = append(pad32(r.Bytes()), pad32(sv.Bytes())...)
		}
	case "none":
		sig = nil
	case "HS256":
		// The alg-confusion attack: sign with the RSA *public* key as an HMAC
		// secret and hope the verifier trusts the header.
		mac := hmac.New(sha256.New, s.rsa.N.Bytes())
		mac.Write([]byte(signing))
		sig = mac.Sum(nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + b64enc(sig)
}

func b64enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func pad32(b []byte) []byte {
	if len(b) >= 32 {
		return b
	}
	return append(make([]byte, 32-len(b)), b...)
}

func saClaims(now time.Time, over map[string]any) map[string]any {
	c := map[string]any{
		"iss": testIssuer,
		"sub": "system:serviceaccount:external-secrets:external-secrets",
		"aud": []string{testAud},
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
		"kubernetes.io": map[string]any{
			"namespace":      "external-secrets",
			"serviceaccount": map[string]any{"name": "external-secrets", "uid": "uid-123"},
		},
	}
	for k, v := range over {
		if v == nil {
			delete(c, k)
			continue
		}
		c[k] = v
	}
	return c
}

func TestK8sSAHappyPath(t *testing.T) {
	s := newSigner(t)
	now := time.Now()
	raw, _ := json.Marshal(s.jwks)
	iss := Issuer{Name: "kind", URL: testIssuer, Audience: testAud, JWKS: raw}

	for _, alg := range []string{"RS256", "ES256"} {
		tok := s.mint(t, alg, saClaims(now, nil))
		id, err := K8sSA{}.Verify([]byte(tok), iss, now)
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		if id.Namespace != "external-secrets" || id.Account != "external-secrets" {
			t.Errorf("%s: identity = %+v", alg, id)
		}
		if id.UID != "uid-123" {
			t.Errorf("%s: uid = %q", alg, id.UID)
		}
	}
}

// Each case is a real attack against token verifiers. None of them may pass.
func TestK8sSARejects(t *testing.T) {
	s := newSigner(t)
	now := time.Now()
	raw, _ := json.Marshal(s.jwks)
	iss := Issuer{Name: "kind", URL: testIssuer, Audience: testAud, JWKS: raw}

	cases := []struct {
		name  string
		token func() string
	}{
		{"alg=none", func() string { return s.mint(t, "none", saClaims(now, nil)) }},
		{"alg confusion: RSA public key used as HMAC secret",
			func() string { return s.mint(t, "HS256", saClaims(now, nil)) }},
		{"wrong audience — a token minted for another service",
			func() string { return s.mint(t, "RS256", saClaims(now, map[string]any{"aud": []string{"vault"}})) }},
		{"no audience at all",
			func() string { return s.mint(t, "RS256", saClaims(now, map[string]any{"aud": nil})) }},
		{"wrong issuer",
			func() string { return s.mint(t, "RS256", saClaims(now, map[string]any{"iss": "https://evil.example"})) }},
		{"expired",
			func() string {
				return s.mint(t, "RS256", saClaims(now, map[string]any{"exp": now.Add(-2 * time.Hour).Unix()}))
			}},
		{"no expiry",
			func() string { return s.mint(t, "RS256", saClaims(now, map[string]any{"exp": nil})) }},
		{"not a service account subject",
			func() string { return s.mint(t, "RS256", saClaims(now, map[string]any{"sub": "system:node:worker-1"})) }},
		{"sub disagrees with the kubernetes.io claim",
			func() string {
				return s.mint(t, "RS256", saClaims(now, map[string]any{
					"sub": "system:serviceaccount:kube-system:admin",
				}))
			}},
		{"tampered payload",
			func() string {
				tok := s.mint(t, "RS256", saClaims(now, nil))
				p := strings.Split(tok, ".")
				evil, _ := json.Marshal(saClaims(now, map[string]any{"sub": "system:serviceaccount:kube-system:admin"}))
				return p[0] + "." + b64enc(evil) + "." + p[2]
			}},
		{"signed by a key that is not pinned",
			func() string { return newSigner(t).mint(t, "RS256", saClaims(now, nil)) }},
		{"malformed", func() string { return "not.a.jwt" }},
	}

	for _, c := range cases {
		if _, err := (K8sSA{}).Verify([]byte(c.token()), iss, now); err == nil {
			t.Errorf("%s: accepted, must be rejected", c.name)
		}
	}
}

// A verifier configured without an audience must fail closed rather than accept
// anything: a missing requirement is not a satisfied one.
func TestMissingAudienceConfigFailsClosed(t *testing.T) {
	s := newSigner(t)
	now := time.Now()
	raw, _ := json.Marshal(s.jwks)
	tok := s.mint(t, "RS256", saClaims(now, nil))
	if _, err := (K8sSA{}).Verify([]byte(tok), Issuer{URL: testIssuer, JWKS: raw}, now); err == nil {
		t.Error("verification succeeded with no configured audience")
	}
}

func TestParseJWKSRejectsGarbage(t *testing.T) {
	for _, in := range []string{`{}`, `{"keys":[]}`, `{"keys":[{"kty":"oct","k":"aaa"}]}`, `not json`} {
		if _, err := ParseJWKS([]byte(in)); err == nil {
			t.Errorf("ParseJWKS(%s) succeeded, want error", in)
		}
	}
}
