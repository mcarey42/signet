// Package attest turns evidence that a principal presents into a verified
// identity claim. Every authentication method — Kubernetes ServiceAccount
// tokens today, WebAuthn, TPM quotes, and cloud instance documents later — is
// a Verifier behind one interface: "what principal does this evidence prove?"
//
// JWS verification is implemented on the standard library. Signet's dependency
// budget exists precisely so that the code sitting on the authentication path
// is code we can read, and Go ships everything required.
package attest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// JWKS is a pinned key set. Signet never discovers verification keys from a
// URL supplied in a request — key material is registered out of band, because
// an issuer that can point you at its own keys can mint any identity it likes
// (E-01 AT-2).
type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"` // RSA modulus
	E   string `json:"e"` // RSA exponent
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func ParseJWKS(raw []byte) (*JWKS, error) {
	var s JWKS
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("jwks: %w", err)
	}
	if len(s.Keys) == 0 {
		return nil, errors.New("jwks: no keys")
	}

	// Keep the keys we can use and drop the ones we cannot, rather than
	// rejecting the whole set because of one.
	//
	// This runs on every login (k8ssa.go). Failing the set closed meant that a
	// Kubernetes cluster adding a single key of a type we do not implement —
	// an Ed25519 "OKP" key, say — would take down authentication for that
	// entire issuer, for a key nobody was going to use. RFC 7517 §5 is explicit
	// that a consumer should ignore keys it cannot process; a key set is a
	// bag of offers, not a contract.
	//
	// Dropping a key is not silently permissive: a token whose `kid` names a
	// dropped key simply finds no key and fails, which is the correct and
	// narrow outcome. Only if NOTHING is usable is this an error, and then the
	// reasons are reported together so the operator sees the real cause.
	usable := make([]JWK, 0, len(s.Keys))
	var why []string
	for i, k := range s.Keys {
		if _, err := k.publicKey(); err != nil {
			why = append(why, fmt.Sprintf("key %d (kid %q): %v", i, k.Kid, err))
			continue
		}
		usable = append(usable, k)
	}
	if len(usable) == 0 {
		return nil, fmt.Errorf("jwks: no usable keys — %s", strings.Join(why, "; "))
	}
	s.Keys = usable
	return &s, nil
}

func (j JWK) publicKey() (crypto.PublicKey, error) {
	switch j.Kty {
	case "RSA":
		n, err := b64uint(j.N)
		if err != nil {
			return nil, fmt.Errorf("modulus: %w", err)
		}
		e, err := b64uint(j.E)
		if err != nil {
			return nil, fmt.Errorf("exponent: %w", err)
		}
		if !e.IsInt64() || e.Int64() > 1<<31 {
			return nil, errors.New("implausible exponent")
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case "EC":
		var curve elliptic.Curve
		switch j.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported curve %q", j.Crv)
		}
		x, err := b64uint(j.X)
		if err != nil {
			return nil, err
		}
		y, err := b64uint(j.Y)
		if err != nil {
			return nil, err
		}
		if !curve.IsOnCurve(x, y) {
			return nil, errors.New("point is not on the curve")
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	default:
		return nil, fmt.Errorf("unsupported key type %q", j.Kty)
	}
}

// Claims are the registered JWT claims Signet inspects, plus the raw payload
// for verifier-specific fields.
type Claims struct {
	Issuer   string
	Subject  string
	Audience []string
	Expiry   time.Time
	IssuedAt time.Time
	Raw      []byte
}

type rawClaims struct {
	Iss string          `json:"iss"`
	Sub string          `json:"sub"`
	Aud json.RawMessage `json:"aud"` // string or array of strings
	Exp int64           `json:"exp"`
	Nbf int64           `json:"nbf"`
	Iat int64           `json:"iat"`
}

// Skew is the tolerated clock difference between issuer and verifier. Signet
// depends on rough time agreement (docs/03); this bounds how rough.
const Skew = 30 * time.Second

// VerifyJWS validates a compact JWS against a pinned key set and checks the
// registered claims.
//
// The algorithm comes from the pinned key, never from the token's own header —
// a token that names its own algorithm can name "none", or claim an RSA public
// key is an HMAC secret. Both are classic, and both are impossible here.
func VerifyJWS(token string, jwks *JWKS, issuer string, audience string, now time.Time) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("jws: not three segments")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	hraw, err := b64(parts[0])
	if err != nil {
		return nil, fmt.Errorf("jws: header: %w", err)
	}
	if err := json.Unmarshal(hraw, &hdr); err != nil {
		return nil, fmt.Errorf("jws: header: %w", err)
	}
	sig, err := b64(parts[2])
	if err != nil {
		return nil, fmt.Errorf("jws: signature: %w", err)
	}
	signed := parts[0] + "." + parts[1]

	verified := false
	for _, k := range jwks.Keys {
		// A kid in the token selects a key; it never introduces one.
		if hdr.Kid != "" && k.Kid != "" && hdr.Kid != k.Kid {
			continue
		}
		pub, err := k.publicKey()
		if err != nil {
			continue
		}
		if err := verifySignature(pub, hdr.Alg, signed, sig); err == nil {
			verified = true
			break
		}
	}
	if !verified {
		return nil, errors.New("jws: no pinned key verifies this signature")
	}

	praw, err := b64(parts[1])
	if err != nil {
		return nil, fmt.Errorf("jws: payload: %w", err)
	}
	var rc rawClaims
	if err := json.Unmarshal(praw, &rc); err != nil {
		return nil, fmt.Errorf("jws: payload: %w", err)
	}
	c := &Claims{Issuer: rc.Iss, Subject: rc.Sub, Raw: praw}
	if rc.Exp > 0 {
		c.Expiry = time.Unix(rc.Exp, 0)
	}
	if rc.Iat > 0 {
		c.IssuedAt = time.Unix(rc.Iat, 0)
	}
	if c.Audience, err = parseAudience(rc.Aud); err != nil {
		return nil, err
	}

	if issuer == "" || c.Issuer != issuer {
		return nil, fmt.Errorf("jws: issuer %q is not the registered issuer", c.Issuer)
	}
	// An audience is not decoration: it is what stops a token minted for some
	// other service from being replayed at Signet (E-01 AT-0/AT-1).
	if audience == "" {
		return nil, errors.New("jws: no required audience configured")
	}
	if !slicesContain(c.Audience, audience) {
		return nil, fmt.Errorf("jws: audience %v does not include %q", c.Audience, audience)
	}
	if rc.Exp == 0 {
		return nil, errors.New("jws: token has no expiry")
	}
	if now.After(c.Expiry.Add(Skew)) {
		return nil, fmt.Errorf("jws: expired at %s", c.Expiry.UTC().Format(time.RFC3339))
	}
	if rc.Nbf > 0 && now.Add(Skew).Before(time.Unix(rc.Nbf, 0)) {
		return nil, errors.New("jws: not yet valid")
	}
	return c, nil
}

func verifySignature(pub crypto.PublicKey, alg, signed string, sig []byte) error {
	sum := sha256.Sum256([]byte(signed))
	switch p := pub.(type) {
	case *rsa.PublicKey:
		if alg != "RS256" {
			return fmt.Errorf("alg %q not supported for RSA", alg)
		}
		return rsa.VerifyPKCS1v15(p, crypto.SHA256, sum[:], sig)
	case *ecdsa.PublicKey:
		if alg != "ES256" {
			return fmt.Errorf("alg %q not supported for EC", alg)
		}
		if len(sig) != 64 {
			return errors.New("bad ECDSA signature length")
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(p, sum[:], r, s) {
			return errors.New("ECDSA verification failed")
		}
		return nil
	default:
		return errors.New("unsupported key type")
	}
}

func parseAudience(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return nil, errors.New("jws: audience is neither a string nor an array")
	}
	return many, nil
}

func b64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func b64uint(s string) (*big.Int, error) {
	b, err := b64(s)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, errors.New("empty value")
	}
	return new(big.Int).SetBytes(b), nil
}

func slicesContain(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
