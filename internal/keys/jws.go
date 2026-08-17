package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/mcarey42/signet/internal/seal"
)

// SignJWS produces a compact JWS over the claims, using the key's own algorithm
// rather than anything a caller supplies. That is the same rule the verifier in
// internal/attest follows from the other side: the algorithm is a property of
// the key, never of the message.
func (k *Key) SignJWS(sl seal.Seal, claims any) (string, error) {
	if k.Purpose != PurposeToken {
		return "", fmt.Errorf("keys: %s keys do not sign tokens", k.Purpose)
	}
	header, err := json.Marshal(map[string]string{
		"alg": k.Algorithm, "typ": "JWT", "kid": k.ID,
	})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := b64(header) + "." + b64(payload)

	signer, err := k.Signer(sl)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(signing))

	var sig []byte
	switch priv := signer.(type) {
	case *rsa.PrivateKey:
		if sig, err = rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:]); err != nil {
			return "", err
		}
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, priv, sum[:])
		if err != nil {
			return "", err
		}
		// JOSE wants the raw R||S pair, each left-padded to the curve size —
		// not the ASN.1 form crypto/ecdsa returns from its other entry point.
		sig = make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
	default:
		return "", errors.New("keys: unsupported token key type")
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyJWSSelf re-checks a token this key just produced.
//
// It exists for the same reason the CA re-parses its own certificates: a
// credential is released to the world and cannot be recalled, so the cheapest
// possible moment to catch a malformed one is immediately after making it
// (charter principle 6).
func (k *Key) VerifyJWSSelf(sl seal.Seal, token string) error {
	parts := splitN(token, '.', 3)
	if len(parts) != 3 {
		return errors.New("self-verify: malformed token")
	}
	pub, err := k.Public(sl)
	if err != nil {
		return err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return errors.New("self-verify: malformed signature")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch p := pub.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(p, crypto.SHA256, sum[:], sig); err != nil {
			return errors.New("self-verify: signature does not verify under the issuing key")
		}
	case *ecdsa.PublicKey:
		if len(sig) != 64 {
			return errors.New("self-verify: malformed signature")
		}
		if !ecdsa.Verify(p, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return errors.New("self-verify: signature does not verify under the issuing key")
		}
	default:
		return errors.New("self-verify: unsupported key type")
	}
	return nil
}

func splitN(s string, sep byte, n int) []string {
	out := make([]string, 0, n)
	start := 0
	for i := 0; i < len(s) && len(out) < n-1; i++ {
		if s[i] == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}
