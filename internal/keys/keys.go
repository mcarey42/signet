// Package keys manages Signet's signing keys.
//
// These are deliberately not the seal. The seal protects data at rest; signing
// keys mint credentials that relying parties accept without asking anyone. They
// are kept separate, generated per purpose, and rotated independently, because
// one stolen key should not be all of them (E-01 DB-3). Moving them into a TPM,
// PKCS#11 token, or cloud KMS is the hardening milestone: the interface here is
// shaped so the private half can stop being a byte slice without callers
// changing.
package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"

	"github.com/mcarey42/signet/internal/seal"
)

// Purpose separates keys by what they are allowed to sign. A key minted for
// tokens can never be used to sign an SSH certificate, so compromise of one
// does not spend the other.
type Purpose string

const (
	// PurposeToken signs OIDC ID tokens and other JWTs.
	PurposeToken Purpose = "token"
	// PurposeSSH is the SSH certificate authority key.
	PurposeSSH Purpose = "ssh"
)

// Key is one signing key. Old keys stay published for verification after
// rotation, so credentials already in the wild keep validating until they
// expire — that is what makes rotation a non-event.
//
// Exactly one of PrivatePEM or Sealed carries the private half. Sealed is the
// form that gets stored: the material is enclosed under a data key only the
// seal can unwrap, so the replicated log — which is append-only and whose
// backups are immutable — never holds a key the barrier alone can open.
// PrivatePEM exists only in memory, between generation and sealing.
type Key struct {
	ID         string         `json:"id"` // the JWKS "kid"
	Purpose    Purpose        `json:"purpose"`
	Algorithm  string         `json:"alg"`
	PrivatePEM []byte         `json:"private,omitempty"`
	Sealed     *seal.Envelope `json:"sealed,omitempty"`
	CreatedSec int64          `json:"created"`
	Retired    bool           `json:"retired,omitempty"`
}

// keyAAD binds an envelope to the specific key it belongs to, so a sealed blob
// cannot be moved onto a different key record.
func keyAAD(purpose Purpose, id string) []byte {
	return []byte("signet/key/" + string(purpose) + "/" + id)
}

// Seal encloses the private half and drops the plaintext. The returned copy is
// what may be persisted.
func (k *Key) Seal(s seal.Seal) (*Key, error) {
	if k.Sealed != nil {
		return k, nil
	}
	if len(k.PrivatePEM) == 0 {
		return nil, errors.New("keys: nothing to seal")
	}
	env, err := seal.NewEnvelope(s, k.PrivatePEM, keyAAD(k.Purpose, k.ID))
	if err != nil {
		return nil, err
	}
	out := *k
	out.Sealed = env
	out.PrivatePEM = nil
	return &out, nil
}

// private returns the key material, opening the envelope if that is where it
// lives. The seal is required for anything sealed, which is the point.
func (k *Key) private(s seal.Seal) ([]byte, error) {
	if k.Sealed == nil {
		if len(k.PrivatePEM) == 0 {
			return nil, errors.New("keys: key has no private material")
		}
		return k.PrivatePEM, nil
	}
	if s == nil {
		return nil, errors.New("keys: key is sealed and no seal was provided")
	}
	return k.Sealed.Open(s, keyAAD(k.Purpose, k.ID))
}

// Generate creates a key for a purpose.
//
// Token keys are RSA-2048 (RS256) by default, not because it is the better
// algorithm — ES256 is smaller and faster — but because RS256 is the one every
// OIDC consumer accepts without configuration. The Kubernetes API server, for
// instance, rejects ES256 outright unless explicitly told otherwise, and a
// credential system that requires every relying party to be reconfigured before
// it works is a credential system nobody adopts. ES256 remains available for
// deployments that know their consumers.
//
// SSH keys are Ed25519, which OpenSSH has preferred for a decade.
func Generate(purpose Purpose, nowSec int64) (*Key, error) {
	return GenerateAlg(purpose, "", nowSec)
}

// GenerateAlg creates a key with an explicit algorithm. An empty alg takes the
// most compatible default for the purpose.
func GenerateAlg(purpose Purpose, alg string, nowSec int64) (*Key, error) {
	switch purpose {
	case PurposeToken:
		if alg == "" {
			alg = "RS256"
		}
		switch alg {
		case "RS256":
			k, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				return nil, err
			}
			der, err := x509.MarshalPKCS8PrivateKey(k)
			if err != nil {
				return nil, err
			}
			id, err := thumbprint(k.Public())
			if err != nil {
				return nil, err
			}
			return &Key{ID: id, Purpose: purpose, Algorithm: "RS256",
				PrivatePEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
				CreatedSec: nowSec}, nil
		case "ES256":
		default:
			return nil, fmt.Errorf("keys: unsupported token algorithm %q", alg)
		}
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, err
		}
		id, err := thumbprint(k.Public())
		if err != nil {
			return nil, err
		}
		return &Key{ID: id, Purpose: purpose, Algorithm: "ES256",
			PrivatePEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
			CreatedSec: nowSec}, nil
	case PurposeSSH:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, err
		}
		id, err := thumbprint(priv.Public())
		if err != nil {
			return nil, err
		}
		return &Key{ID: id, Purpose: purpose, Algorithm: "ssh-ed25519",
			PrivatePEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
			CreatedSec: nowSec}, nil
	default:
		return nil, fmt.Errorf("keys: unknown purpose %q", purpose)
	}
}

// Signer returns the private half. Callers hold it only for the duration of one
// signing operation.
func (k *Key) Signer(s seal.Seal) (crypto.Signer, error) {
	material, err := k.private(s)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(material)
	if blk == nil {
		return nil, errors.New("keys: private key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, errors.New("keys: not a signing key")
	}
	return signer, nil
}

// Public needs the seal too, because the public half is derived from the
// private one. Callers that publish JWKS hold the seal anyway.
func (k *Key) Public(s seal.Seal) (crypto.PublicKey, error) {
	signer, err := k.Signer(s)
	if err != nil {
		return nil, err
	}
	return signer.Public(), nil
}

// JWK renders the public half for a JWKS document. Only public material is ever
// produced here — there is no code path that publishes a private key.
func (k *Key) JWK(s seal.Seal) (map[string]any, error) {
	pub, err := k.Public(s)
	if err != nil {
		return nil, err
	}
	switch p := pub.(type) {
	case *rsa.PublicKey:
		return map[string]any{
			"kty": "RSA", "alg": "RS256", "use": "sig", "kid": k.ID,
			"n": b64(p.N.Bytes()),
			"e": b64(big.NewInt(int64(p.E)).Bytes()),
		}, nil
	case *ecdsa.PublicKey:
		return map[string]any{
			"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": k.ID,
			"x": b64(p.X.FillBytes(make([]byte, 32))),
			"y": b64(p.Y.FillBytes(make([]byte, 32))),
		}, nil
	default:
		return nil, fmt.Errorf("keys: %s is not publishable as a JWK", k.Algorithm)
	}
}

// thumbprint derives a stable key ID from the public key, so the same key
// always presents the same kid no matter how often it is reloaded.
func thumbprint(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return b64(sum[:16]), nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// SealedBy reports which seal wrapping key holds this key's material, or an
// empty string if it is not sealed. Rotation uses it to tell what still needs
// moving, and `seal status` uses it to surface a half-finished ceremony.
func (k *Key) SealedBy() string {
	if k.Sealed == nil || k.Sealed.DEK == nil {
		return ""
	}
	return k.Sealed.DEK.Seal + "/" + k.Sealed.DEK.KeyID
}

// Rewrap moves the private material from one seal to another.
//
// The material itself is unchanged — this re-encloses it under a new data key
// that the new seal holds. The key keeps its identity, so every credential
// already issued under it stays valid: rotating the seal is not rotating the
// key, and conflating the two would turn a custody change into an outage.
func (k *Key) Rewrap(from, to seal.Seal) (*Key, error) {
	material, err := k.private(from)
	if err != nil {
		return nil, err
	}
	env, err := seal.NewEnvelope(to, material, keyAAD(k.Purpose, k.ID))
	if err != nil {
		return nil, err
	}
	out := *k
	out.Sealed = env
	out.PrivatePEM = nil
	return &out, nil
}
