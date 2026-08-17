package seal

import (
	"crypto"
	"fmt"
)

// KeyRef points at a key that lives *inside* a token and has never existed
// outside it.
//
// This is the difference between wrapping and holding. A sealed envelope keeps
// key material encrypted at rest, but the plaintext still passes through
// Signet's memory every time it signs. A reference never does: the private key
// is generated in the device, marked non-extractable, and every signature is
// computed there. Compromising Signet then buys the ability to *ask* for
// signatures while the process lives — not the key (E-01 DB-3).
//
// What Signet stores is this reference. It is not secret; it is a pointer.
type KeyRef struct {
	Seal  string `json:"seal"`  // backend that holds it, e.g. "pkcs11"
	Token string `json:"token"` // token label
	Label string `json:"label"` // key label within the token
	ID    []byte `json:"id,omitempty"`
	Alg   string `json:"alg"` // "ECDSA-P256" or "RSA-2048"
}

func (r *KeyRef) String() string {
	if r == nil {
		return "<none>"
	}
	return fmt.Sprintf("%s:%s/%s (%s)", r.Seal, r.Token, r.Label, r.Alg)
}

// SigningSeal is a seal that can also hold signing keys, not merely wrap them.
//
// Only hardware backends implement this. A file seal deliberately does not:
// there is no meaningful sense in which a key "lives inside" a file, and
// pretending otherwise would let an operator believe they had a property they
// do not have.
type SigningSeal interface {
	Seal
	// GenerateSigner creates a key inside the token, non-extractable, and
	// returns a reference to it. The private half never leaves the device — not
	// during generation, not afterwards.
	GenerateSigner(label, alg string) (*KeyRef, error)
	// Signer returns a crypto.Signer that performs signatures inside the token.
	Signer(ref *KeyRef) (crypto.Signer, error)
	// DeleteSigner destroys a key inside the token. This is irreversible and
	// there is no copy anywhere else, which is the point and also the hazard.
	DeleteSigner(ref *KeyRef) error
}

// AsSigningSeal reports whether a seal can hold keys, with an explanation
// suitable for showing an operator when it cannot.
func AsSigningSeal(s Seal) (SigningSeal, error) {
	if ss, ok := s.(SigningSeal); ok {
		return ss, nil
	}
	return nil, fmt.Errorf(
		"the %q seal can wrap keys but cannot hold them: key material would still pass through "+
			"Signet's memory to be used. Holding a key requires a hardware seal (pkcs11:), where "+
			"the key is generated inside the device and never leaves it", s.Name())
}

// Supported signing algorithms for keys held inside a token.
const (
	AlgECDSAP256 = "ECDSA-P256"
	AlgRSA2048   = "RSA-2048"
)
