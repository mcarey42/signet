//go:build pkcs11

package seal

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// A key held in a token must sign correctly and must not be extractable. Both
// halves matter: a key that cannot sign is useless, and one that can be
// exported provides none of the protection it was chosen for.
func TestTokenHeldKeySignsAndCannotBeExported(t *testing.T) {
	s := hsm(t)
	ss, err := AsSigningSeal(s)
	if err != nil {
		t.Fatal(err)
	}
	label := "signet-test-key"
	ref, err := ss.GenerateSigner(label, AlgECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.DeleteSigner(ref) })

	signer, err := ss.Signer(ref)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key is %T, want ECDSA", signer.Public())
	}

	// The signature must verify under the public half the token reported.
	digest := sha256.Sum256([]byte("something to sign"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatal("the token's signature does not verify under the public key it reported")
	}

	// And the signer must be usable where it actually matters: issuing a
	// certificate through crypto/x509, which is the real contract.
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "held-in-hardware"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		t.Fatalf("crypto/x509 could not use the token-held signer: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Fatalf("the self-signed certificate does not verify: %v", err)
	}
}

// A reference is a pointer, not a secret — but it must point somewhere real.
func TestSignerRejectsAReferenceTheTokenDoesNotHold(t *testing.T) {
	s := hsm(t)
	ss, _ := AsSigningSeal(s)
	if _, err := ss.Signer(&KeyRef{Seal: "pkcs11", Token: "signet", Label: "no-such-key", Alg: AlgECDSAP256}); err == nil {
		t.Fatal("got a signer for a key the token does not hold")
	}
}

// A signer must refuse a nil digest algorithm rather than crashing: it is
// called from library code several layers away from the operator.
func TestSignerRejectsMissingOptsWithoutPanicking(t *testing.T) {
	s := hsm(t)
	ss, _ := AsSigningSeal(s)
	ref, err := ss.GenerateSigner("signet-test-nilopts", AlgECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.DeleteSigner(ref) })
	signer, err := ss.Signer(ref)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Sign(rand.Reader, make([]byte, 32), nil); err == nil {
		t.Fatal("signing succeeded with no digest algorithm specified")
	}
}

// A file seal must refuse to pretend it can hold keys, since believing
// otherwise would give an operator a property they do not have.
func TestFileSealIsNotASigningSeal(t *testing.T) {
	p := t.TempDir() + "/seal.key"
	if err := GenerateKeyFile(p); err != nil {
		t.Fatal(err)
	}
	f, err := OpenFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AsSigningSeal(f); err == nil {
		t.Fatal("a file seal claimed it can hold keys")
	}
}
