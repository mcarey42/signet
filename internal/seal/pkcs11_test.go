//go:build pkcs11

package seal

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// These tests run against a real PKCS#11 token. SoftHSM2 implements the same
// interface a hardware module does, so the code path exercised here is the one
// that runs against an HSM in production — which is the whole reason to test
// with it rather than with a mock.
//
// Point them at a token with:
//
//	export SOFTHSM2_CONF=/path/to/softhsm2.conf
//	export SIGNET_TEST_PKCS11='pkcs11:?module=/opt/homebrew/lib/softhsm/libsofthsm2.so&token=signet&pin=1234&label=signet-seal'
//	CGO_ENABLED=1 go test -tags pkcs11 ./internal/seal/
func hsm(t *testing.T) Seal {
	t.Helper()
	uri := os.Getenv("SIGNET_TEST_PKCS11")
	if uri == "" {
		t.Skip("set SIGNET_TEST_PKCS11 to run the hardware seal tests")
	}
	s, err := Open(uri)
	if err != nil {
		t.Fatalf("open hardware seal: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestHSMWrapRoundTrip(t *testing.T) {
	s := hsm(t)
	if s.Name() != "pkcs11" {
		t.Fatalf("seal name = %q", s.Name())
	}
	secret := []byte("a 32-byte data key --------------")
	b, err := s.Wrap(secret, []byte("purpose"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b.CT, secret) {
		t.Fatal("the token returned plaintext")
	}
	got, err := s.Unwrap(b, []byte("purpose"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("round trip through the token = %q", got)
	}
}

func TestHSMBindsToPurpose(t *testing.T) {
	s := hsm(t)
	b, err := s.Wrap([]byte("secret"), []byte("purpose-a"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Unwrap(b, []byte("purpose-b")); err == nil {
		t.Fatal("the token unwrapped under the wrong binding")
	}
}

// The end-to-end property: private key material enclosed under a hardware seal
// is unreadable without the device, and the root key on disk is likewise only
// ever present in wrapped form.
func TestHSMEnvelopeAndRootKey(t *testing.T) {
	s := hsm(t)

	material := []byte("-----BEGIN PRIVATE KEY-----\npretend\n-----END PRIVATE KEY-----")
	env, err := NewEnvelope(s, material, []byte("signet/key/token/abc"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(env.CT, material) {
		t.Fatal("the envelope leaks its plaintext")
	}
	got, err := env.Open(s, []byte("signet/key/token/abc"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, material) {
		t.Fatal("envelope round trip through the token lost the material")
	}

	dir := t.TempDir()
	root, err := LoadOrCreateRootKey(s, dir)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "root.seal"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, root) {
		t.Fatal("the root key is on disk in the clear")
	}
	again, err := LoadOrCreateRootKey(s, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(root, again) {
		t.Fatal("the root key changed between loads")
	}
	// A file seal must not be able to open what the token wrapped.
	p := filepath.Join(t.TempDir(), "seal.key")
	if err := GenerateKeyFile(p); err != nil {
		t.Fatal(err)
	}
	file, err := OpenFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateRootKey(file, dir); err == nil {
		t.Fatal("a file seal opened a root key the HSM wrapped")
	}
}
