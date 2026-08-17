package seal

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func testSeal(t *testing.T) Seal {
	t.Helper()
	p := filepath.Join(t.TempDir(), "seal.key")
	if err := GenerateKeyFile(p); err != nil {
		t.Fatal(err)
	}
	s, err := OpenFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestWrapRoundTrip(t *testing.T) {
	s := testSeal(t)
	secret := []byte("a data key")
	b, err := s.Wrap(secret, []byte("purpose"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b.CT, secret) {
		t.Fatal("the wrapped blob contains its own plaintext")
	}
	got, err := s.Unwrap(b, []byte("purpose"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("round trip = %q", got)
	}
}

// The AAD binds a blob to what it is for. Without this check, a wrapped data
// key could be lifted from one record and pasted onto another.
func TestWrapIsBoundToItsPurpose(t *testing.T) {
	s := testSeal(t)
	b, err := s.Wrap([]byte("secret"), []byte("purpose-a"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Unwrap(b, []byte("purpose-b")); err == nil {
		t.Fatal("a blob unwrapped under a purpose it was not wrapped for")
	}
}

// A different seal must not be able to open another's blobs — that is what
// makes "which seal is this domain using" a real question.
func TestADifferentSealCannotUnwrap(t *testing.T) {
	a, b := testSeal(t), testSeal(t)
	blob, err := a.Wrap([]byte("secret"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Unwrap(blob, nil); err == nil {
		t.Fatal("a foreign seal opened the blob")
	}
}

// The envelope is the property the whole design rests on: what gets stored is
// openable only with the seal, so the barrier alone — which is what an attacker
// with the store or its backups has — is not enough.
func TestEnvelopeRequiresTheSeal(t *testing.T) {
	s := testSeal(t)
	material := []byte("-----BEGIN PRIVATE KEY-----\nnot really\n-----END PRIVATE KEY-----")
	env, err := NewEnvelope(s, material, []byte("signet/key/token/abc"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(env.CT, material) || bytes.Contains(env.DEK.CT, material) {
		t.Fatal("the envelope leaks its own plaintext")
	}

	got, err := env.Open(s, []byte("signet/key/token/abc"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, material) {
		t.Fatal("envelope round trip lost the material")
	}
	// Another seal holds a different wrapping key, so it cannot recover the
	// data key even though it has the whole envelope.
	if _, err := env.Open(testSeal(t), []byte("signet/key/token/abc")); err == nil {
		t.Fatal("a foreign seal opened the envelope")
	}
	if _, err := env.Open(s, []byte("signet/key/token/different")); err == nil {
		t.Fatal("the envelope opened under the wrong binding")
	}
}

// The root key is only ever written wrapped, and re-opening the same directory
// must return the same key or every stored value becomes unreadable.
func TestRootKeyIsStoredWrappedAndIsStable(t *testing.T) {
	s := testSeal(t)
	dir := t.TempDir()
	first, err := LoadOrCreateRootKey(s, dir)
	if err != nil {
		t.Fatal(err)
	}
	again, err := LoadOrCreateRootKey(s, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, again) {
		t.Fatal("the root key changed between loads")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "root.seal"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, first) {
		t.Fatal("the root key is on disk in the clear")
	}
	// A domain moved to a different seal must fail loudly rather than silently
	// producing a different key and corrupting everything.
	if _, err := LoadOrCreateRootKey(testSeal(t), dir); err == nil {
		t.Fatal("a foreign seal unsealed the root key")
	}
}

func TestOpenRejectsUnknownAndMissingSchemes(t *testing.T) {
	for _, uri := range []string{"", "wat://x", "kms://nope"} {
		if _, err := Open(uri); err == nil {
			t.Errorf("Open(%q) succeeded, want an error", uri)
		}
	}
}

// A build without PKCS#11 must refuse a hardware seal rather than quietly
// falling back: a domain that believes its keys are in an HSM and is wrong is
// worse off than one that will not start.
func TestPKCS11WithoutSupportFailsLoudly(t *testing.T) {
	_, err := Open("pkcs11:?module=/nonexistent.so&label=x")
	if err == nil {
		t.Fatal("a pkcs11 seal opened unexpectedly")
	}
}
