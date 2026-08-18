//go:build pkcs11

package seal

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// Does the token actually give every wrap a fresh IV?
//
// Wrap() calls NewGCMParams(nil, aad, 128) — a NULL IV — and then reads the IV
// back out of the mechanism parameters, on the assumption that the token
// generated one and wrote it there. In PKCS#11 v2.40 CK_GCM_PARAMS is an INPUT
// structure: who generates the IV is underspecified, implementations disagree,
// and v3.0 introduced a separate message-based interface precisely because of
// that ambiguity.
//
// If a token does not write an IV back, every wrap runs under the same one. For
// the root key and every DEK that is the catastrophic case: AES-GCM under a
// repeated (key, IV) leaks the XOR of the plaintexts and the authentication key
// with it. So this is not a compatibility question, it is the same class of bug
// as the barrier's nonce reuse — and it must be settled by measurement on every
// token we support, not by reading the specification.
//
// The decisive test is the simplest one: wrap identical plaintext twice and
// compare. Identical ciphertext means a fixed IV.

// TestHSMWrapUsesAFreshIVEachTime is the load-bearing test in this file.
func TestHSMWrapUsesAFreshIVEachTime(t *testing.T) {
	s := hsm(t)
	pt := []byte("a 32-byte data key --------------")
	aad := []byte("signet/test/gcm")

	first, err := s.Wrap(pt, aad)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Wrap(pt, aad)
	if err != nil {
		t.Fatal(err)
	}

	if len(first.Nonce) == 0 {
		t.Fatalf("the token returned NO IV. Wrap stored an empty nonce, so every wrap under this " +
			"token shares one IV — plaintext recovery and forgery follow. Supply an explicit IV " +
			"rather than passing NULL")
	}
	if len(first.Nonce) != 12 {
		t.Errorf("IV is %d bytes, expected 12 (%s)", len(first.Nonce), hex.EncodeToString(first.Nonce))
	}
	if bytes.Equal(first.Nonce, second.Nonce) {
		t.Fatalf("two wraps used the SAME IV (%s). This token does not generate a fresh IV for a "+
			"NULL parameter; Wrap must supply one itself", hex.EncodeToString(first.Nonce))
	}
	if bytes.Equal(first.CT, second.CT) {
		t.Fatal("identical plaintext produced identical ciphertext: the IV is fixed, which is the " +
			"catastrophic case for GCM")
	}
	if allZero(first.Nonce) {
		t.Fatalf("the IV is all zeroes (%s) — that is a placeholder, not a nonce",
			hex.EncodeToString(first.Nonce))
	}
}

// Over many wraps, no IV may repeat. One comparison could pass by luck; this
// would catch a token cycling a small counter or reseeding per session.
func TestHSMIVsDoNotRepeatOverManyWraps(t *testing.T) {
	s := hsm(t)
	const n = 64
	seen := make(map[string]int, n)
	for i := 0; i < n; i++ {
		b, err := s.Wrap([]byte("same plaintext every time"), []byte("aad"))
		if err != nil {
			t.Fatal(err)
		}
		k := string(b.Nonce)
		if prev, dup := seen[k]; dup {
			t.Fatalf("IV %s reused on wraps %d and %d of %d",
				hex.EncodeToString(b.Nonce), prev, i, n)
		}
		seen[k] = i
	}
}

// The IV must be carried with the blob and must matter. If a token ignored the
// IV we hand back on decrypt, unwrapping under a corrupted one would still
// succeed — which would mean the IV in the blob is decorative and the real one
// is fixed somewhere inside the token.
func TestHSMUnwrapDependsOnTheStoredIV(t *testing.T) {
	s := hsm(t)
	pt := []byte("a 32-byte data key --------------")
	aad := []byte("signet/test/gcm")
	b, err := s.Wrap(pt, aad)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.Unwrap(b, aad); err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("round trip failed: %v", err)
	}

	bad := *b
	bad.Nonce = append([]byte(nil), b.Nonce...)
	bad.Nonce[0] ^= 0xFF
	if _, err := s.Unwrap(&bad, aad); err == nil {
		t.Fatal("unwrapping under a corrupted IV succeeded: the stored IV is not the one being used")
	}
}

// AAD must bind. The wrapped material is bound to its purpose, so a blob must
// not be movable to a different one.
func TestHSMAADBinds(t *testing.T) {
	s := hsm(t)
	b, err := s.Wrap([]byte("material"), []byte("purpose/a"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Unwrap(b, []byte("purpose/b")); err == nil {
		t.Fatal("a blob unwrapped under different AAD: the binding is not enforced by the token")
	}
	if _, err := s.Unwrap(b, nil); err == nil {
		t.Fatal("a blob unwrapped with no AAD at all")
	}
}

// A single flipped bit anywhere in the ciphertext must fail authentication,
// which is what distinguishes GCM from raw CTR.
func TestHSMCiphertextIsAuthenticated(t *testing.T) {
	s := hsm(t)
	aad := []byte("purpose")
	b, err := s.Wrap([]byte("a 32-byte data key --------------"), aad)
	if err != nil {
		t.Fatal(err)
	}
	for _, pos := range []int{0, len(b.CT) / 2, len(b.CT) - 1} {
		bad := *b
		bad.CT = append([]byte(nil), b.CT...)
		bad.CT[pos] ^= 0x01
		if _, err := s.Unwrap(&bad, aad); err == nil {
			t.Fatalf("a flipped bit at offset %d still authenticated", pos)
		}
	}
}

// The tag must actually be 128 bits: ciphertext should exceed plaintext by
// exactly the tag length. A token silently using a shorter tag would weaken
// forgery resistance without any other visible symptom.
func TestHSMTagLength(t *testing.T) {
	s := hsm(t)
	pt := []byte("a 32-byte data key --------------")
	b, err := s.Wrap(pt, []byte("purpose"))
	if err != nil {
		t.Fatal(err)
	}
	if overhead := len(b.CT) - len(pt); overhead != 16 {
		t.Errorf("ciphertext overhead is %d bytes, expected a 16-byte GCM tag. If the token "+
			"returns the IV inside the ciphertext instead, Wrap is storing it twice and the "+
			"layout assumption is wrong", overhead)
	}
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return len(b) > 0
}

// A key regenerated under the same label must be a DIFFERENT key, as far as
// the seal is concerned.
//
// KeyID was token/label — a location, not an identity — so a successor
// reported the same ID as its predecessor. RewrapRootKey treats a matching
// KeyID as "already moved", which meant rotating to a same-label successor
// skipped every blob: `seal status` showed a clean rotation while the material
// was still wrapped by the key the operator believed retired. That is the worst
// shape a rotation bug can take, because it looks like success.
func TestHSMKeyIDDistinguishesASuccessorKey(t *testing.T) {
	s := hsm(t)
	p, ok := s.(*PKCS11Seal)
	if !ok {
		t.Skipf("not a pkcs11 seal: %T", s)
	}
	if p.fingerprint == UnidentifiedKey {
		t.Skip("this token exposes neither CKA_CHECK_VALUE nor CKA_ID; " +
			"key identity cannot be established and rotation will never skip")
	}

	id := s.KeyID()
	if !strings.Contains(id, p.token) || !strings.Contains(id, p.label) {
		t.Errorf("KeyID should still locate the key: %q", id)
	}
	// The identity must carry something derived from the key, not only its name.
	if id == p.token+"/"+p.label {
		t.Fatal("KeyID is still location-only; a successor under this label would be indistinguishable")
	}
	t.Logf("key identity: %s", id)
}

// A blob wrapped by one key must be refused by another, rather than producing
// an opaque decrypt failure.
func TestHSMUnwrapRefusesAForeignKeyID(t *testing.T) {
	s := hsm(t)
	b, err := s.Wrap([]byte("material"), []byte("purpose"))
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := s.(*PKCS11Seal); ok && p.fingerprint == UnidentifiedKey {
		t.Skip("token cannot identify its own key; the check is necessarily inert here")
	}

	foreign := *b
	foreign.KeyID = b.KeyID + "-but-not-really"
	_, err = s.Unwrap(&foreign, []byte("purpose"))
	if err == nil {
		t.Fatal("a blob claiming a different wrapping key was accepted")
	}
	if !strings.Contains(err.Error(), "wrapped by key") {
		t.Fatalf("the refusal should name the mismatch, got: %v", err)
	}
}
