package trust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Each test here names the thing it stops, because a bundle's whole value is
// that a consumer can be wrong about the network and still be right about who
// it trusts.

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func mkCA(t *testing.T, cn string, parent *testCA) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	signParent, signKey := tmpl, key
	if parent != nil {
		signParent, signKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signParent, key.Public(), signKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func anchorOf(c *testCA, role AnchorRole) Anchor {
	return Anchor{Role: role, Name: c.cert.Subject.CommonName, CertPEM: c.pem, SPKI: Fingerprint(c.cert)}
}

func issuerOf(c *testCA) Issuer {
	return Issuer{Name: c.cert.Subject.CommonName, CertPEM: c.pem, SPKI: Fingerprint(c.cert)}
}

// mkBundle builds a signed bundle for a root and its issuers.
func mkBundle(t *testing.T, root *testCA, epoch uint64, maxAge time.Duration, issuers ...*testCA) *Bundle {
	t.Helper()
	anchors := []Anchor{anchorOf(root, RoleRoot)}
	var pub []Issuer
	for _, i := range issuers {
		anchors = append(anchors, anchorOf(i, RoleIssuer))
		pub = append(pub, issuerOf(i))
	}
	p, err := Build("home.example.net", epoch, maxAge, anchors, pub, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b, err := Sign(p, root.key)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustVerify(t *testing.T, b *Bundle, opts VerifyOptions) *Payload {
	t.Helper()
	p, err := Verify(b, opts)
	if err != nil {
		t.Fatalf("expected the bundle to verify: %v", err)
	}
	return p
}

func wantErr(t *testing.T, err error, contains string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a refusal mentioning %q, got acceptance", contains)
	}
	if !strings.Contains(err.Error(), contains) {
		t.Fatalf("expected the refusal to mention %q, got: %v", contains, err)
	}
}

// A bundle signed by the pinned root is accepted, and both consumer styles can
// select from the same artifact.
func TestOneBundleServesBothAnchorChoices(t *testing.T) {
	root := mkCA(t, "example root", nil)
	a := mkCA(t, "issuer a", root)
	b := mkCA(t, "issuer b", root)
	bundle := mkBundle(t, root, 1, time.Hour, a, b)

	p := mustVerify(t, bundle, VerifyOptions{PinnedSPKI: Fingerprint(root.cert), Domain: "home.example.net", Now: time.Now()})

	// Cascade: anchor on the root, accept leaves from any issuer beneath it.
	cascade, err := p.SelectAnchor(RoleRoot, "")
	if err != nil {
		t.Fatal(err)
	}
	if cascade.SPKI != Fingerprint(root.cert) {
		t.Fatal("cascade consumer did not select the root")
	}
	roots, inter, err := p.Pool(cascade)
	if err != nil {
		t.Fatal(err)
	}
	leaf := mkCA(t, "leaf under a", a)
	if _, err := leaf.cert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("cascade consumer should accept a leaf from any issuer: %v", err)
	}

	// Pinned: anchor on one issuer, and reject the sibling's leaves.
	pinned, err := p.SelectAnchor(RoleIssuer, "issuer a")
	if err != nil {
		t.Fatal(err)
	}
	roots, inter, err = p.Pool(pinned)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.cert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("a consumer pinned to issuer a should accept issuer a's leaf: %v", err)
	}
	otherLeaf := mkCA(t, "leaf under b", b)
	if _, err := otherLeaf.cert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err == nil {
		t.Fatal("a consumer pinned to issuer a accepted issuer b's leaf: the subdivision is not real")
	}
}

// A bundle from an entirely different root must not be accepted just because it
// is well formed and internally consistent.
func TestForgedBundleFromAnotherRootIsRefused(t *testing.T) {
	real := mkCA(t, "example root", nil)
	realIssuer := mkCA(t, "issuer a", real)
	attacker := mkCA(t, "example root", nil) // same name, different key
	attackerIssuer := mkCA(t, "issuer a", attacker)

	forged := mkBundle(t, attacker, 99, time.Hour, attackerIssuer)
	_, err := Verify(forged, VerifyOptions{PinnedSPKI: Fingerprint(real.cert), Now: time.Now()})
	wantErr(t, err, "not signed by the pinned key")
	_ = realIssuer
}

// Altering the payload must break the signature, even by one byte.
func TestTamperedPayloadIsRefused(t *testing.T) {
	root := mkCA(t, "example root", nil)
	a := mkCA(t, "issuer a", root)
	rogue := mkCA(t, "rogue issuer", nil)
	bundle := mkBundle(t, root, 1, time.Hour, a)

	// Splice in an extra issuer, as a man in the middle would.
	p, err := PayloadOf(bundle)
	if err != nil {
		t.Fatal(err)
	}
	p.Issuers = append(p.Issuers, issuerOf(rogue))
	raw, _ := json.Marshal(p)
	bundle.Payload = base64.StdEncoding.EncodeToString(raw)

	_, err = Verify(bundle, VerifyOptions{PinnedSPKI: Fingerprint(root.cert), Now: time.Now()})
	wantErr(t, err, "altered after it was signed")
}

// An old bundle stays a valid signed artifact forever. Replaying one is the
// natural way to suppress a change, so a consumer must refuse to go backwards.
func TestReplayedOlderBundleIsRefused(t *testing.T) {
	root := mkCA(t, "example root", nil)
	a := mkCA(t, "issuer a", root)
	b := mkCA(t, "issuer b", root)

	old := mkBundle(t, root, 4, time.Hour, a, b)
	current := mkBundle(t, root, 5, time.Hour, a) // b withdrawn

	pin := Fingerprint(root.cert)
	mustVerify(t, current, VerifyOptions{PinnedSPKI: pin, Now: time.Now(), LastEpoch: 4})

	// Having accepted 5, an attacker serves 4 again to bring issuer b back.
	_, err := Verify(old, VerifyOptions{PinnedSPKI: pin, Now: time.Now(), LastEpoch: 5})
	wantErr(t, err, "Refusing to move backwards")
}

// Staleness fails closed: past its max age a bundle is refused, not used with a
// warning, because serving a stale one is how a withdrawal gets hidden.
func TestStaleBundleFailsClosed(t *testing.T) {
	root := mkCA(t, "example root", nil)
	a := mkCA(t, "issuer a", root)
	bundle := mkBundle(t, root, 1, time.Hour, a)
	pin := Fingerprint(root.cert)

	mustVerify(t, bundle, VerifyOptions{PinnedSPKI: pin, Now: time.Now().Add(30 * time.Minute)})

	_, err := Verify(bundle, VerifyOptions{PinnedSPKI: pin, Now: time.Now().Add(2 * time.Hour)})
	wantErr(t, err, "went stale")
}

// A bundle timestamped in the future is refused rather than believed.
func TestFutureDatedBundleIsRefused(t *testing.T) {
	root := mkCA(t, "example root", nil)
	a := mkCA(t, "issuer a", root)
	bundle := mkBundle(t, root, 1, time.Hour, a)
	_, err := Verify(bundle, VerifyOptions{
		PinnedSPKI: Fingerprint(root.cert), Now: time.Now().Add(-24 * time.Hour), Skew: 5 * time.Minute})
	wantErr(t, err, "in the future")
}

// Trust domains are never merged: a bundle describing another domain is refused
// even when correctly signed by its own root.
func TestBundleForAnotherDomainIsRefused(t *testing.T) {
	root := mkCA(t, "aws root", nil)
	a := mkCA(t, "issuer a", root)
	bundle := mkBundle(t, root, 1, time.Hour, a) // built for home.example.net

	_, err := Verify(bundle, VerifyOptions{
		PinnedSPKI: Fingerprint(root.cert), Domain: "aws.example.net", Now: time.Now()})
	wantErr(t, err, "Trust domains are kept")
}

// Without a pin a bundle vouches for itself, so verification must refuse rather
// than fall back to trusting the anchors it happens to contain.
func TestUnpinnedVerificationIsRefused(t *testing.T) {
	root := mkCA(t, "example root", nil)
	a := mkCA(t, "issuer a", root)
	bundle := mkBundle(t, root, 1, time.Hour, a)
	_, err := Verify(bundle, VerifyOptions{Now: time.Now()})
	wantErr(t, err, "no pinned key was supplied")
}

// A revoked issuer must not help build a path, or withdrawing one would be
// advisory.
func TestRevokedIssuerIsNotUsableForPathBuilding(t *testing.T) {
	root := mkCA(t, "example root", nil)
	good := mkCA(t, "issuer good", root)
	bad := mkCA(t, "issuer compromised", root)

	anchors := []Anchor{anchorOf(root, RoleRoot)}
	p, err := Build("home.example.net", 2, time.Hour, anchors, []Issuer{issuerOf(good), issuerOf(bad)}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p.Revoked = []string{Fingerprint(bad.cert)}
	b, err := Sign(p, root.key)
	if err != nil {
		t.Fatal(err)
	}
	got := mustVerify(t, b, VerifyOptions{PinnedSPKI: Fingerprint(root.cert), Now: time.Now()})

	anchor, _ := got.SelectAnchor(RoleRoot, "")
	roots, inter, err := got.Pool(anchor)
	if err != nil {
		t.Fatal(err)
	}
	goodLeaf := mkCA(t, "leaf good", good)
	if _, err := goodLeaf.cert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("a leaf from the surviving issuer should still verify: %v", err)
	}
	badLeaf := mkCA(t, "leaf bad", bad)
	if _, err := badLeaf.cert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err == nil {
		t.Fatal("a leaf from the revoked issuer still verified: revocation in the bundle is decorative")
	}
}

// A bundle whose signer is not among its own anchors would leave a reader
// unable to check it against anything, so it is refused.
func TestBundleNotContainingItsOwnSignerIsRefused(t *testing.T) {
	root := mkCA(t, "example root", nil)
	a := mkCA(t, "issuer a", root)
	p, err := Build("home.example.net", 1, time.Hour,
		[]Anchor{anchorOf(a, RoleIssuer)}, []Issuer{issuerOf(a)}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b, err := Sign(p, root.key) // signed by the root, which is not an anchor here
	if err != nil {
		t.Fatal(err)
	}
	// The pinned key is not among the anchors, so no anchor's COMPUTED
	// fingerprint matches it and the bundle is refused. (This used to be
	// reported via the declared-SPKI lookup; that lookup was the pin bypass.)
	_, err = Verify(b, VerifyOptions{PinnedSPKI: Fingerprint(root.cert), Now: time.Now()})
	wantErr(t, err, "not signed by the pinned key")
}

// A bundle with no anchors, or no expiry, is refused at build time: both would
// produce an artifact that cannot fail closed later.
func TestDegenerateBundlesAreRefusedAtBuild(t *testing.T) {
	root := mkCA(t, "example root", nil)
	if _, err := Build("home.example.net", 1, time.Hour, nil, nil, time.Now()); err == nil {
		t.Fatal("a bundle with no anchors was built")
	}
	if _, err := Build("home.example.net", 1, 0, []Anchor{anchorOf(root, RoleRoot)}, nil, time.Now()); err == nil {
		t.Fatal("a bundle with no max age was built")
	}
	if _, err := Build("", 1, time.Hour, []Anchor{anchorOf(root, RoleRoot)}, nil, time.Now()); err == nil {
		t.Fatal("a bundle with no domain was built")
	}
}

// Consumer state is what makes epochs mean anything, so it must survive a
// restart and must not silently re-pin to a different key.
func TestStateRemembersEpochAndRefusesSilentRepin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trust.json")
	st, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Pin("home.example.net", "sha256:AAA"); err != nil {
		t.Fatal(err)
	}
	st.Accept("home.example.net", 7, time.Now().Unix())
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}

	reloaded, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.Get("home.example.net").LastEpoch; got != 7 {
		t.Fatalf("epoch did not survive a restart: got %d, want 7", got)
	}
	// Rolling the remembered epoch backwards is not possible through Accept.
	reloaded.Accept("home.example.net", 3, time.Now().Unix())
	if got := reloaded.Get("home.example.net").LastEpoch; got != 7 {
		t.Fatalf("remembered epoch moved backwards to %d", got)
	}
	// Re-pinning to a different key is a deliberate act, not a quiet update.
	err = reloaded.Pin("home.example.net", "sha256:BBB")
	wantErr(t, err, "already pinned")
}

// Anchoring on an intermediate depends on the verifier, and this records which
// behaviour Signet's own stack has.
//
// Measured against the real tools during milestone 4b: Go's crypto/x509 treats
// any certificate in the root pool as a valid trust anchor, self-signed or not,
// so the pinned-issuer mode works. OpenSSL refuses a non-self-signed anchor
// unless run with -partial_chain, so the same bundle and the same anchor fail
// there for reasons that have nothing to do with the certificates. This is the
// same class of finding as E-02: enforcement is not uniform across verifiers,
// so the mode is offered with a warning rather than assumed to work.
func TestPinnedIntermediateAnchorIsAcceptedByGo(t *testing.T) {
	root := mkCA(t, "example root", nil)
	issuer := mkCA(t, "issuer a", root)
	leaf := mkCA(t, "leaf", issuer)

	bundle := mkBundle(t, root, 1, time.Hour, issuer)
	p := mustVerify(t, bundle, VerifyOptions{PinnedSPKI: Fingerprint(root.cert), Now: time.Now()})
	anchor, err := p.SelectAnchor(RoleIssuer, "issuer a")
	if err != nil {
		t.Fatal(err)
	}
	roots, inter, err := p.Pool(anchor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.cert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("Go should accept an intermediate as a trust anchor: %v", err)
	}
	if anchor.CertPEM == nil || string(anchor.CertPEM) == string(root.pem) {
		t.Fatal("the pinned anchor should be the intermediate, not the root")
	}
}

// Clock-skew tolerance must not quietly extend a bundle's life.
//
// This is here because it was a live bug: skew was applied to the staleness
// check as well as the future-dated one, so a bundle stayed usable for a full
// skew window past its max age. The original staleness test missed it by
// passing Skew: 0 while every caller passed five minutes — so this asserts the
// two are independent, with the skew a caller actually uses.
func TestSkewDoesNotExtendAStaleBundle(t *testing.T) {
	root := mkCA(t, "example root", nil)
	a := mkCA(t, "issuer a", root)
	pin := Fingerprint(root.cert)

	p, err := Build("home.example.net", 1, time.Second,
		[]Anchor{anchorOf(root, RoleRoot)}, []Issuer{issuerOf(a)}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b, err := Sign(p, root.key)
	if err != nil {
		t.Fatal(err)
	}
	// Two seconds past a one-second max age, with the five minutes of skew every
	// caller passes. It must still be refused.
	_, err = Verify(b, VerifyOptions{PinnedSPKI: pin, Now: time.Now().Add(2 * time.Second), Skew: 5 * time.Minute})
	wantErr(t, err, "went stale")

	// Skew still does its actual job: absorbing a clock that runs slightly slow
	// relative to the publisher, so a fresh bundle is not read as future-dated.
	_, err = Verify(b, VerifyOptions{PinnedSPKI: pin, Now: time.Now().Add(-30 * time.Second), Skew: 5 * time.Minute})
	if err != nil {
		t.Fatalf("a clock 30s slow should still accept a fresh bundle: %v", err)
	}
}

// The pin must be checked against the key that ACTUALLY signed, not against a
// label the bundle applies to itself.
//
// This was a complete bypass of trust pinning. Verify compared the consumer's
// pinned fingerprint to Anchor.SPKI and Signature.SPKI — both strings the
// bundle declares — and then verified with whatever key the attached
// certificate carried. Fingerprint() existed and was never called here. So an
// attacker who knew only the PUBLIC pin (which is published on purpose: it is
// handed out to every consumer) could mint a bundle under their own root,
// label it with the victim's fingerprint, and have every consumer install it.
//
// It reached the authority node too, through PutTrustBundle.
func TestPinIsCheckedAgainstTheActualSigningKey(t *testing.T) {
	victim := mkCA(t, "Example Root CA", nil)
	victimIssuer := mkCA(t, "issuer a", victim)
	pin := Fingerprint(victim.cert) // public by design — consumers are given it

	// The attacker's own root, with no relationship to the victim's.
	attacker := mkCA(t, "Example Root CA", nil)
	attackerIssuer := mkCA(t, "issuer a", attacker)

	// Build a bundle under the attacker's key, then LABEL its anchor and its
	// signature with the victim's fingerprint. Every declared field says the
	// right thing; only the actual key is wrong.
	p, err := Build("home.example.net", 1, time.Hour,
		[]Anchor{{Role: RoleRoot, Name: "Example Root CA",
			CertPEM: attacker.pem, SPKI: pin}}, // <- the lie
		[]Issuer{issuerOf(attackerIssuer)}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	forged, err := Sign(p, attacker.key)
	if err != nil {
		t.Fatal(err)
	}
	forged.Signatures[0].SPKI = pin // <- the same lie, on the signature

	_, err = Verify(forged, VerifyOptions{PinnedSPKI: pin, Domain: "home.example.net", Now: time.Now()})
	if err == nil {
		t.Fatal("a bundle signed by an unrelated key was accepted because it CLAIMED the pinned fingerprint")
	}
	if !strings.Contains(err.Error(), "does not match") && !strings.Contains(err.Error(), "not signed by the pinned key") {
		t.Fatalf("refused, but not for the right reason: %v", err)
	}

	// The genuine article still verifies, so the fix is not merely "refuse".
	good := mkBundle(t, victim, 1, time.Hour, victimIssuer)
	if _, err := Verify(good, VerifyOptions{PinnedSPKI: pin, Domain: "home.example.net", Now: time.Now()}); err != nil {
		t.Fatalf("the real bundle must still verify: %v", err)
	}
}

// A withdrawn issuer must not be resurrected by relabelling it, either.
func TestRevocationIsKeyedOnTheActualKey(t *testing.T) {
	root := mkCA(t, "example root", nil)
	bad := mkCA(t, "issuer compromised", root)
	leaf := mkCA(t, "leaf", bad)

	anchors := []Anchor{anchorOf(root, RoleRoot)}
	// The published issuer entry lies about its own fingerprint, so a naive
	// revocation check keyed on the declared label would miss it.
	lying := Issuer{Name: "issuer compromised", CertPEM: bad.pem, SPKI: "sha256:not-my-real-fingerprint"}
	p, err := Build("home.example.net", 2, time.Hour, anchors, []Issuer{lying}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p.Revoked = []string{Fingerprint(bad.cert)} // revoked by its REAL fingerprint
	b, err := Sign(p, root.key)
	if err != nil {
		t.Fatal(err)
	}
	got := mustVerify(t, b, VerifyOptions{PinnedSPKI: Fingerprint(root.cert), Now: time.Now()})

	if _, err := got.VerifyCert(leaf.cert, nil, time.Now()); err == nil {
		t.Fatal("a revoked issuer was usable because its published entry misreported its fingerprint")
	}
}

// Only the ROOT anchor may sign a bundle.
//
// Verify accepted any anchor, so a consumer pinned to an ISSUER would accept a
// bundle that issuer signed. An issuing key is authorized to mint leaves inside
// a namespace, not to declare the trust set — that is the invariant this whole
// package rests on, and accepting an issuer-signed bundle let one compromised
// node redefine trust for everyone pinned to it.
func TestOnlyTheRootAnchorMaySignABundle(t *testing.T) {
	root := mkCA(t, "example root", nil)
	issuer := mkCA(t, "issuer a", root)

	// A bundle signed by the ISSUER, with the issuer present as an anchor.
	p, err := Build("home.example.net", 1, time.Hour,
		[]Anchor{anchorOf(root, RoleRoot), anchorOf(issuer, RoleIssuer)},
		[]Issuer{issuerOf(issuer)}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b, err := Sign(p, issuer.key)
	if err != nil {
		t.Fatal(err)
	}

	// A consumer pinned to that issuer must still refuse it.
	_, err = Verify(b, VerifyOptions{PinnedSPKI: Fingerprint(issuer.cert), Now: time.Now()})
	wantErr(t, err, "not signed by the pinned key")
}

// One epoch must mean one trust set. A non-strict rollback check let two
// DIFFERENT bundles share an epoch, so a withdrawal could be undone by
// republishing the pre-withdrawal content under its original number.
func TestSameEpochWithDifferentContentIsRefused(t *testing.T) {
	root := mkCA(t, "example root", nil)
	a := mkCA(t, "issuer a", root)
	b := mkCA(t, "issuer b", root)
	pin := Fingerprint(root.cert)

	withB := mkBundle(t, root, 5, time.Hour, a, b) // before the withdrawal
	withoutB := mkBundle(t, root, 5, time.Hour, a) // same epoch, b withdrawn

	accepted := mustVerify(t, withoutB, VerifyOptions{PinnedSPKI: pin, Now: time.Now()})
	if accepted.Epoch != 5 {
		t.Fatal("precondition")
	}
	digest := DigestOf(withoutB)

	// Re-presenting the SAME bundle at that epoch is fine — refresh must work.
	if _, err := Verify(withoutB, VerifyOptions{
		PinnedSPKI: pin, LastEpoch: 5, LastDigest: digest, Now: time.Now()}); err != nil {
		t.Fatalf("re-accepting the identical bundle should be allowed: %v", err)
	}

	// Different content under the same number is not.
	_, err := Verify(withB, VerifyOptions{
		PinnedSPKI: pin, LastEpoch: 5, LastDigest: digest, Now: time.Now()})
	wantErr(t, err, "cannot share an epoch")
}
