package trust

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/url"
	"path/filepath"
	"testing"
	"time"
)

// mkLeaf issues a leaf carrying a spiffe:// identity, which is how a
// certificate says which trust domain it belongs to.
func mkLeaf(t *testing.T, issuer *testCA, spiffeID string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(issuer.key.Curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(spiffeID)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: u.Path},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		URIs:         []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer.cert, key.Public(), issuer.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// bundleFor builds and signs a bundle for a named domain.
func bundleFor(t *testing.T, domain string, root *testCA, issuers ...*testCA) []byte {
	t.Helper()
	anchors := []Anchor{anchorOf(root, RoleRoot)}
	var pub []Issuer
	for _, i := range issuers {
		anchors = append(anchors, anchorOf(i, RoleIssuer))
		pub = append(pub, issuerOf(i))
	}
	p, err := Build(domain, 1, time.Hour, anchors, pub, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b, err := Sign(p, root.key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func newFabric(t *testing.T) *State {
	t.Helper()
	st, err := LoadState(filepath.Join(t.TempDir(), "trust.json"))
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// The headline finding of milestone 4c, and the reason VerifyCert exists.
//
// Under cascade every domain's issuer descends from one organizational root, so
// a sibling's issuer chains to the same anchor. If the presenter supplies that
// issuer — which is exactly what a TLS peer does with its own chain — the path
// is genuinely valid and the sibling can assert another domain's identities.
//
// Building a path is therefore not proof that a domain vouched for something.
// The chain must also run only through issuers that domain published.
func TestCascadeSiblingCannotImpersonateViaSuppliedIntermediate(t *testing.T) {
	orgRoot := mkCA(t, "Example Root CA", nil)
	homeIssuer := mkCA(t, "home issuer", orgRoot)
	gcpIssuer := mkCA(t, "gcp issuer", orgRoot)

	gcpBundle := bundleFor(t, "gcp.example.net", orgRoot, gcpIssuer)
	p := mustPayload(t, gcpBundle)

	// home mints a certificate claiming a gcp identity, and presents its own
	// issuer alongside it the way a TLS server presents its chain.
	forged := mkLeaf(t, homeIssuer, "spiffe://gcp.example.net/workload/api")
	supplied := []*x509.Certificate{homeIssuer.cert}

	// Precondition: the chain really is cryptographically valid. Without this
	// the test would prove nothing about *why* the certificate is refused.
	anchor, err := p.SelectAnchor(RoleRoot, "")
	if err != nil {
		t.Fatal(err)
	}
	roots, inter, err := p.Pool(anchor)
	if err != nil {
		t.Fatal(err)
	}
	inter.AddCert(homeIssuer.cert)
	if _, err := forged.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("precondition: under a shared root the forged chain SHOULD verify, got: %v", err)
	}

	// And yet the bundle refuses it, because home's issuer is not one gcp
	// publishes.
	_, err = p.VerifyCert(forged, supplied, time.Now())
	wantErr(t, err, "which the domain does not publish as one of its issuers")

	// The genuine article still works, including when extra certs are supplied.
	real := mkLeaf(t, gcpIssuer, "spiffe://gcp.example.net/workload/api")
	if _, err := p.VerifyCert(real, supplied, time.Now()); err != nil {
		t.Fatalf("gcp's own leaf should verify: %v", err)
	}
}

// The same attack through the fabric's own entry point, which is what a relying
// party actually calls.
func TestFabricRefusesSiblingImpersonation(t *testing.T) {
	orgRoot := mkCA(t, "Example Root CA", nil)
	homeIssuer := mkCA(t, "home issuer", orgRoot)
	gcpIssuer := mkCA(t, "gcp issuer", orgRoot)

	fab := newFabric(t)
	for _, d := range []struct {
		name   string
		issuer *testCA
	}{{"home.example.net", homeIssuer}, {"gcp.example.net", gcpIssuer}} {
		if _, err := fab.Peer(Fingerprint(orgRoot.cert), bundleFor(t, d.name, orgRoot, d.issuer), time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	forged := mkLeaf(t, homeIssuer, "spiffe://gcp.example.net/workload/api")
	_, err := fab.VerifyLeafWith(forged, []*x509.Certificate{homeIssuer.cert}, "", time.Now())
	wantErr(t, err, "does not publish as one of its issuers")
}

// The same certificate, checked against the domain that may vouch for it, is
// accepted — so the refusal above is scoping, not breakage.
func TestIdentityIsAcceptedByItsOwnDomain(t *testing.T) {
	orgRoot := mkCA(t, "Example Root CA", nil)
	homeIssuer := mkCA(t, "home issuer", orgRoot)
	gcpIssuer := mkCA(t, "gcp issuer", orgRoot)

	fab := newFabric(t)
	for _, d := range []struct {
		name   string
		issuer *testCA
	}{{"home.example.net", homeIssuer}, {"gcp.example.net", gcpIssuer}} {
		if _, err := fab.Peer(Fingerprint(orgRoot.cert), bundleFor(t, d.name, orgRoot, d.issuer), time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	leaf := mkLeaf(t, gcpIssuer, "spiffe://gcp.example.net/workload/api")
	id, err := fab.VerifyLeaf(leaf, "", time.Now())
	if err != nil {
		t.Fatalf("gcp's own domain should vouch for it: %v", err)
	}
	if id.Domain != "gcp.example.net" {
		t.Fatalf("verified under the wrong domain: %s", id.Domain)
	}

	// Federating with gcp must not give gcp authority over home's namespace.
	impostor := mkLeaf(t, gcpIssuer, "spiffe://home.example.net/people/root")
	_, err = fab.VerifyLeaf(impostor, "", time.Now())
	wantErr(t, err, "does not vouch for this certificate")
}

// A sovereign domain stands on its own root, so a cascade consumer cannot build
// a path to it at all. The separation is cryptographic, not merely policy.
func TestSovereignDomainIsSeparatedCryptographically(t *testing.T) {
	orgRoot := mkCA(t, "Example Root CA", nil)
	homeIssuer := mkCA(t, "home issuer", orgRoot)
	awsRoot := mkCA(t, "AWS Root CA", nil) // its own root, not signed by the org
	awsIssuer := mkCA(t, "aws issuer", awsRoot)

	fab := newFabric(t)
	if _, err := fab.Peer(Fingerprint(orgRoot.cert), bundleFor(t, "home.example.net", orgRoot, homeIssuer), time.Now()); err != nil {
		t.Fatal(err)
	}

	// Without a federation link, aws identities are simply not recognized.
	awsLeaf := mkLeaf(t, awsIssuer, "spiffe://aws.example.net/workload/api")
	_, err := fab.VerifyLeaf(awsLeaf, "", time.Now())
	wantErr(t, err, "no trust bundle for domain")

	// With one, they verify — under aws's own root, not the org's.
	awsBundle := bundleFor(t, "aws.example.net", awsRoot, awsIssuer)
	if _, err := fab.Peer(Fingerprint(awsRoot.cert), awsBundle, time.Now()); err != nil {
		t.Fatal(err)
	}
	id, err := fab.VerifyLeaf(awsLeaf, "", time.Now())
	if err != nil {
		t.Fatalf("aws should vouch for its own identity: %v", err)
	}
	if id.Domain != "aws.example.net" {
		t.Fatalf("wrong domain: %s", id.Domain)
	}

	// The org root cannot mint into a sovereign domain's namespace. This is the
	// concrete difference from cascade: under cascade the org root could
	// produce a chain that verifies and be stopped only by the namespace check;
	// here it cannot produce a verifying chain at all.
	forged := mkLeaf(t, homeIssuer, "spiffe://aws.example.net/workload/api")
	_, err = fab.VerifyLeaf(forged, "", time.Now())
	wantErr(t, err, "does not vouch for this certificate")

	// And the stronger statement: even handed home's whole chain up to the org
	// root, aws still refuses — there is no path from aws's root to anything
	// the org signed. Under cascade the equivalent forgery is stopped by
	// policy; here it is stopped by arithmetic.
	_, err = fab.VerifyLeafWith(forged,
		[]*x509.Certificate{homeIssuer.cert, orgRoot.cert}, "", time.Now())
	wantErr(t, err, "does not vouch for this certificate")

	// Sovereignty is a property of the fabric, not of one bundle: from a single
	// bundle a domain's own root and its parent's look identical. What a
	// consumer can see is whether two domains it trusts present the same root.
	if got := fab.Sovereignty("aws.example.net"); got != "sovereign" {
		t.Fatalf("aws stands on its own root; got %q", got)
	}
	if got := fab.Sovereignty("home.example.net"); got != "sovereign" {
		t.Fatalf("home is the only org-rooted domain here, so nothing is shared yet; got %q", got)
	}

	// Federate with a second org-rooted domain and the shared root becomes
	// visible — neither is sovereign against the other any more.
	gcpIssuer := mkCA(t, "gcp issuer", orgRoot)
	if _, err := fab.Peer(Fingerprint(orgRoot.cert), bundleFor(t, "gcp.example.net", orgRoot, gcpIssuer), time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := fab.Sovereignty("home.example.net"); got != "shared root" {
		t.Fatalf("home and gcp share the org root; got %q", got)
	}
	if got := fab.SharesRootWith("home.example.net"); len(got) != 1 || got[0] != "gcp.example.net" {
		t.Fatalf("home should be reported as sharing a root with gcp; got %v", got)
	}
	if got := fab.Sovereignty("aws.example.net"); got != "sovereign" {
		t.Fatalf("aws remains sovereign regardless of who else joins; got %q", got)
	}
	_ = awsBundle
}

// A caller may not relabel a certificate that already names its own domain.
func TestDomainHintCannotOverrideTheCertificatesOwnClaim(t *testing.T) {
	orgRoot := mkCA(t, "Example Root CA", nil)
	homeIssuer := mkCA(t, "home issuer", orgRoot)
	fab := newFabric(t)
	if _, err := fab.Peer(Fingerprint(orgRoot.cert), bundleFor(t, "home.example.net", orgRoot, homeIssuer), time.Now()); err != nil {
		t.Fatal(err)
	}
	leaf := mkLeaf(t, homeIssuer, "spiffe://gcp.example.net/workload/api")
	_, err := fab.VerifyLeaf(leaf, "home.example.net", time.Now())
	wantErr(t, err, "The certificate's own name wins")
}

// A peer may describe only itself: a bundle is filed under the domain it
// verifiably claims, never under one the caller chooses.
func TestPeerCannotFileABundleUnderAnotherDomainsName(t *testing.T) {
	awsRoot := mkCA(t, "AWS Root CA", nil)
	awsIssuer := mkCA(t, "aws issuer", awsRoot)
	fab := newFabric(t)

	p, err := fab.Peer(Fingerprint(awsRoot.cert), bundleFor(t, "aws.example.net", awsRoot, awsIssuer), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if p.Domain != "aws.example.net" {
		t.Fatalf("filed under %q", p.Domain)
	}
	if _, ok := fab.Domains["home.example.net"]; ok {
		t.Fatal("a bundle was filed under a domain it does not describe")
	}
}

// A stored bundle that has gone stale must stop being usable on its own, with
// no one having to remember to re-check it.
func TestStoredBundleGoingStaleStopsVerifying(t *testing.T) {
	root := mkCA(t, "Example Root CA", nil)
	issuer := mkCA(t, "home issuer", root)
	fab := newFabric(t)
	if _, err := fab.Peer(Fingerprint(root.cert), bundleFor(t, "home.example.net", root, issuer), time.Now()); err != nil {
		t.Fatal(err)
	}
	leaf := mkLeaf(t, issuer, "spiffe://home.example.net/workload/api")

	if _, err := fab.VerifyLeaf(leaf, "", time.Now()); err != nil {
		t.Fatalf("should verify while fresh: %v", err)
	}
	// The bundle's max age is an hour; two hours on, it is refused without any
	// re-fetch or explicit expiry sweep.
	_, err := fab.VerifyLeaf(leaf, "", time.Now().Add(2*time.Hour))
	wantErr(t, err, "went stale")
}

// The fabric survives a restart: federation links are persistent state, not
// something rebuilt from memory on each run.
func TestFabricSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trust.json")
	root := mkCA(t, "Example Root CA", nil)
	issuer := mkCA(t, "home issuer", root)

	st, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Peer(Fingerprint(root.cert), bundleFor(t, "home.example.net", root, issuer), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}

	reloaded, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	leaf := mkLeaf(t, issuer, "spiffe://home.example.net/workload/api")
	if _, err := reloaded.VerifyLeaf(leaf, "", time.Now()); err != nil {
		t.Fatalf("a federation link should survive a restart: %v", err)
	}
}

// A domain does not gain authority over names that merely look like its
// children, which would reintroduce transitive trust by string suffix.
func TestSubdomainsAreNotImplicitlyGoverned(t *testing.T) {
	if BelongsTo("prod.aws.example.net", "aws.example.net") {
		t.Fatal("a domain must not implicitly govern its DNS-looking children")
	}
	if !BelongsTo("aws.example.net", "aws.example.net") {
		t.Fatal("exact match should hold")
	}
	if BelongsTo("", "aws.example.net") {
		t.Fatal("an empty identity domain must not match")
	}
}

func mustPayload(t *testing.T, raw []byte) *Payload {
	t.Helper()
	p, err := PayloadOfBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
