package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

func testCA(t *testing.T) *CA {
	t.Helper()
	res, err := Genesis("Test", []string{"example.com"}, nil, 10*365*24*time.Hour, 365*24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// The root key is returned to the caller and is not part of the material
	// that gets stored — that separation is the whole point of the ceremony.
	if len(res.RootKeyPEM) == 0 {
		t.Fatal("ceremony produced no root key")
	}
	if strings.Contains(string(res.Material.RootCertPEM), "PRIVATE KEY") ||
		strings.Contains(string(res.Material.IntermediateCertPEM), "PRIVATE KEY") {
		t.Fatal("a private key leaked into stored certificate material")
	}
	c, err := Load(res.Material)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func csrFor(t *testing.T, cn string, dns []string, ips []net.IP, uris []*url.URL) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: cn},
		DNSNames:    dns,
		IPAddresses: ips,
		URIs:        uris,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func role() Role {
	return Role{
		Name: "server", Scope: "/pki/server",
		AllowedDomains: []string{"example.com"}, AllowSubdomains: true,
		MaxTTLSeconds: int64((24 * time.Hour).Seconds()),
	}
}

func TestSignHappyPath(t *testing.T) {
	c := testCA(t)
	now := time.Now()
	serial, _ := NewSerial()
	issued, err := c.Sign(Request{
		CSRPEM: csrFor(t, "web.example.com", []string{"web.example.com"}, nil, nil),
		TTL:    time.Hour,
	}, role(), serial, now)
	if err != nil {
		t.Fatal(err)
	}

	blk, _ := pem.Decode(issued.CertPEM)
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "web.example.com" {
		t.Errorf("CN = %q", cert.Subject.CommonName)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "web.example.com" {
		t.Errorf("SANs = %v", cert.DNSNames)
	}
	if cert.IsCA {
		t.Error("leaf carries the CA bit")
	}
	if issued.Serial == "" || issued.ChainPEM == nil {
		t.Error("issuance is missing its serial or chain")
	}
	// The certificate must verify against the CA's own chain, the way any
	// relying party would check it.
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(c.RootPEM())
	inter := x509.NewCertPool()
	inter.AppendCertsFromPEM(c.material.IntermediateCertPEM)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Errorf("issued certificate does not verify: %v", err)
	}
}

// The role is what bounds a request, and the request supplies the names — so
// every one of these is an attempt to be issued an identity nobody granted.
func TestSignRefusesNamesOutsideTheRole(t *testing.T) {
	c := testCA(t)
	now := time.Now()
	uri, _ := url.Parse("spiffe://other.example/ns/x")

	cases := []struct {
		name string
		req  Request
	}{
		{"a different domain entirely",
			Request{CSRPEM: csrFor(t, "evil.test", []string{"evil.test"}, nil, nil)}},
		{"a domain that merely ends with the allowed one",
			Request{CSRPEM: csrFor(t, "notexample.com", []string{"notexample.com"}, nil, nil)}},
		{"a suffix trick without a dot boundary",
			Request{CSRPEM: csrFor(t, "evilexample.com", []string{"evilexample.com"}, nil, nil)}},
		{"an out-of-scope name added alongside a permitted one",
			Request{CSRPEM: csrFor(t, "web.example.com", []string{"web.example.com", "evil.test"}, nil, nil)}},
		{"an out-of-scope name smuggled through the request rather than the CSR",
			Request{CSRPEM: csrFor(t, "web.example.com", []string{"web.example.com"}, nil, nil),
				DNSNames: []string{"evil.test"}}},
		{"an IP address the role does not allow",
			Request{CSRPEM: csrFor(t, "web.example.com", []string{"web.example.com"}, []net.IP{net.ParseIP("10.0.0.1")}, nil)}},
		{"a URI SAN with no permitted prefix",
			Request{CSRPEM: csrFor(t, "web.example.com", []string{"web.example.com"}, nil, []*url.URL{uri})}},
	}
	for _, c2 := range cases {
		serial, _ := NewSerial()
		if _, err := c.Sign(c2.req, role(), serial, now); err == nil {
			t.Errorf("%s: signed, must be refused", c2.name)
		}
	}
}

// Verify is the gate that runs on the bytes that actually came out. This proves
// it independently rejects a certificate the builder should never have made —
// the case where Sign itself has the bug.
func TestVerifyCatchesMisIssuance(t *testing.T) {
	c := testCA(t)
	now := time.Now()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := NewSerial()

	// Forge exactly what a buggy builder would produce: a well-formed
	// certificate from this CA, for a name the role does not permit.
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "evil.test"},
		DNSNames:     []string{"evil.test"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.intermediate, key.Public(), c.key)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(der, role(), now); err == nil {
		t.Fatal("Verify accepted a certificate for a name outside the role")
	}

	// A certificate whose lifetime exceeds the role's maximum.
	long := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "web.example.com"},
		DNSNames:  []string{"web.example.com"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(72 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err = x509.CreateCertificate(rand.Reader, long, c.intermediate, key.Public(), c.key)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(der, role(), now); err == nil {
		t.Fatal("Verify accepted a certificate that outlives the role's maximum TTL")
	}

	// A leaf that claims to be a CA.
	caLeaf := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "web.example.com"},
		DNSNames:  []string{"web.example.com"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	der, err = x509.CreateCertificate(rand.Reader, caLeaf, c.intermediate, key.Public(), c.key)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(der, role(), now); err == nil {
		t.Fatal("Verify accepted a leaf carrying the CA bit")
	}

	// A certificate with no SANs at all: name constraints bound SANs, not the
	// common name, so nothing would constrain it.
	bare := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "web.example.com"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err = x509.CreateCertificate(rand.Reader, bare, c.intermediate, key.Public(), c.key)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(der, role(), now); err == nil {
		t.Fatal("Verify accepted a certificate with no subject alternative names")
	}
}

// A CSR proves possession of the private key. Without checking it, a caller
// could obtain a certificate over somebody else's public key.
func TestSignRejectsTamperedCSR(t *testing.T) {
	c := testCA(t)
	good := csrFor(t, "web.example.com", []string{"web.example.com"}, nil, nil)
	blk, _ := pem.Decode(good)
	// Flip a byte in the encoded subject region; the signature no longer matches.
	tampered := make([]byte, len(blk.Bytes))
	copy(tampered, blk.Bytes)
	tampered[len(tampered)/3] ^= 0xff
	bad := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: tampered})

	serial, _ := NewSerial()
	if _, err := c.Sign(Request{CSRPEM: bad}, role(), serial, time.Now()); err == nil {
		t.Fatal("signed a CSR whose signature does not verify")
	}
}

func TestTTLIsClampedToTheRole(t *testing.T) {
	c := testCA(t)
	now := time.Now()
	serial, _ := NewSerial()
	issued, err := c.Sign(Request{
		CSRPEM: csrFor(t, "web.example.com", []string{"web.example.com"}, nil, nil),
		TTL:    365 * 24 * time.Hour, // far beyond the role's 24h
	}, role(), serial, now)
	if err != nil {
		t.Fatal(err)
	}
	if issued.NotAfter.After(now.Add(25 * time.Hour)) {
		t.Errorf("TTL not clamped: expires %s", issued.NotAfter)
	}
}

// Subdomains are allowed only when the role says so, and a bare domain is not
// a subdomain of itself.
func TestSubdomainAndBareDomainRules(t *testing.T) {
	strict := Role{Name: "strict", AllowedDomains: []string{"example.com"}}
	if domainAllowed(strict, "example.com") {
		t.Error("bare domain allowed without allow_bare_domains")
	}
	if domainAllowed(strict, "web.example.com") {
		t.Error("subdomain allowed without allow_subdomains")
	}
	bare := Role{Name: "bare", AllowedDomains: []string{"example.com"}, AllowBareDomains: true}
	if !domainAllowed(bare, "example.com") {
		t.Error("bare domain refused with allow_bare_domains")
	}
	if domainAllowed(bare, "web.example.com") {
		t.Error("subdomain allowed with only allow_bare_domains")
	}
	sub := Role{Name: "sub", AllowedDomains: []string{"example.com"}, AllowSubdomains: true}
	if !domainAllowed(sub, "web.example.com") || !domainAllowed(sub, "a.b.example.com") {
		t.Error("subdomain refused with allow_subdomains")
	}
	if domainAllowed(sub, "evilexample.com") {
		t.Error("suffix without a dot boundary treated as a subdomain")
	}
	// Case and a trailing dot are the same name.
	if !domainAllowed(sub, "WEB.EXAMPLE.COM.") {
		t.Error("case or trailing dot changed the answer")
	}
}
