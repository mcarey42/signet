package ca

import (
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"testing"
	"time"

	"github.com/mcarey42/signet/internal/seal"
)

func fileSeal(t *testing.T) seal.Seal {
	t.Helper()
	p := filepath.Join(t.TempDir(), "seal.key")
	if err := seal.GenerateKeyFile(p); err != nil {
		t.Fatal(err)
	}
	s, err := seal.OpenFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func parse(t *testing.T, p []byte) *x509.Certificate {
	t.Helper()
	blk, _ := pem.Decode(p)
	if blk == nil {
		t.Fatal("not PEM")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The point of the split ceremony: one root certifies several issuers, each
// holding its own key, and every leaf still chains to that one root. This is
// what lets nodes with different custody serve the same trust chain.
func TestOneRootCertifiesSeveralIndependentIssuers(t *testing.T) {
	now := time.Now()
	root, err := NewRoot("Test", 10*365*24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	rootCert, rootSigner, err := LoadRootSigner(root.CertPEM, root.KeyPEM, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(rootCert)
	var issuers []*x509.Certificate

	for _, name := range []string{"issuer one", "issuer two", "issuer three"} {
		// Each issuer generates its own key — nothing is shared or copied.
		req, err := NewIssuerRequest(fileSeal(t), name, "label")
		if err != nil {
			t.Fatal(err)
		}
		certPEM, err := SignIssuer(rootCert, rootSigner, req.CSRPEM,
			[]string{"example.com"}, nil, 365*24*time.Hour, now)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		cert := parse(t, certPEM)
		if cert.Subject.CommonName != name {
			t.Errorf("issuer CN = %q, want %q", cert.Subject.CommonName, name)
		}
		if !cert.IsCA {
			t.Errorf("%s is not a CA certificate", name)
		}
		if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			t.Errorf("%s does not chain to the root: %v", name, err)
		}
		issuers = append(issuers, cert)
	}

	// Independent keys: no two issuers share one, which is what makes losing a
	// node cost only that node.
	for i := range issuers {
		for j := i + 1; j < len(issuers); j++ {
			if issuers[i].Subject.CommonName == issuers[j].Subject.CommonName {
				t.Fatal("issuers are not distinct")
			}
			if string(issuers[i].RawSubjectPublicKeyInfo) == string(issuers[j].RawSubjectPublicKeyInfo) {
				t.Fatal("two issuers share a public key, so their keys were copied rather than generated separately")
			}
		}
	}
	// The delegated namespace is what bounds each issuer forever.
	for _, c := range issuers {
		if len(c.PermittedDNSDomains) != 1 || c.PermittedDNSDomains[0] != "example.com" {
			t.Errorf("issuer %q lacks its delegated name constraint: %v", c.Subject.CommonName, c.PermittedDNSDomains)
		}
	}
}

// A signing request whose signature does not verify must be refused: otherwise
// a node could obtain an issuing certificate over a key it does not hold.
func TestSignIssuerRejectsATamperedRequest(t *testing.T) {
	now := time.Now()
	root, _ := NewRoot("Test", 10*365*24*time.Hour, now)
	rootCert, rootSigner, err := LoadRootSigner(root.CertPEM, root.KeyPEM, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	req, err := NewIssuerRequest(fileSeal(t), "issuer", "label")
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(req.CSRPEM)
	tampered := append([]byte{}, blk.Bytes...)
	tampered[len(tampered)/3] ^= 0xff
	bad := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: tampered})

	if _, err := SignIssuer(rootCert, rootSigner, bad, []string{"example.com"}, nil, time.Hour, now); err == nil {
		t.Fatal("signed a request whose signature does not verify")
	}
}

// An issuer that outlives its root would fail verification later, in the field,
// rather than here where it is cheap to notice.
func TestSignIssuerRefusesToOutliveItsRoot(t *testing.T) {
	now := time.Now()
	root, _ := NewRoot("Test", 24*time.Hour, now)
	rootCert, rootSigner, err := LoadRootSigner(root.CertPEM, root.KeyPEM, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := NewIssuerRequest(fileSeal(t), "issuer", "label")
	if _, err := SignIssuer(rootCert, rootSigner, req.CSRPEM, []string{"example.com"}, nil, 365*24*time.Hour, now); err == nil {
		t.Fatal("signed an issuer that outlives its own root")
	}
}

// The root ceremony produces a key the caller holds; it is never bundled into
// the material a node stores.
func TestRootKeyIsSeparateFromIssuerMaterial(t *testing.T) {
	root, err := NewRoot("Test", 10*365*24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(root.KeyPEM) == 0 {
		t.Fatal("software root produced no key for the operator to take offline")
	}
	req, _ := NewIssuerRequest(fileSeal(t), "issuer", "label")
	rootCert, rootSigner, _ := LoadRootSigner(root.CertPEM, root.KeyPEM, nil, nil)
	certPEM, err := SignIssuer(rootCert, rootSigner, req.CSRPEM, []string{"example.com"}, nil, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	m, err := AssembleIssuer(root.CertPEM, certPEM, req)
	if err != nil {
		t.Fatal(err)
	}
	// The material a node stores carries the root's certificate but never its key.
	if string(m.RootCertPEM) != string(root.CertPEM) {
		t.Error("issuer material lost the root certificate")
	}
	blob := string(m.RootCertPEM) + string(m.IntermediateCertPEM) + string(m.IntermediateKeyPEM)
	if len(root.KeyPEM) > 0 && contains(blob, string(root.KeyPEM)) {
		t.Fatal("the root private key leaked into the material a node stores")
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		func() bool {
			for i := 0; i+len(needle) <= len(haystack); i++ {
				if haystack[i:i+len(needle)] == needle {
					return true
				}
			}
			return false
		}()
}
