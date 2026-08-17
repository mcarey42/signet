package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/mcarey42/signet/internal/seal"
)

// The ceremonies here exist so that one root can serve many issuers.
//
// A domain runs several signing nodes, each generating its key *where that key
// will live* — a PKCS#11 token, a cloud KMS, a file seal — and receiving its own
// intermediate certificate. The root key never travels to a node; a certificate
// signing request travels to the root instead. That asymmetry is what makes
// heterogeneous custody routine rather than a special case, and it is why the
// steps are separate commands rather than one genesis call (docs/02).

// Root is a certificate authority's top certificate together with whatever is
// needed to sign with it. The key is present only during a ceremony.
type Root struct {
	CertPEM []byte
	KeyPEM  []byte       // software roots only; empty when held in hardware
	Ref     *seal.KeyRef // hardware roots only
}

// NewRoot creates a root certificate authority and nothing else.
//
// Deliberately separate from issuing: a root is created once, kept offline, and
// used a handful of times per decade. Bundling it with an issuer — as a single
// genesis call must — quietly assumes one signing node forever.
func NewRoot(commonName string, ttl time.Duration, now time.Time) (*Root, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating the root key: %w", err)
	}
	certPEM, err := selfSignRoot(commonName, key, key.Public(), ttl, now)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &Root{CertPEM: certPEM, KeyPEM: pemEncode("EC PRIVATE KEY", der)}, nil
}

// NewRootInHardware creates a root whose key is generated inside a token and
// cannot leave it. There is no key file, and none can be produced.
func NewRootInHardware(ss seal.SigningSeal, commonName, label string, ttl time.Duration, now time.Time) (*Root, error) {
	ref, err := ss.GenerateSigner(label, seal.AlgECDSAP256)
	if err != nil {
		return nil, fmt.Errorf("generating the root key inside the token: %w", err)
	}
	signer, err := ss.Signer(ref)
	if err != nil {
		return nil, fmt.Errorf("using the root key just generated: %w", err)
	}
	certPEM, err := selfSignRoot(commonName, signer, signer.Public(), ttl, now)
	if err != nil {
		return nil, err
	}
	return &Root{CertPEM: certPEM, Ref: ref}, nil
}

func selfSignRoot(commonName string, signer crypto.Signer, pub crypto.PublicKey, ttl time.Duration, now time.Time) ([]byte, error) {
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName + " Root CA"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
	if err != nil {
		return nil, fmt.Errorf("self-signing the root certificate: %w", err)
	}
	return pemEncode("CERTIFICATE", der), nil
}

// IssuerRequest is what a signing node sends to the root: a CSR for a key the
// node already holds, and never anything more.
type IssuerRequest struct {
	CSRPEM []byte
	// Key material for a software issuer, or a reference for one held in a
	// device. Exactly one is set, and neither travels to the root.
	KeyPEM []byte
	Ref    *seal.KeyRef
}

// NewIssuerRequest generates an issuing key in the caller's own custody and
// produces a CSR for it.
//
// If the seal can hold keys, the key is generated inside the device and this
// returns a reference; otherwise it is generated in software for the caller to
// seal. Either way the private half stays with the node.
func NewIssuerRequest(s seal.Seal, commonName, label string) (*IssuerRequest, error) {
	if ss, err := seal.AsSigningSeal(s); err == nil {
		ref, err := ss.GenerateSigner(label, seal.AlgECDSAP256)
		if err != nil {
			return nil, fmt.Errorf("generating this issuer's key inside the token: %w", err)
		}
		signer, err := ss.Signer(ref)
		if err != nil {
			return nil, err
		}
		csr, err := makeCSR(commonName, signer)
		if err != nil {
			return nil, err
		}
		return &IssuerRequest{CSRPEM: csr, Ref: ref}, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csr, err := makeCSR(commonName, key)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &IssuerRequest{CSRPEM: csr, KeyPEM: pemEncode("EC PRIVATE KEY", der)}, nil
}

func makeCSR(commonName string, signer crypto.Signer) ([]byte, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}, signer)
	if err != nil {
		return nil, fmt.Errorf("creating the certificate signing request: %w", err)
	}
	return pemEncode("CERTIFICATE REQUEST", der), nil
}

// SignIssuer signs a node's CSR with the root, producing that node's issuing
// intermediate. This is the only operation that needs the root key.
//
// The name constraints delegated here bound everything the node can ever issue,
// so they are the security decision of the ceremony — not the TTL, and not the
// common name.
func SignIssuer(root *x509.Certificate, rootSigner crypto.Signer, csrPEM []byte,
	permittedDNS []string, permittedIPs []*net.IPNet, ttl time.Duration, now time.Time) ([]byte, error) {

	csr, err := parseCSR(csrPEM)
	if err != nil {
		return nil, err
	}
	// The CSR proves the requester holds the key. Skipping this would let a
	// node obtain an issuing certificate over somebody else's key.
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf(
			"the signing request's own signature does not verify: %w — it was altered in transit, "+
				"or produced by something that does not hold the key it names", err)
	}
	if csr.Subject.CommonName == "" {
		return nil, errors.New("the signing request carries no common name, so the resulting issuer would be unidentifiable")
	}

	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	if notAfter := now.Add(ttl); notAfter.After(root.NotAfter) {
		return nil, fmt.Errorf(
			"an issuer valid until %s would outlive its root, which expires %s: shorten -ttl or re-issue the root first",
			notAfter.UTC().Format(time.RFC3339), root.NotAfter.UTC().Format(time.RFC3339))
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: csr.Subject.CommonName},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	applyNameConstraints(tmpl, permittedDNS, permittedIPs)

	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, csr.PublicKey, rootSigner)
	if err != nil {
		return nil, fmt.Errorf("signing the issuer certificate with the root key: %w", err)
	}
	// Verify before release, as everywhere else: an issuer certificate that
	// does not chain to its own root would fail at every relying party instead
	// of here, where it is cheap to notice.
	issued, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	if _, err := issued.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, fmt.Errorf("refusing to release an issuer certificate that does not verify against its root: %w", err)
	}
	return pemEncode("CERTIFICATE", der), nil
}

// LoadRootSigner reassembles a root for a ceremony, from a key file or a token.
func LoadRootSigner(certPEM, keyPEM []byte, ref *seal.KeyRef, s seal.Seal) (*x509.Certificate, crypto.Signer, error) {
	cert, err := parseCert(certPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("reading the root certificate: %w", err)
	}
	if ref != nil {
		ss, err := seal.AsSigningSeal(s)
		if err != nil {
			return nil, nil, fmt.Errorf("this root is held in hardware (%s) but %w", ref, err)
		}
		signer, err := ss.Signer(ref)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot use the root key %s: %w", ref, err)
		}
		return cert, signer, nil
	}
	blk, _ := pem.Decode(keyPEM)
	if blk == nil {
		return nil, nil, errors.New("the root key is not PEM; a root ceremony needs either a key file or a hardware reference")
	}
	key, err := x509.ParseECPrivateKey(blk.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("reading the root key: %w", err)
	}
	return cert, key, nil
}

// AssembleIssuer builds the material a node stores: the root it chains to, its
// own signed intermediate, and its own key in whatever custody holds it.
func AssembleIssuer(rootCertPEM, issuerCertPEM []byte, req *IssuerRequest) (Material, error) {
	m := Material{
		RootCertPEM:         rootCertPEM,
		IntermediateCertPEM: issuerCertPEM,
		IntermediateKeyPEM:  req.KeyPEM,
		IntermediateRef:     req.Ref,
	}
	// Confirm the certificate actually matches the key this node holds before
	// storing it — a mismatch here would surface much later, as unexplained
	// signature failures.
	if _, err := parseCert(issuerCertPEM); err != nil {
		return m, fmt.Errorf("the issuer certificate is unreadable: %w", err)
	}
	return m, nil
}
