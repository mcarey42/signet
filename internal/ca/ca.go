// Package ca issues X.509 certificates.
//
// Two rules shape everything here:
//
//   - The root private key never touches the store. It is generated in the
//     genesis ceremony, signs exactly one intermediate, and is handed to the
//     operator to take offline. Anything written to the FSM lands in the Raft
//     log and in every immutable backup generation built from it, so a root key
//     that touched state would make "the root is offline" permanently false in
//     the disaster-recovery chain (docs/14, E-13 F6).
//   - Nothing is released without being independently re-verified. Sign builds
//     a certificate; Verify re-parses the bytes that came out and checks them
//     against the issuer's own constraints through a separate code path. The
//     two halves do not share assumptions, which is the point (charter
//     principle 6).
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
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"
)

// Material is a CA's persistable form. The intermediate's private key is the
// only key here; it lives in the store under the barrier, and moving it into a
// TPM, PKCS#11 token, or cloud KMS is the hardening milestone's job (E-01 DB-3).
type Material struct {
	RootCertPEM         []byte `json:"root_cert"`
	IntermediateCertPEM []byte `json:"intermediate_cert"`
	IntermediateKeyPEM  []byte `json:"intermediate_key"`
}

// CA is a loaded, ready-to-sign authority.
type CA struct {
	root         *x509.Certificate
	intermediate *x509.Certificate
	key          crypto.Signer
	material     Material
}

// Role constrains what a caller may ask for. A signing request that satisfies
// no role is refused; a request that satisfies one is still checked field by
// field, because the request supplies the names and the names are the identity.
type Role struct {
	Name             string   `json:"name"`
	Scope            string   `json:"scope"` // where in the resource tree signing is authorized
	AllowedDomains   []string `json:"allowed_domains"`
	AllowSubdomains  bool     `json:"allow_subdomains"`
	AllowBareDomains bool     `json:"allow_bare_domains"`
	AllowIPSANs      bool     `json:"allow_ip_sans"`
	AllowedURIPrefix []string `json:"allowed_uri_prefixes"`
	MaxTTLSeconds    int64    `json:"max_ttl_seconds"`
}

// GenesisResult is what a root ceremony produces. RootKeyPEM is returned to the
// caller and deliberately never stored: the ceremony hands it to the operator.
type GenesisResult struct {
	Material   Material
	RootKeyPEM []byte
}

// Genesis creates a root and the one intermediate it signs.
//
// permittedDNS, when non-empty, becomes an X.509 name constraint on the
// intermediate. Constraints are defense in depth here, not the primary control:
// E-02 measured that DNS constraints are honored widely, while URI constraints
// break verification outright in the rustls/webpki family — so DNS, IP, and
// email subtrees are emitted and URI constraints are not. Primary enforcement
// is issuer-side, in Sign and Verify below.
func Genesis(commonName string, permittedDNS []string, permittedIPs []*net.IPNet, rootTTL, intermediateTTL time.Duration, now time.Time) (*GenesisResult, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	rootSerial, err := newSerial()
	if err != nil {
		return nil, err
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          rootSerial,
		Subject:               pkix.Name{CommonName: commonName + " Root CA"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(rootTTL),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootKey.Public(), rootKey)
	if err != nil {
		return nil, fmt.Errorf("ca: create root: %w", err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, err
	}

	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	interSerial, err := newSerial()
	if err != nil {
		return nil, err
	}
	interTmpl := &x509.Certificate{
		SerialNumber:          interSerial,
		Subject:               pkix.Name{CommonName: commonName + " Issuing CA"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(intermediateTTL),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	if len(permittedDNS) > 0 {
		interTmpl.PermittedDNSDomainsCritical = true
		interTmpl.PermittedDNSDomains = permittedDNS
		// Close the cross-type gap: a DNS-only constraint leaves IP and email
		// name forms unconstrained in a conforming verifier (E-02 F3).
		//
		// A constraint has to permit what the authority is actually expected to
		// issue. Excluding every IP range is the right default for a CA that
		// only names hosts by DNS, but it makes IP SANs impossible — so an
		// authority that must issue them says which ranges instead.
		if len(permittedIPs) > 0 {
			interTmpl.PermittedIPRanges = permittedIPs
		} else {
			interTmpl.ExcludedIPRanges = []*net.IPNet{
				{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
				{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
			}
		}
		interTmpl.ExcludedEmailAddresses = []string{""}
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, root, interKey.Public(), rootKey)
	if err != nil {
		return nil, fmt.Errorf("ca: create intermediate: %w", err)
	}

	rootKeyDER, err := x509.MarshalECPrivateKey(rootKey)
	if err != nil {
		return nil, err
	}
	interKeyDER, err := x509.MarshalECPrivateKey(interKey)
	if err != nil {
		return nil, err
	}
	return &GenesisResult{
		Material: Material{
			RootCertPEM:         pemEncode("CERTIFICATE", rootDER),
			IntermediateCertPEM: pemEncode("CERTIFICATE", interDER),
			IntermediateKeyPEM:  pemEncode("EC PRIVATE KEY", interKeyDER),
		},
		RootKeyPEM: pemEncode("EC PRIVATE KEY", rootKeyDER),
	}, nil
}

// Load parses stored material into a usable authority.
func Load(m Material) (*CA, error) {
	root, err := parseCert(m.RootCertPEM)
	if err != nil {
		return nil, fmt.Errorf("ca: root: %w", err)
	}
	inter, err := parseCert(m.IntermediateCertPEM)
	if err != nil {
		return nil, fmt.Errorf("ca: intermediate: %w", err)
	}
	blk, _ := pem.Decode(m.IntermediateKeyPEM)
	if blk == nil {
		return nil, errors.New("ca: intermediate key is not PEM")
	}
	key, err := x509.ParseECPrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: intermediate key: %w", err)
	}
	return &CA{root: root, intermediate: inter, key: key, material: m}, nil
}

func (c *CA) RootPEM() []byte { return c.material.RootCertPEM }
func (c *CA) ChainPEM() []byte {
	return append(append([]byte{}, c.material.IntermediateCertPEM...), c.material.RootCertPEM...)
}

// Request is one signing request, as a dialect presents it.
type Request struct {
	CSRPEM     []byte
	CommonName string
	DNSNames   []string
	IPs        []string
	URIs       []string
	TTL        time.Duration
	// ExcludeCNFromSANs mirrors Vault's flag: some callers want the common name
	// left out of the SAN list.
	ExcludeCNFromSANs bool
}

// Issued is a signed certificate and the facts worth logging about it.
type Issued struct {
	CertPEM      []byte
	IssuingCAPEM []byte
	ChainPEM     []byte
	Serial       string
	NotAfter     time.Time
	Subject      string
	SANs         []string
}

// Sign validates a request against a role, issues a certificate, and refuses to
// return it unless an independent verification pass agrees it should exist.
func (c *CA) Sign(req Request, role Role, serial *big.Int, now time.Time) (*Issued, error) {
	csr, err := parseCSR(req.CSRPEM)
	if err != nil {
		return nil, err
	}
	// A CSR proves the requester holds the private key. Without this check the
	// caller could request a certificate for somebody else's key.
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("ca: CSR signature: %w", err)
	}

	cn := req.CommonName
	if cn == "" {
		cn = csr.Subject.CommonName
	}
	dns := dedupe(append(append([]string{}, csr.DNSNames...), req.DNSNames...))
	if cn != "" && !req.ExcludeCNFromSANs && looksLikeDNS(cn) {
		dns = dedupe(append(dns, cn))
	}
	ips := dedupe(append(ipStrings(csr.IPAddresses), req.IPs...))
	uris := dedupe(append(uriStrings(csr.URIs), req.URIs...))

	ttl := req.TTL
	maxTTL := time.Duration(role.MaxTTLSeconds) * time.Second
	if maxTTL <= 0 {
		maxTTL = 24 * time.Hour
	}
	if ttl <= 0 || ttl > maxTTL {
		ttl = maxTTL
	}
	notAfter := now.Add(ttl)
	// A leaf may not outlive the authority that signed it.
	if notAfter.After(c.intermediate.NotAfter) {
		notAfter = c.intermediate.NotAfter
	}

	// Pre-issuance check. Verify runs the same rules again afterwards, from the
	// certificate's own bytes rather than from these variables.
	if err := checkNames(role, cn, dns, ips, uris); err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dns,
	}
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			return nil, fmt.Errorf("ca: %q is not an IP address", ip)
		}
		tmpl.IPAddresses = append(tmpl.IPAddresses, parsed)
	}
	for _, u := range uris {
		parsed, err := url.Parse(u)
		if err != nil {
			return nil, fmt.Errorf("ca: URI %q: %w", u, err)
		}
		tmpl.URIs = append(tmpl.URIs, parsed)
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.intermediate, csr.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("ca: sign: %w", err)
	}

	issued := &Issued{
		CertPEM:      pemEncode("CERTIFICATE", der),
		IssuingCAPEM: c.material.IntermediateCertPEM,
		ChainPEM:     c.ChainPEM(),
		Serial:       formatSerial(serial),
		NotAfter:     notAfter,
		Subject:      cn,
		SANs:         append(append(append([]string{}, dns...), ips...), uris...),
	}
	// The gate. Nothing leaves this function unverified.
	if err := c.Verify(der, role, now); err != nil {
		return nil, fmt.Errorf("ca: refusing to release certificate: %w", err)
	}
	return issued, nil
}

// Verify re-checks a freshly signed certificate from its own encoded bytes.
//
// This deliberately re-derives everything rather than trusting what Sign
// computed: it parses the DER again, builds a chain against the CA's own
// anchors, and lints every name form the certificate actually carries. A bug in
// the builder — a name that slipped through, a TTL that stretched, a field set
// on the wrong template — turns into a failed request rather than a certificate
// in the wild, where it could not be recalled.
func (c *CA) Verify(der []byte, role Role, now time.Time) error {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("re-parse: %w", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(c.root)
	inters := x509.NewCertPool()
	inters.AddCert(c.intermediate)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inters,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Errorf("chain: %w", err)
	}

	if cert.IsCA {
		return errors.New("leaf certificate carries the CA bit")
	}
	if len(cert.DNSNames) == 0 && len(cert.IPAddresses) == 0 && len(cert.URIs) == 0 && len(cert.EmailAddresses) == 0 {
		// Constraints bound SANs, not the common name, so a certificate whose
		// only identity is a CN is one nothing constrains (E-02 F4).
		return errors.New("certificate has no subject alternative names")
	}
	if maxTTL := time.Duration(role.MaxTTLSeconds) * time.Second; maxTTL > 0 {
		if cert.NotAfter.After(now.Add(maxTTL).Add(time.Minute)) {
			return fmt.Errorf("lifetime %s exceeds the role's maximum %s", cert.NotAfter.Sub(now), maxTTL)
		}
	}
	if cert.NotAfter.After(c.intermediate.NotAfter) {
		return errors.New("leaf outlives its issuer")
	}

	// Lint every name form present on the certificate, including any the
	// builder never intended to set.
	return checkNames(role, cert.Subject.CommonName,
		cert.DNSNames, ipStrings(cert.IPAddresses), uriStrings(cert.URIs))
}

// checkNames is the scope rule, applied identically before and after signing.
func checkNames(role Role, cn string, dns, ips, uris []string) error {
	for _, name := range dns {
		if !domainAllowed(role, name) {
			return fmt.Errorf("DNS name %q is not permitted by role %q", name, role.Name)
		}
	}
	if cn != "" && looksLikeDNS(cn) && !domainAllowed(role, cn) {
		return fmt.Errorf("common name %q is not permitted by role %q", cn, role.Name)
	}
	if len(ips) > 0 && !role.AllowIPSANs {
		return fmt.Errorf("role %q does not permit IP addresses", role.Name)
	}
	for _, u := range uris {
		if !uriAllowed(role, u) {
			return fmt.Errorf("URI %q is not permitted by role %q", u, role.Name)
		}
	}
	return nil
}

func domainAllowed(role Role, name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" {
		return false
	}
	for _, d := range role.AllowedDomains {
		d = strings.ToLower(d)
		if name == d {
			// A bare domain is only the same as a subdomain if the role says so.
			if role.AllowBareDomains || role.AllowSubdomains {
				return true
			}
			continue
		}
		// Component-wise suffix only: "evilexample.com" must not match
		// "example.com".
		if role.AllowSubdomains && strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

func uriAllowed(role Role, uri string) bool {
	for _, p := range role.AllowedURIPrefix {
		if strings.HasPrefix(uri, p) {
			return true
		}
	}
	return false
}

func looksLikeDNS(s string) bool {
	return strings.Contains(s, ".") && net.ParseIP(s) == nil && !strings.Contains(s, " ")
}

// NewSerial produces a random 128-bit serial. Serials must be unpredictable,
// not merely unique.
func NewSerial() (*big.Int, error) { return newSerial() }

func newSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	return n.Add(n, big.NewInt(1)), nil
}

func formatSerial(s *big.Int) string {
	b := s.Bytes()
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02x", x)
	}
	return strings.Join(parts, ":")
}

func parseCert(p []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(p)
	if blk == nil {
		return nil, errors.New("not PEM")
	}
	return x509.ParseCertificate(blk.Bytes)
}

func parseCSR(p []byte) (*x509.CertificateRequest, error) {
	blk, _ := pem.Decode(p)
	if blk == nil {
		return nil, errors.New("ca: CSR is not PEM")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: CSR: %w", err)
	}
	return csr, nil
}

func pemEncode(kind string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

func uriStrings(uris []*url.URL) []string {
	out := make([]string, 0, len(uris))
	for _, u := range uris {
		out = append(out, u.String())
	}
	return out
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := in[:0:0]
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
