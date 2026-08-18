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

	"github.com/mcarey42/signet/internal/seal"
)

// Material is a CA's persistable form.
//
// Certificates are public and belong in the replicated log — every replica
// needs them and they are published anyway. The intermediate's private key is
// different: it is enclosed in a seal envelope, so what reaches the log is
// ciphertext the barrier alone cannot open. Without that, rotating the
// intermediate would not help, because the log is append-only and its backups
// are immutable — the old key would remain readable forever to anyone who ever
// obtained the barrier key (docs/11).
type Material struct {
	RootCertPEM         []byte         `json:"root_cert"`
	IntermediateCertPEM []byte         `json:"intermediate_cert"`
	IntermediateKeyPEM  []byte         `json:"intermediate_key,omitempty"` // in-memory only
	SealedKey           *seal.Envelope `json:"sealed_key,omitempty"`       // wrapped at rest
	// IntermediateRef points at a key held inside a token. When set, no private
	// material exists anywhere outside the device — not in the log, not in a
	// backup, not in this process. Signing happens in the token.
	IntermediateRef *seal.KeyRef `json:"intermediate_ref,omitempty"`
	// RootRef records where the root key lives when it too is held in hardware.
	// Signet never uses it to sign — the root signs intermediates during a
	// ceremony, not certificates — but recording it means a future ceremony can
	// find the key instead of hunting for a file.
	RootRef *seal.KeyRef `json:"root_ref,omitempty"`
}

const caKeyAAD = "signet/ca/intermediate/v1"

// Seal encloses the intermediate key and drops the plaintext, returning the
// form that may be persisted.
func (m Material) Seal(s seal.Seal) (Material, error) {
	// A key held in hardware has nothing to seal: there is no material.
	if m.IntermediateRef != nil {
		return m, nil
	}
	if m.SealedKey != nil {
		return m, nil
	}
	if len(m.IntermediateKeyPEM) == 0 {
		return m, errors.New("ca: no intermediate key to seal")
	}
	env, err := seal.NewEnvelope(s, m.IntermediateKeyPEM, []byte(caKeyAAD))
	if err != nil {
		return m, err
	}
	m.SealedKey = env
	m.IntermediateKeyPEM = nil
	return m, nil
}

// HeldInHardware reports whether the intermediate signs inside a device.
func (m Material) HeldInHardware() bool { return m.IntermediateRef != nil }

// intermediateKey recovers the private half, which requires the seal.
func (m Material) intermediateKey(s seal.Seal) ([]byte, error) {
	if m.SealedKey == nil {
		if len(m.IntermediateKeyPEM) == 0 {
			return nil, errors.New("ca: material has no intermediate key")
		}
		return m.IntermediateKeyPEM, nil
	}
	if s == nil {
		return nil, errors.New("ca: intermediate key is sealed and no seal was provided")
	}
	return m.SealedKey.Open(s, []byte(caKeyAAD))
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
	applyNameConstraints(interTmpl, permittedDNS, permittedIPs)
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

// applyNameConstraints puts the delegated namespace on the intermediate.
//
// Constraints are defense in depth here, not the primary control: E-02 measured
// that DNS constraints are honored widely while URI constraints break
// verification outright in the rustls/webpki family, so DNS, IP, and email
// subtrees are emitted and URI constraints are not. A DNS-only constraint would
// leave IP and email forms unconstrained in a conforming verifier, so those are
// closed too — by permitting specific ranges when the authority must issue
// them, and excluding everything otherwise.
func applyNameConstraints(tmpl *x509.Certificate, permittedDNS []string, permittedIPs []*net.IPNet) {
	if len(permittedDNS) == 0 {
		return
	}
	tmpl.PermittedDNSDomainsCritical = true
	tmpl.PermittedDNSDomains = permittedDNS
	if len(permittedIPs) > 0 {
		tmpl.PermittedIPRanges = permittedIPs
	} else {
		tmpl.ExcludedIPRanges = []*net.IPNet{
			{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
			{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		}
	}
	tmpl.ExcludedEmailAddresses = []string{""}
}

// Load parses stored material into a usable authority. The seal is needed to
// open the intermediate key; pass nil to load only the public half, which is
// enough to validate material without being able to sign with it.
func Load(m Material, s seal.Seal) (*CA, error) {
	root, err := parseCert(m.RootCertPEM)
	if err != nil {
		return nil, fmt.Errorf("ca: root: %w", err)
	}
	inter, err := parseCert(m.IntermediateCertPEM)
	if err != nil {
		return nil, fmt.Errorf("ca: intermediate: %w", err)
	}
	loaded := &CA{root: root, intermediate: inter, material: m}

	// A key held inside a token: ask the device for a signer rather than
	// recovering material, because there is no material to recover.
	if m.IntermediateRef != nil {
		if s == nil {
			return loaded, nil // public-only load
		}
		ss, err := seal.AsSigningSeal(s)
		if err != nil {
			return nil, fmt.Errorf(
				"this authority's intermediate key is held in hardware (%s) but %w",
				m.IntermediateRef, err)
		}
		signer, err := ss.Signer(m.IntermediateRef)
		if err != nil {
			return nil, fmt.Errorf("cannot use the intermediate key %s: %w", m.IntermediateRef, err)
		}
		loaded.key = signer
		return loaded, nil
	}

	if s == nil && m.SealedKey != nil {
		// Public-only load: the authority can be inspected and its chain
		// published, but nothing can be signed with it.
		return loaded, nil
	}
	material, err := m.intermediateKey(s)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(material)
	if blk == nil {
		return nil, errors.New("ca: intermediate key is not PEM")
	}
	key, err := x509.ParseECPrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: intermediate key: %w", err)
	}
	loaded.key = key
	return loaded, nil
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
	if c.key == nil {
		return nil, errors.New("ca: this authority was loaded without its key and cannot sign")
	}
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

// uriAllowed checks a URI SAN against a role's permitted prefixes, matching at
// a STRUCTURAL boundary rather than by raw string prefix.
//
// A bare HasPrefix made `spiffe://home.example` also permit
// `spiffe://home.example.evil/anything`, because "home.example.evil" starts
// with "home.example". Since URI name constraints are deliberately never
// emitted into certificates (E-02: verifiers disagree about them), this
// predicate is the ONLY control over what SPIFFE identities a role can issue —
// so a string-prefix bug here is the whole boundary.
//
// A prefix matches when the URI is identical to it, or continues it at a
// separator: '/' within the path, or the end of the authority. Comparison is
// case-insensitive on scheme and host, as URIs are, and case-sensitive on the
// path, as they also are.
func uriAllowed(role Role, uri string) bool {
	for _, p := range role.AllowedURIPrefix {
		if uriPrefixMatches(p, uri) {
			return true
		}
	}
	return false
}

func uriPrefixMatches(prefix, uri string) bool {
	if prefix == "" {
		return false
	}
	pu, err := url.Parse(prefix)
	if err != nil {
		return false
	}
	cu, err := url.Parse(uri)
	if err != nil {
		return false
	}
	// Scheme and authority must match exactly — this is where the old bug lived,
	// since a longer host trivially "starts with" a shorter one.
	if !strings.EqualFold(pu.Scheme, cu.Scheme) || !strings.EqualFold(pu.Host, cu.Host) {
		return false
	}
	if pu.User != nil || cu.User != nil {
		return false // userinfo in a workload identity is not something to interpret
	}
	pp, cp := pu.EscapedPath(), cu.EscapedPath()
	switch {
	case pp == "" || pp == "/":
		return true // the whole trust domain was delegated
	case cp == pp:
		return true
	default:
		return strings.HasPrefix(cp, strings.TrimSuffix(pp, "/")+"/")
	}
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

// SealedBy reports which seal wrapping key holds the intermediate's private
// material, or an empty string if it is not sealed.
func (m Material) SealedBy() string {
	if m.IntermediateRef != nil {
		return "held in " + m.IntermediateRef.String()
	}
	if m.SealedKey == nil || m.SealedKey.DEK == nil {
		return ""
	}
	return m.SealedKey.DEK.Seal + "/" + m.SealedKey.DEK.KeyID
}

// Rewrap moves the intermediate's private key from one seal to another. The
// certificates are untouched — they are public and unaffected by custody.
func (m Material) Rewrap(from, to seal.Seal) (Material, error) {
	// Nothing to rewrap: the key lives in a device and was never wrapped.
	// Moving it between devices is a re-key, not a rewrap.
	if m.IntermediateRef != nil {
		return m, nil
	}
	material, err := m.intermediateKey(from)
	if err != nil {
		return m, err
	}
	env, err := seal.NewEnvelope(to, material, []byte(caKeyAAD))
	if err != nil {
		return m, err
	}
	m.SealedKey = env
	m.IntermediateKeyPEM = nil
	return m, nil
}

// HardwareGenesis creates a root and intermediate whose private keys are
// generated *inside* a token and never leave it.
//
// This is what a real certificate authority does, and it changes the operational
// story in two ways worth understanding before choosing it:
//
//   - There is no root key file to protect, lose, or copy. The offline root is
//     offline because the token is in a safe, not because a file is on a USB
//     stick. Re-issuing an intermediate becomes a ceremony with the device
//     rather than a hunt for a key file.
//   - There is also no way to recover the root if the token dies. A file can be
//     backed up; a non-extractable key cannot, by definition. Operators who
//     need survivability run two tokens and generate a root in each, or accept
//     that losing the device means re-establishing trust from scratch.
func HardwareGenesis(ss seal.SigningSeal, commonName string, permittedDNS []string, permittedIPs []*net.IPNet,
	rootLabel, intermediateLabel string, rootTTL, intermediateTTL time.Duration, now time.Time) (*GenesisResult, error) {

	rootRef, err := ss.GenerateSigner(rootLabel, seal.AlgECDSAP256)
	if err != nil {
		return nil, fmt.Errorf("generating the root key inside the token: %w", err)
	}
	rootSigner, err := ss.Signer(rootRef)
	if err != nil {
		return nil, fmt.Errorf("using the root key just generated: %w", err)
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
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootSigner.Public(), rootSigner)
	if err != nil {
		return nil, fmt.Errorf("self-signing the root certificate with the token-held key: %w", err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, err
	}

	interRef, err := ss.GenerateSigner(intermediateLabel, seal.AlgECDSAP256)
	if err != nil {
		return nil, fmt.Errorf("generating the intermediate key inside the token: %w", err)
	}
	interSigner, err := ss.Signer(interRef)
	if err != nil {
		return nil, fmt.Errorf("using the intermediate key just generated: %w", err)
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
	applyNameConstraints(interTmpl, permittedDNS, permittedIPs)

	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, root, interSigner.Public(), rootSigner)
	if err != nil {
		return nil, fmt.Errorf("signing the intermediate with the token-held root key: %w", err)
	}

	return &GenesisResult{
		Material: Material{
			RootCertPEM:         pemEncode("CERTIFICATE", rootDER),
			IntermediateCertPEM: pemEncode("CERTIFICATE", interDER),
			IntermediateRef:     interRef,
			RootRef:             rootRef,
		},
		// Deliberately empty: there is no root key to hand over, which is the
		// entire point of this path.
		RootKeyPEM: nil,
	}, nil
}
