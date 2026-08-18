// Package trust builds and verifies trust bundles: the signed artifact that
// tells a consumer which anchors to trust, which issuers exist beneath them,
// and until when that statement may be believed.
//
// # Who signs a bundle, and why it is the root
//
// A bundle declares the trust set, so it must be signed by something already
// authorized to make trust decisions. An *issuing* key is not that — it is
// authorized to mint leaves inside a namespace, and nothing more. If issuers
// could sign bundles, a single compromised node could publish one adding its
// own anchor, and the compromise of one issuer would become the compromise of
// the whole trust fabric.
//
// So the root signs, which means publishing a bundle is a root ceremony. That
// is a real cost, and it is the right one: the things a bundle declares —
// anchors, the issuer set, algorithm policy — change only when the shape of
// trust changes, which is exactly when a deliberate offline ceremony is
// appropriate. Routine credential churn never touches it.
//
// # What that means for revocation
//
// Withdrawing an issuer therefore requires a ceremony, or waiting out its
// certificate. That is consistent with the rest of Signet, which leans on short
// lifetimes rather than revocation lists (docs/02: "revoking a subtree =
// declining one renewal"). An online, frequently-republished freshness
// statement — a delegated key signing short-lived revocation deltas — is the
// natural extension when leaf-level revocation is needed, and is deliberately
// not built yet.
package trust

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// FormatVersion guards the envelope shape. A verifier that does not recognise
// the version refuses rather than guessing, because guessing about a trust
// statement is how you end up trusting the wrong thing.
const FormatVersion = 1

// AnchorRole describes what a consumer would be choosing by anchoring here.
type AnchorRole string

const (
	// RoleRoot is the domain's root: the cascade choice. Issuers rotate freely
	// beneath it, and the holder of this key can mint anywhere in the domain.
	RoleRoot AnchorRole = "root"
	// RoleIssuer is one issuing intermediate: the pinned choice. It isolates a
	// consumer to exactly what that issuer produces — including against a
	// replacement minted by the root — at the cost of rotation touching every
	// consumer that pinned it (docs/02).
	RoleIssuer AnchorRole = "issuer"
)

// Anchor is a certificate a consumer may choose to trust directly.
type Anchor struct {
	Role AnchorRole `json:"role"`
	Name string     `json:"name"`
	// CertPEM is the anchor itself. It is never trusted because it appears
	// here — a bundle that vouched for its own anchors would be circular. It is
	// trusted because the verifier pinned its key fingerprint out of band.
	CertPEM []byte `json:"cert"`
	// SPKI is the SHA-256 of the SubjectPublicKeyInfo, which is what a consumer
	// pins. Fingerprinting the key rather than the certificate means the pin
	// survives re-issuing the same key with new validity dates.
	SPKI string `json:"spki"`
}

// Issuer is a certificate that signs leaves, published so verifiers can build
// paths without discovery.
type Issuer struct {
	Name    string `json:"name"`
	CertPEM []byte `json:"cert"`
	SPKI    string `json:"spki"`
	// Custody records where the private key lives. It is informational — a
	// consumer cannot verify it — but it tells an operator reading a bundle
	// which issuers are hardware-held without inspecting every node.
	Custody string `json:"custody,omitempty"`
}

// Payload is the signed content of a bundle.
type Payload struct {
	Version int    `json:"version"`
	Domain  string `json:"domain"`
	// Epoch increases with every publication and never decreases. It is what
	// makes replaying an older bundle detectable: a verifier that has seen
	// epoch N refuses anything below it, so an attacker cannot roll a consumer
	// back to a trust set that has since been narrowed (E-01 FED-1).
	Epoch      uint64   `json:"epoch"`
	IssuedAt   int64    `json:"issued_at"`
	MaxAgeSec  int64    `json:"max_age_sec"`
	Anchors    []Anchor `json:"anchors"`
	Issuers    []Issuer `json:"issuers"`
	Algorithms []string `json:"algorithms,omitempty"`
	// Revoked lists SPKI fingerprints withdrawn from service. Publishing this
	// is a root ceremony, so it is for withdrawing an *issuer*, not a leaf.
	Revoked []string `json:"revoked,omitempty"`
}

// Bundle is the transmitted artifact: the exact signed bytes, plus signatures.
//
// The payload travels as bytes rather than as a re-marshalled object on
// purpose. Verifying a re-serialized structure means trusting that two
// marshallers agree forever, which is the sort of assumption that quietly
// breaks and takes signature verification with it. What was signed is what is
// transmitted, byte for byte.
type Bundle struct {
	// Payload is base64 of the signed JSON, as a string rather than []byte:
	// Go encodes a []byte field as base64 itself, which would encode it twice
	// and leave any non-Go verifier decoding a blob that still looks like
	// base64. This artifact is meant to be readable outside Go.
	Payload    string      `json:"payload"`
	Signatures []Signature `json:"signatures"`
}

type Signature struct {
	// SPKI identifies the signing key, so a verifier can tell whether this
	// bundle was signed by the key it pinned before doing any parsing.
	SPKI string `json:"spki"`
	Alg  string `json:"alg"`
	Sig  []byte `json:"sig"`
}

// Fingerprint is the pin form of a public key: SHA-256 over its
// SubjectPublicKeyInfo, which is stable across re-issuance of the same key.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return "sha256:" + base64.RawURLEncoding.EncodeToString(sum[:])
}

// Build assembles a payload. It does not sign; signing is a separate step
// because it happens somewhere else — with the offline root.
func Build(domain string, epoch uint64, maxAge time.Duration, anchors []Anchor, issuers []Issuer, now time.Time) (*Payload, error) {
	if domain == "" {
		return nil, errors.New("trust: a bundle must name its domain, or a consumer cannot tell whose trust it describes")
	}
	if len(anchors) == 0 {
		return nil, errors.New("trust: a bundle with no anchors would tell a consumer to trust nothing")
	}
	if maxAge <= 0 {
		return nil, errors.New("trust: max-age must be positive, or staleness can never be detected")
	}
	return &Payload{
		Version: FormatVersion, Domain: domain, Epoch: epoch,
		IssuedAt: now.Unix(), MaxAgeSec: int64(maxAge.Seconds()),
		Anchors: anchors, Issuers: issuers,
	}, nil
}

// Sign serializes a payload and signs those exact bytes with the root key.
func Sign(p *Payload, signer crypto.Signer) (*Bundle, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("trust: bundles are signed with ECDSA; this key is %T", signer.Public())
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	spki := "sha256:" + base64.RawURLEncoding.EncodeToString(sum[:])

	digest := sha256.Sum256(raw)
	sig, err := signer.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("trust: signing the bundle: %w", err)
	}
	return &Bundle{
		Payload:    base64.StdEncoding.EncodeToString(raw),
		Signatures: []Signature{{SPKI: spki, Alg: "ES256", Sig: sig}},
	}, nil
}

// VerifyOptions is what a consumer knows before it reads a bundle.
type VerifyOptions struct {
	// PinnedSPKI is the fingerprint of the key that may sign bundles for this
	// domain, learned out of band. Without it a bundle is self-attesting and
	// therefore worthless — anyone can produce a well-formed one.
	PinnedSPKI string
	// Domain is the trust domain the consumer expects. A bundle describing a
	// different one is refused rather than merged: merging trust domains lets
	// one forge identities belonging to another (SPIFFE Federation §4.2).
	Domain string
	// LastEpoch is the highest epoch this consumer has already accepted, and
	// LastDigest the exact bytes it accepted there. Together they make an epoch
	// mean one specific trust set rather than merely a number.
	LastEpoch  uint64
	LastDigest string
	Now        time.Time
	// Skew tolerates disagreement between this clock and the publisher's when
	// judging whether a timestamp is in the future.
	//
	// It deliberately does NOT extend a bundle's life past its max age. Doing
	// so would mean every bundle stayed usable for Skew beyond the point it was
	// declared stale, which is not what failing closed means — and a consumer
	// whose clock runs fast should expire a bundle early, not late. Signet
	// takes NTP as a hard dependency (docs/03) precisely so this can be tight.
	Skew time.Duration
}

// Verify checks a bundle and returns its payload only if every rule holds.
//
// The order is deliberate: identity of the signer first, then integrity, then
// freshness and rollback. Checking freshness before knowing who signed would
// mean reasoning about an attacker's timestamps.
func Verify(b *Bundle, opts VerifyOptions) (*Payload, error) {
	if opts.PinnedSPKI == "" {
		return nil, errors.New(
			"trust: no pinned key was supplied. A bundle vouches for itself, so without a " +
				"fingerprint obtained out of band there is nothing to check it against")
	}
	if len(b.Signatures) == 0 {
		return nil, errors.New("trust: the bundle carries no signatures")
	}

	raw, err := base64.StdEncoding.DecodeString(b.Payload)
	if err != nil {
		return nil, fmt.Errorf("trust: the bundle payload is not valid base64: %w", err)
	}
	var p Payload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("trust: the bundle payload is not readable: %w", err)
	}
	if p.Version != FormatVersion {
		return nil, fmt.Errorf(
			"trust: this bundle is format version %d and this build understands %d. Refusing to "+
				"interpret a trust statement it may not understand correctly", p.Version, FormatVersion)
	}

	// 1. Was it signed by the key we pinned?
	//
	// The pin is matched against a fingerprint COMPUTED from the certificate,
	// never against the SPKI string the bundle carries. Those strings are
	// claims the bundle makes about itself, and this check once believed them:
	// it found the anchor whose declared SPKI equalled the pin and then
	// verified using whatever key that certificate happened to hold. Since the
	// pin is public by design — every consumer is given it — an attacker could
	// mint a bundle under their own root, label it with the victim's
	// fingerprint, and be accepted. Pinning was decorative.
	//
	// Compute, then compare. A self-reported identity is not an identity.
	var signed, foundPinnedAnchor bool
	digest := sha256.Sum256(raw)
	for i := range p.Anchors {
		// Only the ROOT anchor may sign. This once accepted any anchor, so a
		// consumer pinned to an ISSUER would accept a bundle that issuer signed
		// — and an issuing key is authorized to mint leaves in a namespace, not
		// to declare the trust set. That is the invariant this whole package is
		// built on (see the package comment); accepting an issuer-signed bundle
		// let one compromised node redefine trust for everyone pinned to it.
		if p.Anchors[i].Role != RoleRoot {
			continue
		}
		cert, err := parseCert(p.Anchors[i].CertPEM)
		if err != nil {
			continue
		}
		if Fingerprint(cert) != opts.PinnedSPKI {
			continue
		}
		foundPinnedAnchor = true
		pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf(
				"trust: the pinned anchor holds a %T key; bundles are ECDSA-signed", cert.PublicKey)
		}
		for _, sig := range b.Signatures {
			if ecdsa.VerifyASN1(pub, digest[:], sig.Sig) {
				signed = true
				break
			}
		}
		break
	}
	// The two failures are diagnostically different and worth separating: one
	// says the bundle came from the wrong place, the other that it was changed
	// on the way from the right one.
	if foundPinnedAnchor && !signed {
		return nil, errors.New(
			"trust: the bundle carries the pinned anchor, but no signature on it verifies under " +
				"that key. The bundle was altered after it was signed")
	}
	if !signed {
		return nil, fmt.Errorf(
			"trust: the bundle is not signed by the pinned key %s. Whoever served it does not hold "+
				"the key this consumer was told to trust", opts.PinnedSPKI)
	}

	// 2. Is it about the domain we asked about? Bundles are never merged.
	if opts.Domain != "" && p.Domain != opts.Domain {
		return nil, fmt.Errorf(
			"trust: this bundle describes domain %q but %q was expected. Trust domains are kept "+
				"separate deliberately: accepting another's anchors here would let it assert "+
				"identities belonging to this one", p.Domain, opts.Domain)
	}

	// 3. Rollback. An older bundle is a valid signed artifact forever, so the
	// only defence against replaying one is refusing to go backwards.
	// Strictly greater, unless it is byte-identical to what we already hold.
	//
	// A non-strict check let two DIFFERENT bundles at the SAME epoch be
	// interchangeable, so a withdrawal could be undone simply by republishing
	// the pre-withdrawal content under its original epoch number. The epoch is
	// the anti-rollback counter; equal epochs must mean equal bundles.
	if p.Epoch < opts.LastEpoch {
		return nil, fmt.Errorf(
			"trust: this bundle is epoch %d but epoch %d has already been accepted. Refusing to "+
				"move backwards — an older bundle may describe a trust set that has since been "+
				"narrowed, and serving one is how a revocation gets suppressed", p.Epoch, opts.LastEpoch)
	}
	if p.Epoch == opts.LastEpoch && opts.LastDigest != "" {
		if got := digestOf(raw); got != opts.LastDigest {
			return nil, fmt.Errorf(
				"trust: this bundle claims epoch %d, which has already been accepted, but its "+
					"contents differ from the one accepted at that epoch. Two different trust sets "+
					"cannot share an epoch — publish a new one rather than reissuing an old number",
				p.Epoch)
		}
	}

	// 4. Freshness, fail-closed.
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	expires := time.Unix(p.IssuedAt, 0).Add(time.Duration(p.MaxAgeSec) * time.Second)
	if now.After(expires) {
		return nil, fmt.Errorf(
			"trust: this bundle went stale at %s (issued %s, max age %ds). A stale bundle is "+
				"refused rather than used, because the usual reason to serve one is to hide a "+
				"change made since",
			expires.UTC().Format(time.RFC3339),
			time.Unix(p.IssuedAt, 0).UTC().Format(time.RFC3339), p.MaxAgeSec)
	}
	if issued := time.Unix(p.IssuedAt, 0); issued.After(now.Add(opts.Skew)) {
		return nil, fmt.Errorf(
			"trust: this bundle claims to have been issued at %s, which is in the future. Either a "+
				"clock is wrong or the timestamp was fabricated", issued.UTC().Format(time.RFC3339))
	}
	return &p, nil
}

// SelectAnchor returns the anchor a consumer should install, given what it
// chose to trust: the domain root (cascade) or one named issuer (pinned).
func (p *Payload) SelectAnchor(role AnchorRole, name string) (*Anchor, error) {
	for i := range p.Anchors {
		a := &p.Anchors[i]
		if a.Role != role {
			continue
		}
		if name == "" || a.Name == name {
			return a, nil
		}
	}
	if role == RoleIssuer {
		return nil, fmt.Errorf(
			"trust: no issuer anchor named %q in this bundle. Anchoring on an issuer isolates a "+
				"consumer to exactly that issuer, so the name must match one the domain publishes", name)
	}
	return nil, fmt.Errorf("trust: this bundle publishes no %s anchor", role)
}

// Pool builds a verification pool for a chosen anchor, plus the issuers needed
// to build paths up to it.
//
// WARNING: under a shared root these pools are not sufficient on their own. A
// sibling domain's issuer also chains to the same anchor, so a presenter that
// supplies its own intermediates — as every TLS peer does — can build a valid
// path with an issuer this bundle never published. Use VerifyCert, which
// re-checks the resulting chain against the published issuer set. Pool is for
// exporting material to tools that verify elsewhere (openssl, a TLS config
// whose peer chain you separately constrain).
func (p *Payload) Pool(anchor *Anchor) (roots *x509.CertPool, intermediates *x509.CertPool, err error) {
	roots = x509.NewCertPool()
	cert, err := parseCert(anchor.CertPEM)
	if err != nil {
		return nil, nil, err
	}
	roots.AddCert(cert)

	revoked := map[string]bool{}
	for _, spki := range p.Revoked {
		revoked[spki] = true
	}
	intermediates = x509.NewCertPool()
	for _, iss := range p.Issuers {
		c, err := parseCert(iss.CertPEM)
		if err != nil {
			continue
		}
		// Keyed on the COMPUTED fingerprint, not the declared one: otherwise a
		// withdrawn issuer could be resurrected simply by misreporting its own
		// SPKI in the published entry.
		if revoked[Fingerprint(c)] {
			continue // withdrawn: do not help build a path through it
		}
		intermediates.AddCert(c)
	}
	return roots, intermediates, nil
}

// DigestOf is the identity of a bundle's signed bytes, used to pin an epoch to
// one specific trust set.
func DigestOf(b *Bundle) string {
	raw, err := base64.StdEncoding.DecodeString(b.Payload)
	if err != nil {
		return ""
	}
	return digestOf(raw)
}

func digestOf(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + base64.RawURLEncoding.EncodeToString(sum[:])
}

// PayloadOf decodes a bundle's payload WITHOUT verifying it.
//
// It exists for reading state that was verified when it was accepted — the
// stored bundle's epoch, for instance. Never use it on something that just
// arrived over a network: an unverified payload is only an attacker's opinion.
func PayloadOf(b *Bundle) (*Payload, error) {
	raw, err := base64.StdEncoding.DecodeString(b.Payload)
	if err != nil {
		return nil, err
	}
	var p Payload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// PayloadOfBytes decodes a serialized bundle's payload without verifying it.
// The same caution as PayloadOf applies: this is for already-accepted state.
func PayloadOfBytes(raw []byte) (*Payload, error) {
	var b Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("trust: this does not parse as a trust bundle: %w", err)
	}
	return PayloadOf(&b)
}

func parseCert(p []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(p)
	if blk == nil {
		return nil, errors.New("not PEM")
	}
	return x509.ParseCertificate(blk.Bytes)
}
