package trust

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// A fabric is one consumer's view of several trust domains at once.
//
// # Bundles are never merged
//
// Each domain is pinned separately and verified separately. Merging their
// anchors into one pool would mean any domain could vouch for any identity, so
// federating with a partner would silently hand it authority over names it has
// no business asserting (E-01 FED-4, SPIFFE Federation §4.2). Instead an
// identity names its own trust domain, that domain selects the bundle, and only
// that bundle's anchors are consulted.
//
// # Chain verification alone does not separate domains
//
// This is worth stating plainly because it surprised us when we built it. Under
// the cascade model every domain's issuers descend from one organizational
// root, so a leaf from *any* domain verifies against *any* sibling's bundle —
// the chain is genuinely valid. What separates them is the namespace check
// below: an identity under aws.example.net is refused by home.example.net's
// bundle because the name does not belong to that domain, not because the
// signature fails.
//
// Under sovereignty the separation is also cryptographic, because there is no
// shared root to build a path through. That is the concrete difference between
// the two modes, and it is why docs/02 says only an own-root child is sovereign
// *against* its parent (E-01 DB-1).
//
// So: the namespace check is not belt-and-braces. In cascade mode it is the
// only thing doing the work.

// Identity is what a verified leaf turned out to be.
type Identity struct {
	Domain string // the trust domain that vouched for it
	URI    string // the SPIFFE-style identity, when the leaf carries one
	CN     string
	// Anchor records which anchor the chain terminated at, so a caller can tell
	// a cascade result from a sovereign one rather than assuming.
	Anchor     string
	AnchorRole AnchorRole
}

// TrustDomainOf extracts the trust domain a certificate claims, from its
// SPIFFE-style URI SAN.
//
// It reads the URI SAN rather than the common name because a CN is decorative
// and unstructured; a spiffe:// URI names its trust domain in a position a
// verifier can check. A certificate with no such URI has no claimed domain, and
// the caller must supply one — Signet will not guess which domain an
// unstructured name belongs to.
func TrustDomainOf(cert *x509.Certificate) (domain, id string, err error) {
	for _, u := range cert.URIs {
		if u.Scheme != "spiffe" {
			continue
		}
		if u.Host == "" {
			return "", "", fmt.Errorf("trust: %q names no trust domain", u.String())
		}
		return u.Host, u.String(), nil
	}
	return "", "", errors.New(
		"this certificate carries no spiffe:// URI, so it does not say which trust domain it " +
			"belongs to. Pass the domain explicitly if you know it")
}

// BelongsTo reports whether an identity may be asserted by a trust domain.
//
// Exact match only. A domain does not gain authority over its DNS-looking
// children: aws.example.net may not assert identities in
// prod.aws.example.net unless that is a domain in its own right with its own
// bundle. Suffix matching here would recreate exactly the transitive trust
// docs/13 rejects, one string comparison at a time.
func BelongsTo(identityDomain, bundleDomain string) bool {
	return identityDomain != "" && identityDomain == bundleDomain
}

// VerifyLeaf verifies a certificate against the one domain entitled to vouch
// for it, and returns what it turned out to be.
//
// domainHint is used only when the certificate carries no spiffe:// URI. It
// never overrides a URI: letting a caller assert the domain of a certificate
// that already names one would make the name decorative.
func (s *State) VerifyLeaf(cert *x509.Certificate, domainHint string, now time.Time) (*Identity, error) {
	return s.VerifyLeafWith(cert, nil, domainHint, now)
}

// VerifyLeafWith is VerifyLeaf given the intermediates a presenter supplied,
// which is the shape a TLS verifier is in.
func (s *State) VerifyLeafWith(cert *x509.Certificate, extra []*x509.Certificate, domainHint string, now time.Time) (*Identity, error) {
	domain, id, err := TrustDomainOf(cert)
	if err != nil {
		if domainHint == "" {
			return nil, err
		}
		domain = domainHint
	} else if domainHint != "" && domainHint != domain {
		return nil, fmt.Errorf(
			"this certificate claims trust domain %q but was checked as %q. The certificate's own "+
				"name wins; refusing rather than verifying it as something it does not claim to be",
			domain, domainHint)
	}

	ds, ok := s.Domains[domain]
	if !ok {
		return nil, fmt.Errorf(
			"no trust bundle for domain %q. This consumer federates with %v — an identity from an "+
				"unfederated domain is refused, not looked up",
			domain, s.DomainNames())
	}
	if len(ds.Bundle) == 0 {
		return nil, fmt.Errorf(
			"domain %q is pinned but no bundle is stored for it. Run `signet trust fetch` for that "+
				"domain before verifying its identities", domain)
	}

	// Re-verify the bundle every time rather than trusting that it was fine
	// when stored: this is where staleness and rollback are caught, and a
	// bundle that has gone stale since it was fetched must stop being usable
	// without anyone having to remember to re-check it.
	verified, err := verifyStored(ds, domain, now)
	if err != nil {
		return nil, err
	}

	// The namespace check. In cascade mode this is the only thing separating
	// one domain from another, because their chains share a root.
	if id != "" && !BelongsTo(domain, verified.Domain) {
		return nil, fmt.Errorf(
			"identity %s is not within trust domain %q, so that domain's bundle may not vouch for "+
				"it. Bundles are scoped to their own namespace on receipt precisely so a federated "+
				"partner cannot assert names belonging to someone else", id, verified.Domain)
	}

	anchor, err := verified.VerifyCert(cert, extra, now)
	if err != nil {
		return nil, fmt.Errorf("domain %q does not vouch for this certificate: %w", verified.Domain, err)
	}
	return &Identity{
		Domain: verified.Domain, URI: id, CN: cert.Subject.CommonName,
		Anchor: anchor.Name, AnchorRole: anchor.Role,
	}, nil
}

// VerifyCert verifies a leaf against this bundle and returns the anchor it
// terminated at.
//
// extra holds intermediates supplied by whoever presented the certificate — a
// TLS peer sends its own chain, and this models that faithfully rather than
// pretending the verifier only ever sees what the bundle published.
//
// # Why the published-issuer check exists
//
// Building a path to the anchor is not sufficient under cascade. Every domain's
// issuer descends from one organizational root, so a *sibling* domain's issuer
// also chains to that root — and if the presenter supplies it, the path is
// genuinely valid. Measured during milestone 4c: with peer-supplied
// intermediates, home.example.net's issuer could mint
// spiffe://gcp.example.net/... and have it verify against gcp's own bundle.
//
// So after a chain is found, every intermediate in it must be one this bundle
// published. That is what makes a bundle's issuer list load-bearing rather than
// a convenience for path building, and it is what actually separates sibling
// domains in cascade mode.
func (p *Payload) VerifyCert(cert *x509.Certificate, extra []*x509.Certificate, now time.Time) (*Anchor, error) {
	published := map[string]bool{}
	revoked := map[string]bool{}
	for _, r := range p.Revoked {
		revoked[r] = true
	}
	for _, iss := range p.Issuers {
		if !revoked[iss.SPKI] {
			published[iss.SPKI] = true
		}
	}

	// Anchors are tried most specific first: verifying under a pinned issuer is
	// a stronger statement than merely chaining to a shared root, and the
	// caller is told which it got rather than having to assume.
	var lastErr error
	for _, role := range []AnchorRole{RoleIssuer, RoleRoot} {
		for i := range p.Anchors {
			a := &p.Anchors[i]
			if a.Role != role {
				continue
			}
			if revoked[a.SPKI] {
				continue
			}
			roots, inter, err := p.Pool(a)
			if err != nil {
				lastErr = err
				continue
			}
			// Merge in what the presenter offered. It may help build a path; it
			// may not smuggle in an unpublished issuer, because the check below
			// runs on whatever chain comes back.
			for _, c := range extra {
				inter.AddCert(c)
			}
			chains, err := cert.Verify(x509.VerifyOptions{
				Roots: roots, Intermediates: inter, CurrentTime: now,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			})
			if err != nil {
				lastErr = err
				continue
			}
			if err := chainUsesPublishedIssuers(chains, a, published); err != nil {
				lastErr = err
				continue
			}
			return a, nil
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no anchor in this bundle produced a path")
	}
	return nil, lastErr
}

// chainUsesPublishedIssuers rejects a chain that reaches the anchor through an
// intermediate the bundle never published.
func chainUsesPublishedIssuers(chains [][]*x509.Certificate, anchor *Anchor, published map[string]bool) error {
	var lastErr error
	for _, chain := range chains {
		// A length-1 chain means the presented certificate IS the anchor —
		// Go returns that when the leaf is itself in the root pool. There are
		// no intermediates to check, and slicing [1:0] would panic.
		if len(chain) < 2 {
			lastErr = errors.New(
				"the presented certificate is itself an anchor, not a leaf issued beneath one. " +
					"An anchor vouches for others; it does not vouch for itself as an identity")
			continue
		}
		ok := true
		// Skip the leaf (index 0) and the anchor itself (last).
		for _, c := range chain[1 : len(chain)-1] {
			fp := Fingerprint(c)
			if published[fp] || fp == anchor.SPKI {
				continue
			}
			ok = false
			lastErr = fmt.Errorf(
				"the chain reaches this domain's anchor through %q, which the domain does not "+
					"publish as one of its issuers. Under a shared root a sibling domain's issuer "+
					"chains to the same anchor, so a valid path is not by itself proof that this "+
					"domain vouched for the certificate", c.Subject.CommonName)
			break
		}
		if ok {
			return nil
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no chain used only published issuers")
	}
	return lastErr
}

// verifyStored re-checks a stored bundle against its own pin and the epoch this
// consumer has accepted.
func verifyStored(ds DomainState, domain string, now time.Time) (*Payload, error) {
	var b Bundle
	if err := json.Unmarshal(ds.Bundle, &b); err != nil {
		return nil, err
	}
	p, err := Verify(&b, VerifyOptions{
		PinnedSPKI: ds.PinnedSPKI, Domain: domain, LastEpoch: ds.LastEpoch,
		Now: now, Skew: 5 * time.Minute,
	})
	if err != nil {
		return nil, fmt.Errorf("the stored bundle for %q is no longer usable: %w", domain, err)
	}
	return p, nil
}

// Peer records a verified bundle for a domain, establishing or refreshing a
// federation link.
//
// The domain is taken from the bundle's own verified payload, never from the
// caller: a peer may describe only itself, so letting a caller file someone
// else's bundle under a chosen name would defeat the scoping above.
func (s *State) Peer(pin string, raw []byte, now time.Time) (*Payload, error) {
	var b Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("this does not parse as a trust bundle: %w", err)
	}
	peek, err := PayloadOf(&b)
	if err != nil {
		return nil, err
	}
	cur := s.Domains[peek.Domain]
	p, err := Verify(&b, VerifyOptions{
		PinnedSPKI: pin, Domain: peek.Domain, LastEpoch: cur.LastEpoch,
		Now: now, Skew: 5 * time.Minute,
	})
	if err != nil {
		return nil, err
	}
	if err := s.Pin(p.Domain, pin); err != nil {
		return nil, err
	}
	st := s.Domains[p.Domain]
	st.Bundle = append([]byte(nil), raw...)
	st.LastEpoch, st.UpdatedAt = p.Epoch, now.Unix()
	s.Domains[p.Domain] = st
	return p, nil
}

// SovereigntyOf reports whether a domain stands on a root of its own, or shares
// one with other domains this consumer federates with.
//
// It is deliberately a property of the FABRIC, not of a single bundle. From one
// bundle you cannot tell a domain's own root from its parent's: both appear as
// a self-signed root anchor, and nothing in the certificate says whether anyone
// else answers to it. What a consumer *can* observe is whether two domains it
// trusts present the same root — and that is the fact that matters, because a
// shared root means whoever holds it could mint into either namespace.
//
// Returns the domains sharing this one's root, empty if it stands alone.
func (s *State) SharesRootWith(domain string) []string {
	mine := rootSPKIs(s.Domains[domain].Bundle)
	if len(mine) == 0 {
		return nil
	}
	var out []string
	for _, other := range s.DomainNames() {
		if other == domain {
			continue
		}
		for spki := range rootSPKIs(s.Domains[other].Bundle) {
			if mine[spki] {
				out = append(out, other)
				break
			}
		}
	}
	return out
}

// Sovereignty describes a domain's standing within this consumer's fabric.
func (s *State) Sovereignty(domain string) string {
	if len(s.Domains[domain].Bundle) == 0 {
		return "unknown"
	}
	if shared := s.SharesRootWith(domain); len(shared) > 0 {
		return "shared root"
	}
	return "sovereign"
}

func rootSPKIs(raw []byte) map[string]bool {
	out := map[string]bool{}
	p, err := PayloadOfBytes(raw)
	if err != nil {
		return out
	}
	for i := range p.Anchors {
		if p.Anchors[i].Role == RoleRoot {
			out[p.Anchors[i].SPKI] = true
		}
	}
	return out
}
