package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mcarey42/signet/internal/ca"
	"github.com/mcarey42/signet/internal/seal"
	"github.com/mcarey42/signet/internal/trust"
)

// A trust bundle is how a consumer learns what to trust without being
// reinstalled. The same signed artifact serves both flows in docs/02: a cascade
// consumer selects the root anchor and accepts every issuer beneath it; a
// pinned consumer selects one issuer anchor and accepts nothing else, including
// a replacement the root could mint. Selection is the consumer's choice, made
// locally, from an artifact it did not have to trust to read.
//
//	signet ca bundle    -root DIR -domain NAME -out FILE   (offline, with the root)
//	signet trust pin    -root DIR                          (fingerprint to hand out)
//	signet trust install -data-dir DIR -bundle FILE        (publish it on a node)
//	signet trust fetch  -url URL -pin FP -domain NAME      (consumer: fetch + verify)
//	signet trust show   -bundle FILE                       (what does it say)
//	signet trust verify -bundle FILE -pin FP               (would I accept it)

const trustUsage = `signet trust — trust bundles

  pin      print the fingerprint to distribute out of band
  install  publish a root-signed bundle on this node
  fetch    fetch a bundle from a domain, verify it, and install the anchor
  show     print what a bundle says (does not imply trusting it)
  verify   check a bundle against a pinned fingerprint
  peers    list the trust domains this consumer federates with
  check    verify a certificate against whichever domain may vouch for it
`

func cmdTrust(args []string) error {
	if len(args) < 1 {
		fmt.Fprint(os.Stderr, trustUsage)
		return errors.New("trust: expected a subcommand")
	}
	switch args[0] {
	case "pin":
		return trustPin(args[1:])
	case "install":
		return trustInstall(args[1:])
	case "fetch":
		return trustFetch(args[1:])
	case "show":
		return trustShow(args[1:])
	case "verify":
		return trustVerify(args[1:])
	case "peers":
		return trustPeers(args[1:])
	case "check":
		return trustCheck(args[1:])
	case "-h", "--help", "help":
		fmt.Print(trustUsage)
		return nil
	}
	return fmt.Errorf("trust: unknown subcommand %q — run `signet trust help`", args[0])
}

// caBundle is the publishing ceremony. It runs where the root key is, because
// only the root may say who is trusted (internal/trust).
func caBundle(args []string) error {
	fs := flag.NewFlagSet("ca bundle", flag.ExitOnError)
	rootDir := fs.String("root", "", "directory holding root.crt and root.key (or root.ref)")
	domain := fs.String("domain", "", "the trust domain this bundle describes, e.g. home.example.net")
	out := fs.String("out", "", "file to write the bundle to")
	maxAge := fs.Duration("max-age", 30*24*time.Hour, "how long a consumer may believe this bundle")
	epoch := fs.Uint64("epoch", 0, "publication number (default: one past the last published here)")
	revoke := fs.String("revoke", "", "comma-separated issuer fingerprints to withdraw")
	extraIssuers := fs.String("issuer", "", "comma-separated issuer common names to publish regardless of their name constraints")
	sealCfg := fs.String("seal", "", "seal holding the root key, for a hardware root")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *rootDir == "" || *domain == "" || *out == "" {
		return errors.New("ca bundle: -root, -domain and -out are all required")
	}

	rootCert, signer, closeFn, err := openRoot(*rootDir, *sealCfg)
	if err != nil {
		return fmt.Errorf("ca bundle: %w", err)
	}
	defer closeFn()

	anchors := []trust.Anchor{{
		Role: trust.RoleRoot, Name: rootCert.Subject.CommonName,
		CertPEM: pemEncodeCert(rootCert), SPKI: trust.Fingerprint(rootCert),
	}}
	all, err := readIssuerDir(filepath.Join(*rootDir, "issuers"))
	if err != nil {
		return fmt.Errorf("ca bundle: %w", err)
	}
	if len(all) == 0 {
		return fmt.Errorf(
			"ca bundle: no issuer certificates in %s. `signet ca sign-issuer` records each issuer "+
				"it signs there; a bundle with no issuers would name anchors but give a verifier "+
				"nothing to build a path with", filepath.Join(*rootDir, "issuers"))
	}

	// Publish only the issuers that may actually issue for THIS domain.
	//
	// The root signs every domain's issuer, so its issuer directory holds all
	// of them. Publishing that whole directory in every domain's bundle is what
	// makes the sibling-impersonation defence vacuous: a verifier requires the
	// chain to run through an issuer the domain published, and if a sibling's
	// issuer is in that list, the requirement is satisfied by the very issuer
	// it was meant to exclude. Found by the test-design pass; both existing
	// tests missed it because both built the issuer set by hand instead of
	// using this command.
	//
	// The filter is the delegation already recorded in the certificate: an
	// issuer whose name constraints do not permit this domain has no business
	// vouching for it. That needs no new bookkeeping from the operator, and it
	// cannot drift from what the issuer is actually allowed to do.
	issuers, excluded := filterIssuersForDomain(
		all, *domain, splitList(*extraIssuers), recordedDomains(filepath.Join(*rootDir, "issuers")))
	if len(issuers) == 0 {
		return fmt.Errorf(
			"ca bundle: none of the %d issuer(s) in %s are constrained to %q, so this bundle would "+
				"publish no issuer that may vouch for it. Sign an issuer with `-domains %s`, or name "+
				"one explicitly with -issuer, or record the association at signing time with "+
				"`ca sign-issuer -trust-domain %s`",
			len(all), filepath.Join(*rootDir, "issuers"), *domain, *domain, *domain)
	}
	for _, c := range issuers {
		fp := trust.Fingerprint(c)
		anchors = append(anchors, trust.Anchor{
			Role: trust.RoleIssuer, Name: c.Subject.CommonName, CertPEM: pemEncodeCert(c), SPKI: fp,
		})
	}
	pubIssuers := make([]trust.Issuer, 0, len(issuers))
	for _, c := range issuers {
		pubIssuers = append(pubIssuers, trust.Issuer{
			Name: c.Subject.CommonName, CertPEM: pemEncodeCert(c), SPKI: trust.Fingerprint(c),
		})
	}

	// The epoch advances here, at the only place that can publish, so it cannot
	// be made to go backwards by a node's local state being lost.
	epochPath := filepath.Join(*rootDir, "bundle.epoch")
	n := *epoch
	if n == 0 {
		last := uint64(0)
		if blob, err := os.ReadFile(epochPath); err == nil {
			fmt.Sscanf(strings.TrimSpace(string(blob)), "%d", &last)
		}
		n = last + 1
	}

	payload, err := trust.Build(*domain, n, *maxAge, anchors, pubIssuers, time.Now())
	if err != nil {
		return fmt.Errorf("ca bundle: %w", err)
	}
	payload.Revoked = splitList(*revoke)

	bundle, err := trust.Sign(payload, signer)
	if err != nil {
		return fmt.Errorf("ca bundle: %w", err)
	}
	blob, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, blob, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(epochPath, []byte(fmt.Sprintf("%d\n", n)), 0o600); err != nil {
		return err
	}

	fmt.Printf("bundle written to %s\n", *out)
	fmt.Printf("  domain:   %s\n  epoch:    %d\n  anchors:  %d (1 root, %d issuer)\n  max age:  %s\n",
		*domain, n, len(anchors), len(issuers), *maxAge)
	for _, c := range issuers {
		fmt.Printf("  publish:  %s\n", c.Subject.CommonName)
	}
	// Say what was left out and why. A filter that works silently is one nobody
	// can check, and this one decides whether a sibling can impersonate you.
	for _, c := range excluded {
		fmt.Printf("  omitted:  %s (not constrained to %s)\n", c.Subject.CommonName, *domain)
	}
	if len(payload.Revoked) > 0 {
		fmt.Printf("  revoked:  %v\n", payload.Revoked)
	}
	fmt.Printf("\nConsumers must pin this fingerprint out of band before the bundle means anything:\n  %s\n",
		trust.Fingerprint(rootCert))
	fmt.Println("\nPublish it with `signet trust install` on a node. Bundles expire, so republish")
	fmt.Println("before the max age elapses or consumers will refuse to refresh.")
	return nil
}

func trustPin(args []string) error {
	fs := flag.NewFlagSet("trust pin", flag.ExitOnError)
	rootDir := fs.String("root", "", "directory holding root.crt")
	certPath := fs.String("cert", "", "a certificate file, instead of -root")
	if err := fs.Parse(args); err != nil {
		return err
	}
	path := *certPath
	if path == "" {
		if *rootDir == "" {
			return errors.New("trust pin: pass -root DIR or -cert FILE")
		}
		path = filepath.Join(*rootDir, "root.crt")
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	cert, err := parseCertPEM(blob)
	if err != nil {
		return fmt.Errorf("trust pin: %s: %w", path, err)
	}
	fmt.Printf("%s\n", trust.Fingerprint(cert))
	fmt.Fprintf(os.Stderr, "\n%s\nDistribute this fingerprint by a channel that does not depend on Signet.\n",
		cert.Subject.CommonName)
	return nil
}

func trustInstall(args []string) error {
	fs := flag.NewFlagSet("trust install", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "data directory of this node (offline; the server must be stopped)")
	addr := fs.String("addr", "", "a running node's API instead, e.g. https://signet.example.net:8200")
	token := fs.String("token", "", "token with admin authority at /, when using -addr")
	sealKey := fs.String("seal", "", "seal (default DATA-DIR/seal.key)")
	bundlePath := fs.String("bundle", "", "the root-signed bundle to publish")
	actorPath := fs.String("actor", "/people/root", "principal performing the change")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *bundlePath == "" {
		return errors.New("trust install: -bundle is required")
	}
	if *dataDir == "" && *addr == "" {
		return errors.New(
			"trust install: pass -addr to publish to a running node, or -data-dir to publish " +
				"offline with the server stopped")
	}
	raw, err := os.ReadFile(*bundlePath)
	if err != nil {
		return err
	}
	if *addr != "" {
		return publishOverAPI(*addr, *token, raw)
	}
	node, k, err := openNode(*dataDir, sealURI(*dataDir, *sealKey))
	if err != nil {
		return err
	}
	defer node.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	actor, err := k.PrincipalByPath(ctx, *actorPath)
	if err != nil {
		return fmt.Errorf("trust install: actor %s: %w", *actorPath, err)
	}
	if err := k.PutTrustBundle(ctx, actor.ID, raw); err != nil {
		return fmt.Errorf("trust install: %w", err)
	}
	p, _ := payloadOf(raw)
	fmt.Printf("bundle published for domain %s, epoch %d\n", p.Domain, p.Epoch)
	fmt.Println("Consumers can now fetch it from this node with `signet trust fetch`.")
	return nil
}

// publishOverAPI is the normal path: a bundle expires on a schedule, so
// replacing one must not require stopping the node that serves it.
func publishOverAPI(addr, token string, raw []byte) error {
	if token == "" {
		return errors.New("trust install: -addr needs -token with admin authority at /")
	}
	req, err := http.NewRequest(http.MethodPut,
		strings.TrimSuffix(addr, "/")+"/v1/trust/bundle", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("trust install: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("trust install: the node refused the bundle (%s): %s", resp.Status, strings.TrimSpace(string(body)))
	}
	p, _ := payloadOf(raw)
	fmt.Printf("bundle published for domain %s, epoch %d\n", p.Domain, p.Epoch)
	fmt.Println("Consumers can now fetch it from this node with `signet trust fetch`.")
	return nil
}

func trustShow(args []string) error {
	fs := flag.NewFlagSet("trust show", flag.ExitOnError)
	bundlePath := fs.String("bundle", "", "bundle file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *bundlePath == "" {
		return errors.New("trust show: -bundle is required")
	}
	raw, err := os.ReadFile(*bundlePath)
	if err != nil {
		return err
	}
	p, err := payloadOf(raw)
	if err != nil {
		return err
	}
	// Deliberately unverified, and deliberately said out loud: reading a bundle
	// is not trusting it, and the difference matters enough to print.
	fmt.Printf("domain:    %s\nepoch:     %d\nissued:    %s\nexpires:   %s\n",
		p.Domain, p.Epoch, time.Unix(p.IssuedAt, 0).UTC().Format(time.RFC3339),
		time.Unix(p.IssuedAt, 0).Add(time.Duration(p.MaxAgeSec)*time.Second).UTC().Format(time.RFC3339))
	fmt.Println("\nanchors — a consumer picks exactly one:")
	for _, a := range p.Anchors {
		note := "everything this domain issues, now and later"
		if a.Role == trust.RoleIssuer {
			note = "only what this issuer signs"
		}
		fmt.Printf("  %-8s %-24s %s\n           %s\n", a.Role, a.Name, a.SPKI, note)
	}
	fmt.Println("\nissuers — used to build paths up to whichever anchor was chosen:")
	for _, i := range p.Issuers {
		state := ""
		for _, r := range p.Revoked {
			if r == i.SPKI {
				state = "  (REVOKED)"
			}
		}
		fmt.Printf("  %-24s %s%s\n", i.Name, i.SPKI, state)
	}
	fmt.Println("\nThis output is not a verification. Run `signet trust verify -pin ...` for that.")
	return nil
}

func trustVerify(args []string) error {
	fs := flag.NewFlagSet("trust verify", flag.ExitOnError)
	bundlePath := fs.String("bundle", "", "bundle file")
	pin := fs.String("pin", "", "fingerprint learned out of band")
	domain := fs.String("domain", "", "the domain expected")
	statePath := fs.String("state", "", "consumer state file, for rollback protection")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *bundlePath == "" || *pin == "" {
		return errors.New("trust verify: -bundle and -pin are both required")
	}
	raw, err := os.ReadFile(*bundlePath)
	if err != nil {
		return err
	}
	p, _, err := verifyBundle(raw, *pin, *domain, *statePath, false)
	if err != nil {
		return err
	}
	fmt.Printf("bundle accepted\n  domain: %s\n  epoch:  %d\n  signed by the pinned key %s\n",
		p.Domain, p.Epoch, *pin)
	return nil
}

// trustFetch is the consumer path end to end: fetch, verify against a
// fingerprint known in advance, choose an anchor, write it where a client can
// use it.
func trustFetch(args []string) error {
	fs := flag.NewFlagSet("trust fetch", flag.ExitOnError)
	url := fs.String("url", "", "a Signet node, e.g. https://signet.example.net:8200")
	pin := fs.String("pin", "", "fingerprint learned out of band (required)")
	domain := fs.String("domain", "", "the domain expected")
	statePath := fs.String("state", "", "consumer state file (default ~/.signet/trust.json)")
	role := fs.String("anchor", "root", "which anchor to install: 'root' (cascade) or 'issuer'")
	name := fs.String("anchor-name", "", "issuer name, when -anchor=issuer")
	out := fs.String("out", "", "file to write the chosen anchor to")
	issuersOut := fs.String("issuers-out", "", "file to write the surviving issuer certificates to")
	insecure := fs.Bool("insecure-transport", false, "skip TLS verification of the fetch itself (the bundle is still verified)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *url == "" || *pin == "" {
		return errors.New(
			"trust fetch: -url and -pin are both required. Fetching without a pin would mean " +
				"trusting whatever answered, which is the problem bundles exist to solve")
	}
	*statePath = defaultStatePath(*statePath)

	client := &http.Client{Timeout: 30 * time.Second}
	if *insecure {
		// The bundle carries its own signature, so transport verification is
		// belt to that braces — but it is still the thing that stops an
		// observer seeing which anchor you chose, so it is opt-out and loud.
		fmt.Fprintln(os.Stderr, "warning: not verifying TLS on the fetch itself; the bundle's signature is still checked")
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	// Redirects are not followed: a redirect on a trust endpoint is an
	// invitation to fetch from somewhere else, and the pin is the only thing
	// that would catch it (E-01 FED-4).
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return fmt.Errorf(
			"the bundle endpoint redirected to %s. Trust endpoints are not followed across "+
				"redirects; point -url at the node that serves the bundle", req.URL)
	}
	endpoint := strings.TrimSuffix(*url, "/") + "/v1/trust/bundle"
	resp, err := client.Get(endpoint)
	if err != nil {
		return fmt.Errorf("trust fetch: %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("trust fetch: %s returned %s", endpoint, resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}

	p, st, err := verifyBundle(raw, *pin, *domain, *statePath, true)
	if err != nil {
		return err
	}
	anchor, err := p.SelectAnchor(trust.AnchorRole(*role), *name)
	if err != nil {
		return fmt.Errorf("trust fetch: %w", err)
	}
	if err := st.Save(); err != nil {
		return err
	}

	fmt.Printf("bundle accepted from %s\n  domain: %s\n  epoch:  %d\n", endpoint, p.Domain, p.Epoch)
	fmt.Printf("  anchor: %s %q\n", anchor.Role, anchor.Name)
	if anchor.Role == trust.RoleIssuer {
		fmt.Println("\nAnchored on one issuer: this client will accept only what that issuer signs,")
		fmt.Println("including refusing a replacement issued by the root. Rotating it means")
		fmt.Println("re-running this command, so publish the new issuer before retiring the old.")
		// Measured, not assumed: OpenSSL rejects a non-self-signed trust anchor
		// outright unless told to accept partial chains, so an operator who
		// pins an intermediate and tests with `openssl verify` will see a
		// failure that looks like a broken certificate rather than a verifier
		// policy. Say so here, where the choice is being made.
		fmt.Println("\nNote: this anchor is an intermediate, not a self-signed root. Verifiers differ")
		fmt.Println("on whether that is allowed:")
		fmt.Println("  Go (crypto/x509)  accepts it as a root pool entry")
		fmt.Println("  OpenSSL           refuses unless given -partial_chain")
		fmt.Println("  others            vary; test yours before relying on this mode")
		fmt.Println("Anchor on the root instead if your consumers cannot be configured for it.")
	} else {
		fmt.Println("\nAnchored on the domain root: issuers may rotate beneath it without touching")
		fmt.Println("this client.")
	}
	if *out != "" {
		if err := os.WriteFile(*out, anchor.CertPEM, 0o644); err != nil {
			return err
		}
		fmt.Printf("\nanchor written to %s\n", *out)
	}
	if *issuersOut != "" {
		// Withdrawn issuers are omitted. This is what makes revocation mean
		// something to a consumer that builds its own paths — one that instead
		// accepts whatever chain a server presents will not notice, so
		// withdrawing an issuer is not a substitute for letting it expire.
		var buf []byte
		kept, dropped := 0, 0
		for _, iss := range p.Issuers {
			if isRevoked(p, iss.SPKI) {
				dropped++
				continue
			}
			buf = append(buf, iss.CertPEM...)
			kept++
		}
		if err := os.WriteFile(*issuersOut, buf, 0o644); err != nil {
			return err
		}
		fmt.Printf("%d issuer(s) written to %s", kept, *issuersOut)
		if dropped > 0 {
			fmt.Printf("; %d withdrawn and omitted", dropped)
		}
		fmt.Println()
	}
	return nil
}

func isRevoked(p *trust.Payload, spki string) bool {
	for _, r := range p.Revoked {
		if r == spki {
			return true
		}
	}
	return false
}

// verifyBundle runs the full consumer check, including rollback protection
// against remembered state.
func verifyBundle(raw []byte, pin, domain, statePath string, record bool) (*trust.Payload, *trust.State, error) {
	var b trust.Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, nil, fmt.Errorf("this does not parse as a trust bundle: %w", err)
	}
	st := &trust.State{Domains: map[string]trust.DomainState{}}
	if statePath != "" {
		var err error
		if st, err = trust.LoadState(statePath); err != nil {
			return nil, nil, err
		}
	}
	// Peek at the domain only to look up remembered state. Nothing is trusted
	// on the strength of it; verification below is what decides.
	peek, err := trust.PayloadOf(&b)
	if err != nil {
		return nil, nil, err
	}
	d := domain
	if d == "" {
		d = peek.Domain
	}
	p, err := trust.Verify(&b, trust.VerifyOptions{
		PinnedSPKI: pin, Domain: domain, LastEpoch: st.Get(d).LastEpoch,
		Now: time.Now(), Skew: 5 * time.Minute,
	})
	if err != nil {
		return nil, nil, err
	}
	if record && statePath != "" {
		// Store the bundle, not merely the epoch: a consumer that federates
		// with several domains keeps one bundle per domain and re-verifies it
		// on use, so staleness and rollback are caught without a re-fetch.
		if _, err := st.Peer(pin, raw, time.Now()); err != nil {
			return nil, nil, err
		}
	}
	return p, st, nil
}

func openRoot(rootDir, sealCfg string) (*x509.Certificate, crypto.Signer, func(), error) {
	certPEM, err := os.ReadFile(filepath.Join(rootDir, "root.crt"))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("reading the root certificate: %w", err)
	}
	var (
		keyPEM  []byte
		ref     *seal.KeyRef
		s       seal.Seal
		closeFn = func() {}
	)
	if blob, err := os.ReadFile(filepath.Join(rootDir, "root.ref")); err == nil {
		ref = &seal.KeyRef{}
		if err := jsonUnmarshal(blob, ref); err != nil {
			return nil, nil, nil, fmt.Errorf("reading the root key reference: %w", err)
		}
		if sealCfg == "" {
			return nil, nil, nil, fmt.Errorf(
				"this root is held in hardware (%s); pass -seal naming the token that holds it", ref)
		}
		if s, err = seal.Open(sealCfg); err != nil {
			return nil, nil, nil, fmt.Errorf("opening the seal: %w", err)
		}
		closeFn = func() { s.Close() }
	} else if keyPEM, err = os.ReadFile(filepath.Join(rootDir, "root.key")); err != nil {
		return nil, nil, nil, fmt.Errorf(
			"reading the root key: %w — a root directory needs either root.key or root.ref "+
				"alongside root.crt", err)
	}
	cert, signer, err := ca.LoadRootSigner(certPEM, keyPEM, ref, s)
	if err != nil {
		closeFn()
		return nil, nil, nil, err
	}
	return cert, signer, closeFn, nil
}

func readIssuerDir(dir string) ([]*x509.Certificate, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []*x509.Certificate
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".crt") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // stable bundle contents across publications
	for _, n := range names {
		blob, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		cert, err := parseCertPEM(blob)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", n, err)
		}
		out = append(out, cert)
	}
	return out, nil
}

func payloadOf(raw []byte) (*trust.Payload, error) {
	var b trust.Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("this does not parse as a trust bundle: %w", err)
	}
	return trust.PayloadOf(&b)
}

func parseCertPEM(blob []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(blob)
	if blk == nil {
		return nil, errors.New("not PEM")
	}
	return x509.ParseCertificate(blk.Bytes)
}

func pemEncodeCert(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func trustPeers(args []string) error {
	fs := flag.NewFlagSet("trust peers", flag.ExitOnError)
	statePath := fs.String("state", "", "consumer state file (default ~/.signet/trust.json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := trust.LoadState(defaultStatePath(*statePath))
	if err != nil {
		return err
	}
	names := st.DomainNames()
	if len(names) == 0 {
		return fmt.Errorf(
			"this consumer federates with no domains yet. `signet trust fetch -url ... -pin ...` "+
				"establishes the first link; the pin must come from somewhere other than the "+
				"domain you are pinning (state: %s)", defaultStatePath(*statePath))
	}
	fmt.Printf("%-24s %-12s %-6s %-8s %s\n", "DOMAIN", "STANDING", "EPOCH", "STATUS", "SHARES ROOT WITH")
	shared := false
	for _, d := range names {
		ds := st.Get(d)
		status := "ok"
		if p, err := trust.PayloadOfBytes(ds.Bundle); err == nil {
			expires := time.Unix(p.IssuedAt, 0).Add(time.Duration(p.MaxAgeSec) * time.Second)
			if time.Now().After(expires) {
				status = "STALE"
			}
		} else if len(ds.Bundle) == 0 {
			status = "no bundle"
		}
		with := strings.Join(st.SharesRootWith(d), ", ")
		if with == "" {
			with = "-"
		} else {
			shared = true
		}
		fmt.Printf("%-24s %-12s %-6d %-8s %s\n", d, st.Sovereignty(d), ds.LastEpoch, status, with)
	}
	fmt.Println("\nBundles are held separately and never merged: an identity is verified only")
	fmt.Println("against the domain that may vouch for it.")
	if shared {
		fmt.Println("\nDomains sharing a root are not sovereign against each other: whoever holds")
		fmt.Println("that root could mint into either namespace. Signet still keeps them apart —")
		fmt.Println("each domain publishes its own issuers and a chain through anyone else's is")
		fmt.Println("refused — but that is a policy boundary, not a cryptographic one.")
	}
	return nil
}

// trustCheck answers the question a relying party actually has: is this
// certificate something I should believe, and who says so.
func trustCheck(args []string) error {
	fs := flag.NewFlagSet("trust check", flag.ExitOnError)
	certPath := fs.String("cert", "", "certificate to check")
	domain := fs.String("domain", "", "trust domain, when the certificate carries no spiffe:// URI")
	chainPath := fs.String("chain", "", "intermediates the presenter supplied, as a TLS peer would")
	statePath := fs.String("state", "", "consumer state file (default ~/.signet/trust.json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *certPath == "" {
		return errors.New("trust check: -cert is required")
	}
	blob, err := os.ReadFile(*certPath)
	if err != nil {
		return err
	}
	cert, err := parseCertPEM(blob)
	if err != nil {
		return fmt.Errorf("trust check: %s: %w", *certPath, err)
	}
	st, err := trust.LoadState(defaultStatePath(*statePath))
	if err != nil {
		return err
	}
	var extra []*x509.Certificate
	if *chainPath != "" {
		blob, err := os.ReadFile(*chainPath)
		if err != nil {
			return err
		}
		for rest := blob; len(rest) > 0; {
			var blk *pem.Block
			if blk, rest = pem.Decode(rest); blk == nil {
				break
			}
			if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
				extra = append(extra, c)
			}
		}
	}
	id, err := st.VerifyLeafWith(cert, extra, *domain, time.Now())
	if err != nil {
		return fmt.Errorf("trust check: %w", err)
	}
	fmt.Printf("accepted\n  identity: %s\n  domain:   %s\n  anchor:   %s %q\n",
		orDash(id.URI, id.CN), id.Domain, id.AnchorRole, id.Anchor)
	if id.AnchorRole == trust.RoleRoot {
		fmt.Println("\nVerified via the domain's root anchor, and through an issuer this domain")
		fmt.Println("publishes. Under a shared root the chain alone would not have been enough:")
		fmt.Println("a sibling domain's issuer reaches the same anchor.")
	}
	return nil
}

func defaultStatePath(p string) string {
	if p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".signet", "trust.json")
}

func short(spki string) string {
	if len(spki) > 26 {
		return spki[:26] + "..."
	}
	return spki
}

func orDash(a, b string) string {
	if a != "" {
		return a
	}
	if b != "" {
		return b
	}
	return "-"
}

// filterIssuersForDomain keeps issuers whose name constraints permit domain.
//
// An issuer with NO permitted-DNS constraint is unconstrained and could issue
// for anything, so it is not included automatically — including it would
// reintroduce exactly the problem this filter exists to solve. Name it with
// -issuer if that is genuinely intended.
func filterIssuersForDomain(all []*x509.Certificate, domain string, explicit []string,
	recorded map[string]string) (keep, drop []*x509.Certificate) {

	named := map[string]bool{}
	for _, n := range explicit {
		named[strings.TrimSpace(n)] = true
	}
	for _, c := range all {
		fp := strings.TrimPrefix(trust.Fingerprint(c), "sha256:")
		switch {
		case named[c.Subject.CommonName]:
			keep = append(keep, c) // named explicitly by the operator
		case recorded[fp] != "":
			// An association recorded at signing time is authoritative: it says
			// what the operator meant, rather than what a name happens to imply.
			if recorded[fp] == domain {
				keep = append(keep, c)
			} else {
				drop = append(drop, c)
			}
		case permitsDomain(c, domain):
			keep = append(keep, c) // no record: fall back to the delegation
		default:
			drop = append(drop, c)
		}
	}
	return keep, drop
}

// recordedDomains reads the trust-domain sidecars written by `ca sign-issuer`.
func recordedDomains(dir string) map[string]string {
	out := map[string]string{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".domain") {
			continue
		}
		blob, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		out[strings.TrimSuffix(e.Name(), ".domain")] = strings.TrimSpace(string(blob))
	}
	return out
}

// permitsDomain reports whether a certificate's permitted DNS subtrees cover
// domain. Matching follows RFC 5280 name-constraint semantics: a permitted
// subtree covers itself and anything beneath it, at a label boundary.
func permitsDomain(c *x509.Certificate, domain string) bool {
	if len(c.PermittedDNSDomains) == 0 {
		return false
	}
	d := strings.ToLower(strings.TrimSuffix(domain, "."))
	for _, p := range c.PermittedDNSDomains {
		p = strings.ToLower(strings.TrimPrefix(strings.TrimSuffix(p, "."), "."))
		if d == p || strings.HasSuffix(d, "."+p) {
			return true
		}
	}
	return false
}
