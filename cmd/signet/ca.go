package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mcarey42/signet/internal/ca"
	"github.com/mcarey42/signet/internal/kernel"
	"github.com/mcarey42/signet/internal/seal"
	"github.com/mcarey42/signet/internal/trust"
)

// The CA ceremonies are separate commands because they happen in separate
// places. A root is created once and kept offline; each signing node generates
// its own key where that key will live and asks the root to certify it. The
// root key travels nowhere — a signing request travels to the root instead
// (docs/02).
//
//	signet ca init-root   -out DIR -common-name NAME   (once, offline)
//	signet ca request     -data-dir DIR -out FILE      (on each signing node)
//	signet ca sign-issuer -root DIR -csr FILE -out F   (offline, with the root)
//	signet ca install     -data-dir DIR -cert FILE     (back on the node)
//	signet ca issuers     -data-dir DIR                (who can sign, and how)

const caUsage = `signet ca — certificate authority ceremonies

  init-root    create a root CA (once, offline; keep the result off the network)
  request      generate this node's issuing key and emit a signing request
  sign-issuer  sign a node's request with the root, delegating a namespace
  install      install a signed issuer certificate on this node
  issuers      list the issuing authorities in this domain
  bundle       publish the domain's signed trust bundle (offline, with the root)
`

func cmdCA(args []string) error {
	if len(args) < 1 {
		fmt.Fprint(os.Stderr, caUsage)
		return errors.New("ca: expected a subcommand")
	}
	switch args[0] {
	case "init-root":
		return caInitRoot(args[1:])
	case "request":
		return caRequest(args[1:])
	case "sign-issuer":
		return caSignIssuer(args[1:])
	case "install":
		return caInstall(args[1:])
	case "issuers":
		return caIssuers(args[1:])
	case "bundle":
		return caBundle(args[1:])
	case "-h", "--help", "help":
		fmt.Print(caUsage)
		return nil
	}
	return fmt.Errorf("ca: unknown subcommand %q — run `signet ca help` for the ceremony list", args[0])
}

func caInitRoot(args []string) error {
	fs := flag.NewFlagSet("ca init-root", flag.ExitOnError)
	out := fs.String("out", "", "directory to write the root material into")
	cn := fs.String("common-name", "", "name for the root, e.g. your organization")
	ttl := fs.Duration("ttl", 10*365*24*time.Hour, "root lifetime")
	inHardware := fs.Bool("in-hardware", false, "generate the root key inside a token so it can never leave (requires -seal pkcs11:...)")
	sealCfg := fs.String("seal", "", "seal to hold the root key, when -in-hardware is set")
	label := fs.String("label", "signet-root-ca", "label for the root key inside the token")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" || *cn == "" {
		return errors.New("ca init-root: -out and -common-name are both required")
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		return err
	}
	certPath := filepath.Join(*out, "root.crt")
	if _, err := os.Stat(certPath); err == nil {
		return fmt.Errorf(
			"ca init-root: %s already exists. Refusing to overwrite a root — a second root at the "+
				"same path would orphan every certificate issued under the first", certPath)
	}

	var (
		root *ca.Root
		err  error
	)
	if *inHardware {
		if *sealCfg == "" {
			return errors.New("ca init-root: -in-hardware needs -seal 'pkcs11:?module=...&token=...&pin=...&label=...'")
		}
		s, err2 := seal.Open(*sealCfg)
		if err2 != nil {
			return fmt.Errorf("ca init-root: opening the seal: %w", err2)
		}
		defer s.Close()
		ss, err2 := seal.AsSigningSeal(s)
		if err2 != nil {
			return fmt.Errorf("ca init-root: %w", err2)
		}
		root, err = ca.NewRootInHardware(ss, *cn, *label, *ttl, time.Now())
	} else {
		root, err = ca.NewRoot(*cn, *ttl, time.Now())
	}
	if err != nil {
		return fmt.Errorf("ca init-root: %w", err)
	}

	if err := os.WriteFile(certPath, root.CertPEM, 0o644); err != nil {
		return err
	}
	fmt.Printf("root created\n  certificate: %s\n", certPath)
	if root.Ref != nil {
		refPath := filepath.Join(*out, "root.ref")
		blob, _ := jsonMarshal(root.Ref)
		if err := os.WriteFile(refPath, blob, 0o600); err != nil {
			return err
		}
		fmt.Printf("  key:         held in %s\n  reference:   %s\n", root.Ref, refPath)
		fmt.Println("\nThere is no root key file and none can be made: the key is non-extractable.")
		fmt.Println("Protect the token accordingly — losing it means re-establishing this trust chain.")
		return nil
	}
	keyPath := filepath.Join(*out, "root.key")
	if err := os.WriteFile(keyPath, root.KeyPEM, 0o400); err != nil {
		return err
	}
	fmt.Printf("  key:         %s\n", keyPath)
	fmt.Println("\nTake this directory offline. The root key is needed only to certify issuers —")
	fmt.Println("a few times per decade — and nothing that runs continuously should hold it.")
	fmt.Println("Back it up somewhere it cannot be lost: split across locations if you can,")
	fmt.Println("because losing it means re-establishing this trust chain from scratch.")
	return nil
}

func caRequest(args []string) error {
	fs := flag.NewFlagSet("ca request", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "data directory of the node requesting an issuer")
	sealKey := fs.String("seal", "", "seal (default DATA-DIR/seal.key)")
	out := fs.String("out", "", "file to write the signing request to")
	cn := fs.String("common-name", "", "name for this issuer, e.g. 'home issuer A' (defaults to the node id)")
	label := fs.String("label", "signet-issuer", "label for the key if the seal can hold it")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dataDir == "" || *out == "" {
		return errors.New("ca request: -data-dir and -out are both required")
	}

	s, err := seal.Open(sealURI(*dataDir, *sealKey))
	if err != nil {
		return fmt.Errorf("ca request: opening this node's seal: %w", err)
	}
	defer s.Close()

	name := *cn
	if name == "" {
		name = "signet issuer"
	}
	req, err := ca.NewIssuerRequest(s, name, *label)
	if err != nil {
		return fmt.Errorf("ca request: %w", err)
	}
	if err := os.WriteFile(*out, req.CSRPEM, 0o644); err != nil {
		return err
	}
	// The key stays here. Only the request travels.
	pending := filepath.Join(*dataDir, "issuer-pending.json")
	blob, err := jsonMarshal(req)
	if err != nil {
		return err
	}
	if err := os.WriteFile(pending, blob, 0o600); err != nil {
		return err
	}

	fmt.Printf("signing request written to %s\n", *out)
	if req.Ref != nil {
		fmt.Printf("this issuer's key is held in %s and will not leave it\n", req.Ref)
	} else {
		fmt.Printf("this issuer's key is held at %s and does not travel with the request\n", pending)
	}
	fmt.Println("\nTake the request to the offline root, sign it with `signet ca sign-issuer`,")
	fmt.Println("and bring the certificate back with `signet ca install`.")
	return nil
}

func caSignIssuer(args []string) error {
	fs := flag.NewFlagSet("ca sign-issuer", flag.ExitOnError)
	rootDir := fs.String("root", "", "directory holding root.crt and root.key (or root.ref)")
	csrPath := fs.String("csr", "", "the signing request to certify")
	out := fs.String("out", "", "file to write the issuer certificate to")
	domains := fs.String("domains", "", "comma-separated DNS namespace this issuer may issue within")
	trustDomain := fs.String("trust-domain", "", "the trust domain this issuer serves, if it differs from -domains (recorded so `ca bundle` knows whose bundle it belongs in)")
	ipRanges := fs.String("ip-ranges", "", "comma-separated CIDRs it may issue IP SANs for (default: none, excluded outright)")
	ttl := fs.Duration("ttl", 365*24*time.Hour, "issuer lifetime")
	sealCfg := fs.String("seal", "", "seal holding the root key, for a hardware root")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *rootDir == "" || *csrPath == "" || *out == "" {
		return errors.New("ca sign-issuer: -root, -csr and -out are all required")
	}
	if *domains == "" {
		return errors.New(
			"ca sign-issuer: -domains is required. The namespace delegated here bounds everything " +
				"this issuer can ever produce, so it is the security decision of this ceremony and " +
				"will not be defaulted")
	}

	certPEM, err := os.ReadFile(filepath.Join(*rootDir, "root.crt"))
	if err != nil {
		return fmt.Errorf("ca sign-issuer: reading the root certificate: %w", err)
	}
	var (
		keyPEM []byte
		ref    *seal.KeyRef
		s      seal.Seal
	)
	if blob, err := os.ReadFile(filepath.Join(*rootDir, "root.ref")); err == nil {
		ref = &seal.KeyRef{}
		if err := jsonUnmarshal(blob, ref); err != nil {
			return fmt.Errorf("ca sign-issuer: reading the root key reference: %w", err)
		}
		if *sealCfg == "" {
			return fmt.Errorf(
				"ca sign-issuer: this root is held in hardware (%s); pass -seal naming the token that holds it", ref)
		}
		if s, err = seal.Open(*sealCfg); err != nil {
			return fmt.Errorf("ca sign-issuer: opening the seal: %w", err)
		}
		defer s.Close()
	} else {
		if keyPEM, err = os.ReadFile(filepath.Join(*rootDir, "root.key")); err != nil {
			return fmt.Errorf(
				"ca sign-issuer: reading the root key: %w — a root directory needs either root.key "+
					"or root.ref alongside root.crt", err)
		}
	}

	rootCert, signer, err := ca.LoadRootSigner(certPEM, keyPEM, ref, s)
	if err != nil {
		return fmt.Errorf("ca sign-issuer: %w", err)
	}
	csrPEM, err := os.ReadFile(*csrPath)
	if err != nil {
		return fmt.Errorf("ca sign-issuer: reading the signing request: %w", err)
	}
	var nets []*net.IPNet
	for _, cidr := range splitList(*ipRanges) {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("ca sign-issuer: -ip-ranges %q: %w", cidr, err)
		}
		nets = append(nets, n)
	}

	issuerPEM, err := ca.SignIssuer(rootCert, signer, csrPEM, splitList(*domains), nets, *ttl, time.Now())
	if err != nil {
		return fmt.Errorf("ca sign-issuer: %w", err)
	}
	if err := os.WriteFile(*out, issuerPEM, 0o644); err != nil {
		return err
	}
	// Keep a copy beside the root. The bundle ceremony runs here, offline, and
	// needs every issuer it has ever certified; hunting them back down from the
	// nodes afterwards would be the wrong direction of travel.
	if err := recordIssuerCopy(*rootDir, issuerPEM, *trustDomain); err != nil {
		return fmt.Errorf("ca sign-issuer: recording the issuer copy: %w", err)
	}

	fmt.Printf("issuer certificate written to %s\n", *out)
	fmt.Printf("  delegated namespace: %v\n", splitList(*domains))
	fmt.Printf("  valid for:           %s\n", *ttl)
	fmt.Println("\nBring this back to the node with `signet ca install`, along with root.crt.")
	return nil
}

func caInstall(args []string) error {
	fs := flag.NewFlagSet("ca install", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "data directory of this node")
	sealKey := fs.String("seal", "", "seal (default DATA-DIR/seal.key)")
	certPath := fs.String("cert", "", "the signed issuer certificate")
	rootPath := fs.String("root-cert", "", "the root certificate this issuer chains to")
	actorPath := fs.String("actor", "/people/root", "principal performing the ceremony")
	nodeID := fs.String("node-id", "signet-0", "name this issuer is installed under; `signet serve -node-id` must match")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dataDir == "" || *certPath == "" || *rootPath == "" {
		return errors.New("ca install: -data-dir, -cert and -root-cert are all required")
	}

	pendingPath := filepath.Join(*dataDir, "issuer-pending.json")
	blob, err := os.ReadFile(pendingPath)
	if err != nil {
		return fmt.Errorf(
			"ca install: reading %s: %w — this node has no pending issuer request. Run "+
				"`signet ca request` here first; the key it generates never leaves this node, so a "+
				"certificate signed for a request made elsewhere cannot be used", pendingPath, err)
	}
	req := &ca.IssuerRequest{}
	if err := jsonUnmarshal(blob, req); err != nil {
		return fmt.Errorf("ca install: reading the pending request: %w", err)
	}
	issuerPEM, err := os.ReadFile(*certPath)
	if err != nil {
		return fmt.Errorf("ca install: reading the issuer certificate: %w", err)
	}
	rootPEM, err := os.ReadFile(*rootPath)
	if err != nil {
		return fmt.Errorf("ca install: reading the root certificate: %w", err)
	}

	material, err := ca.AssembleIssuer(rootPEM, issuerPEM, req)
	if err != nil {
		return fmt.Errorf("ca install: %w", err)
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
		return fmt.Errorf("ca install: actor %s: %w", *actorPath, err)
	}
	name := kernel.IssuerName(*nodeID)
	if err := k.InstallCA(ctx, actor.ID, name, material); err != nil {
		return fmt.Errorf("ca install: %w", err)
	}
	// The key is now referenced by the stored material; the staging file is
	// no longer needed and should not linger.
	_ = os.Remove(pendingPath)

	fmt.Printf("issuer installed as %q\n", name)
	if material.IntermediateRef != nil {
		fmt.Printf("  key: %s\n", material.IntermediateRef)
	} else {
		fmt.Println("  key: sealed in this domain's store")
	}
	fmt.Println("This node now signs with its own issuer. Other nodes are unaffected.")
	return nil
}

func caIssuers(args []string) error {
	fs := flag.NewFlagSet("ca issuers", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "data directory")
	sealKey := fs.String("seal", "", "seal (default DATA-DIR/seal.key)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dataDir == "" {
		return errors.New("ca issuers: -data-dir is required")
	}
	node, k, err := openNode(*dataDir, sealURI(*dataDir, *sealKey))
	if err != nil {
		return err
	}
	defer node.Close()

	issuers, err := k.Issuers(context.Background())
	if err != nil {
		return err
	}
	if len(issuers) == 0 {
		fmt.Println("no certificate authority in this domain yet")
		return nil
	}
	fmt.Printf("%-28s %-12s %s\n", "AUTHORITY", "CUSTODY", "KEY")
	for name, m := range issuers {
		custody, where := "sealed", "in this domain's store"
		if m.IntermediateRef != nil {
			custody, where = "hardware", m.IntermediateRef.String()
		}
		fmt.Printf("%-28s %-12s %s\n", name, custody, where)
	}
	return nil
}

// recordIssuerCopy files a signed issuer under the root directory, named by its
// public key so re-signing the same key replaces the entry instead of
// accumulating stale duplicates in every future bundle.
func recordIssuerCopy(rootDir string, issuerPEM []byte, trustDomain string) error {
	cert, err := parseCertPEM(issuerPEM)
	if err != nil {
		return err
	}
	dir := filepath.Join(rootDir, "issuers")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fp := strings.TrimPrefix(trust.Fingerprint(cert), "sha256:")
	if err := os.WriteFile(filepath.Join(dir, fp+".crt"), issuerPEM, 0o644); err != nil {
		return err
	}
	// Record which trust domain this issuer serves, when it is not simply the
	// DNS namespace delegated to it. A trust domain is an identity namespace
	// and a name constraint bounds certificate SANs; they often coincide but
	// are not the same thing, and `ca bundle` must not have to guess which
	// issuers belong in a given domain's bundle.
	if trustDomain != "" {
		return os.WriteFile(filepath.Join(dir, fp+".domain"), []byte(trustDomain+"\n"), 0o644)
	}
	return nil
}
