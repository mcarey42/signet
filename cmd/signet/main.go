// Command signet is the single Signet binary: it initializes a domain, serves
// it, and provides the minimum client surface to exercise it.
//
// The MVP ships one domain member, one dialect, and no membership machinery.
// Everything deferred (OIDC, SSH, agents, federation, GitOps) arrives with the
// milestone that needs it — see docs/15.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mcarey42/signet/internal/ca"
	"github.com/mcarey42/signet/internal/dialect/oidc"
	"github.com/mcarey42/signet/internal/dialect/sshca"
	"github.com/mcarey42/signet/internal/dialect/vaultkv"
	"github.com/mcarey42/signet/internal/fsm"
	"github.com/mcarey42/signet/internal/kernel"
	"github.com/mcarey42/signet/internal/keys"
	"github.com/mcarey42/signet/internal/op"
	"github.com/mcarey42/signet/internal/seal"
)

const usage = `signet — unified identity, PKI, RBAC, and secrets (MVP)

  signet genesis  -data-dir DIR [-config FILE]   initialize a domain, print a root token
  signet serve    -data-dir DIR [-listen ADDR]   serve the Vault-compatible API
  signet token    -data-dir DIR -principal PATH  mint a token (server must be stopped)
  signet kv get   -addr URL -token T PATH        read a secret over the API
  signet kv put   -addr URL -token T PATH k=v    write a secret over the API
  signet seal status -data-dir DIR               show which seal holds the keys
  signet seal rotate -data-dir DIR -to URI       move key custody to another seal
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "genesis":
		err = cmdGenesis(os.Args[2:])
	case "serve":
		err = cmdServe(os.Args[2:])
	case "token":
		err = cmdToken(os.Args[2:])
	case "kv":
		err = cmdKV(os.Args[2:])
	case "seal":
		err = cmdSeal(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "signet:", err)
		os.Exit(1)
	}
}

// --- genesis --------------------------------------------------------------

// GenesisConfig is the declarative slice of desired state genesis can load.
// Runtime state — sessions, tokens, activations — is deliberately absent: you
// declare who may hold authority, you do not declare live credentials
// (docs/14).
type GenesisConfig struct {
	Principals []struct {
		Path string `json:"path"`
		Type string `json:"type"`
	} `json:"principals"`
	Bindings []struct {
		Subject string `json:"subject"` // principal path
		Role    string `json:"role"`
		Scope   string `json:"scope"`
	} `json:"bindings"`
	// Issuers are pinned attestation trust anchors. The key set is referenced
	// by file rather than inlined so it can be mounted separately and rotated
	// without rewriting policy.
	Issuers []struct {
		Name     string `json:"name"`
		Verifier string `json:"verifier"`
		URL      string `json:"url"`
		Audience string `json:"audience"`
		JWKSFile string `json:"jwks_file"`
	} `json:"issuers"`
	Mappings []struct {
		Name            string   `json:"name"`
		Issuer          string   `json:"issuer"`
		Namespaces      []string `json:"namespaces"`
		ServiceAccounts []string `json:"service_accounts"`
		Principal       string   `json:"principal"` // principal path
		TTLSeconds      int64    `json:"ttl_seconds"`
	} `json:"mappings"`
	PKIRoles []struct {
		Name             string   `json:"name"`
		Scope            string   `json:"scope"`
		AllowedDomains   []string `json:"allowed_domains"`
		AllowSubdomains  bool     `json:"allow_subdomains"`
		AllowBareDomains bool     `json:"allow_bare_domains"`
		AllowIPSANs      bool     `json:"allow_ip_sans"`
		MaxTTLSeconds    int64    `json:"max_ttl_seconds"`
	} `json:"pki_roles"`
	SSHRoles []struct {
		Name                string              `json:"name"`
		Scope               string              `json:"scope"`
		AllowedPrincipals   []string            `json:"allowed_principals"`
		PrincipalsFromRoles map[string][]string `json:"principals_from_roles"`
		MaxTTLSec           int64               `json:"max_ttl_sec"`
		AllowPTY            bool                `json:"allow_pty"`
	} `json:"ssh_roles"`
	// RolePolicies carry each role's security floor — the freshness tier and
	// any requirement on how strongly the session was established.
	RolePolicies []struct {
		Role        string `json:"role"`
		MinTier     int    `json:"min_tier"`
		RequiredAMR string `json:"required_amr"`
		MaxTTLSec   int64  `json:"max_ttl_sec"`
		OwnerScope  string `json:"owner_scope"`
	} `json:"role_policies"`
}

func cmdGenesis(args []string) error {
	fs := flag.NewFlagSet("genesis", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "data directory (local disk; never NFS)")
	sealKey := fs.String("seal", "", "seal: a key file path, or pkcs11:?module=...&token=...&pin=...&label=... for an HSM (default DATA-DIR/seal.key)")
	cfgPath := fs.String("config", "", "declarative config to load (JSON)")
	rootPath := fs.String("root-path", "/people/root", "path of the bootstrap admin principal")
	ttl := fs.Duration("ttl", 12*time.Hour, "root token lifetime")
	mint := fs.String("mint", "", "comma-separated principal paths to also mint tokens for")
	caCN := fs.String("ca-common-name", "", "create a certificate authority with this name (skipped if empty)")
	caDomains := fs.String("ca-domains", "", "comma-separated DNS domains the CA may issue for")
	caIPRanges := fs.String("ca-ip-ranges", "", "comma-separated CIDRs the CA may issue IP SANs for (default: none, and IP SANs are excluded outright)")
	rootKeyOut := fs.String("root-key-out", "", "where to write the root private key (default DATA-DIR/../root-ca.key)")
	serveCertOut := fs.String("server-cert-out", "", "directory to write this server's own TLS material (tls.crt, tls.key, ca.crt)")
	serverNames := fs.String("server-names", "", "comma-separated DNS names and IPs for that certificate")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dataDir == "" {
		return errors.New("genesis: -data-dir is required")
	}
	sealCfg := sealURI(*dataDir, *sealKey)

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		return err
	}
	// Only a file seal has a key to create. A hardware seal's key already
	// exists inside the device and Signet could not create it if it wanted to —
	// which is the point.
	if path, ok := strings.CutPrefix(sealCfg, "file://"); ok {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			if err := seal.GenerateKeyFile(path); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "genesis: wrote seal key %s — back this up; without it the store is unreadable\n", path)
		}
	}

	node, k, err := openNode(*dataDir, sealCfg)
	if err != nil {
		return err
	}
	defer node.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// The bootstrap admin is the one binding in a domain's life with no
	// grantor: there is nobody yet who could be one. Apply permits it exactly
	// once, while the domain holds no bindings at all.
	//
	// Re-running genesis over an initialized domain is not an error — it mints
	// fresh tokens against the existing root. That keeps genesis usable as a
	// container init step, which re-runs whenever a pod is rescheduled.
	var rootID op.ID
	if existing, err := k.PrincipalByPath(ctx, *rootPath); err == nil {
		rootID = existing.ID
		fmt.Fprintf(os.Stderr, "genesis: domain already initialized (root %s)\n", rootID)
	} else {
		if rootID, err = k.PutPrincipal(ctx, "", "", *rootPath, "human"); err != nil {
			return fmt.Errorf("genesis: create root principal: %w", err)
		}
		if _, err := k.PutBinding(ctx, "", rootID, "domain-admin", "/", 0); err != nil {
			return fmt.Errorf("genesis: bootstrap binding: %w", err)
		}
		if *cfgPath != "" {
			if err := loadConfig(ctx, k, rootID, *cfgPath); err != nil {
				return err
			}
		}
	}

	if *caCN != "" {
		if err := genesisCA(ctx, k, rootID, *caCN, *caDomains, *caIPRanges, caKeyPath(*dataDir, *rootKeyOut)); err != nil {
			return err
		}
	}
	// Signing keys for the offline dialects. Separate per purpose so one stolen
	// key is not all of them, and generated here so a domain can mint
	// credentials the moment it exists.
	for _, purpose := range []keys.Purpose{keys.PurposeToken, keys.PurposeSSH} {
		if _, err := k.ActiveKey(ctx, purpose); err == nil {
			continue // already present; rotation is a separate, deliberate act
		}
		key, err := keys.Generate(purpose, time.Now().Unix())
		if err != nil {
			return fmt.Errorf("genesis: %s key: %w", purpose, err)
		}
		if err := k.InstallKey(ctx, rootID, key, true); err != nil {
			return fmt.Errorf("genesis: install %s key: %w", purpose, err)
		}
		fmt.Fprintf(os.Stderr, "  %s signing key %s\n", purpose, key.ID)
	}

	if *serveCertOut != "" {
		if err := genesisServerCert(ctx, k, rootID, *serveCertOut, splitList(*serverNames)); err != nil {
			return err
		}
	}

	token, _, err := k.CreateSession(ctx, rootID, rootID, *ttl, []string{"genesis"}, "bootstrap")
	if err != nil {
		return err
	}
	fmt.Printf("domain initialized\n  root principal: %s (%s)\n  root token: %s\n  expires: %s\n",
		*rootPath, rootID, token, time.Now().Add(*ttl).Format(time.RFC3339))

	// Bootstrap tokens for declared principals. Tokens are runtime state and
	// never belong in declarative config, but genesis is the one moment a
	// domain has no other way to hand out its first credentials — the same
	// reason it emits a root token at all.
	for _, path := range strings.Split(*mint, ",") {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		p, err := k.PrincipalByPath(ctx, path)
		if err != nil {
			return fmt.Errorf("genesis: mint %s: %w", path, err)
		}
		t, _, err := k.CreateSession(ctx, rootID, p.ID, *ttl, []string{"genesis"}, "bootstrap")
		if err != nil {
			return err
		}
		fmt.Printf("  token %s: %s\n", path, t)
	}
	return nil
}

// genesisCA runs the root ceremony.
//
// The root private key is generated here, signs exactly one intermediate, and
// is written to a file outside the data directory — never proposed, never
// stored. Everything written to the FSM lands in the Raft log and in every
// backup generation built from it, so a root key that touched state would make
// "the root is offline" false forever after (docs/14, E-13 F6).
func genesisCA(ctx context.Context, k *kernel.Kernel, actor op.ID, commonName, domains, ipRanges, rootKeyPath string) error {
	// Idempotent like the rest of genesis: a domain that already has an
	// authority keeps it. Minting a second root would orphan every certificate
	// issued under the first.
	if _, _, err := k.CAChain(ctx, "default"); err == nil {
		fmt.Fprintln(os.Stderr, "  CA already present, leaving it alone")
		return nil
	}
	if _, err := os.Stat(rootKeyPath); err == nil {
		return fmt.Errorf("genesis: %s already exists; refusing to overwrite a root key", rootKeyPath)
	}
	if dir := filepath.Dir(rootKeyPath); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("genesis: root key directory: %w", err)
		}
	}
	permitted := splitList(domains)
	var nets []*net.IPNet
	for _, cidr := range splitList(ipRanges) {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("genesis: -ca-ip-ranges %q: %w", cidr, err)
		}
		nets = append(nets, n)
	}
	res, err := kernel.GenesisCA(commonName, permitted, nets, 10*365*24*time.Hour, 365*24*time.Hour)
	if err != nil {
		return err
	}
	// Write the root key before installing the CA: if this fails, no authority
	// exists whose root nobody holds.
	if err := os.WriteFile(rootKeyPath, res.RootKeyPEM, 0o400); err != nil {
		return fmt.Errorf("genesis: write root key: %w", err)
	}
	if err := k.InstallCA(ctx, actor, "default", res.Material); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "  CA %q created for %v\n", commonName, permitted)
	fmt.Fprintf(os.Stderr, "  ROOT KEY WRITTEN TO %s — move it offline and delete this copy.\n", rootKeyPath)
	fmt.Fprintf(os.Stderr, "  It is not in the store, the log, or any backup; this file is the only copy.\n")
	return nil
}

// genesisServerCert issues the certificate Signet itself serves with, from the
// authority it just created.
//
// This resolves a real chicken-and-egg: a Kubernetes API server will only fetch
// OIDC discovery over HTTPS, and the CA that could issue that certificate is
// the one being created here. Doing it in the ceremony means a domain comes up
// able to serve TLS with its own trust chain and nothing borrowed.
func genesisServerCert(ctx context.Context, k *kernel.Kernel, actor op.ID, dir string, names []string) error {
	if len(names) == 0 {
		return errors.New("genesis: -server-cert-out needs -server-names")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	var dns []string
	var ips []net.IP
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			ips = append(ips, ip)
			continue
		}
		dns = append(dns, n)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: names[0]}, DNSNames: dns, IPAddresses: ips,
	}, key)
	if err != nil {
		return err
	}
	// The server's certificate is issued through the same path as everyone
	// else's — role checks, verification gate, issuance log — using a
	// self-scoped role created for the purpose.
	if err := k.PutPKIRole(ctx, actor, ca.Role{
		Name: "signet-server", Scope: "/pki/server",
		AllowedDomains: dns, AllowSubdomains: true, AllowBareDomains: true,
		AllowIPSANs: len(ips) > 0, MaxTTLSeconds: int64((365 * 24 * time.Hour).Seconds()),
	}); err != nil {
		return err
	}
	_, sess, err := k.CreateSession(ctx, actor, actor, time.Minute, []string{"genesis"}, "bootstrap")
	if err != nil {
		return err
	}
	issued, err := k.SignCertificate(ctx, sess, "default", "signet-server", ca.Request{
		CSRPEM:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
		CommonName: names[0], DNSNames: dns, TTL: 365 * 24 * time.Hour,
	})
	if err != nil {
		return fmt.Errorf("genesis: server certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	root, chain, err := k.CAChain(ctx, "default")
	if err != nil {
		return err
	}
	for name, content := range map[string][]byte{
		"tls.crt":   append(append([]byte{}, issued.CertPEM...), issued.IssuingCAPEM...),
		"tls.key":   pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		"ca.crt":    root,
		"chain.pem": chain,
	} {
		mode := os.FileMode(0o644)
		if name == "tls.key" {
			mode = 0o600
		}
		if err := os.WriteFile(filepath.Join(dir, name), content, mode); err != nil {
			return err
		}
	}
	fmt.Fprintf(os.Stderr, "  server certificate for %v written to %s\n", names, dir)
	return nil
}

func caKeyPath(dataDir, override string) string {
	if override != "" {
		return override
	}
	// Deliberately beside the data directory, not inside it: the data directory
	// is what gets backed up.
	return filepath.Join(filepath.Dir(strings.TrimSuffix(dataDir, "/")), "root-ca.key")
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func loadConfig(ctx context.Context, k *kernel.Kernel, actor op.ID, path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cfg GenesisConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	for _, p := range cfg.Principals {
		if _, err := k.PutPrincipal(ctx, actor, "", p.Path, p.Type); err != nil {
			return fmt.Errorf("config: principal %s: %w", p.Path, err)
		}
		fmt.Fprintf(os.Stderr, "  principal %s\n", p.Path)
	}
	for _, b := range cfg.Bindings {
		subj, err := k.PrincipalByPath(ctx, b.Subject)
		if err != nil {
			return fmt.Errorf("config: binding subject %s: %w", b.Subject, err)
		}
		if _, err := k.PutBinding(ctx, actor, subj.ID, b.Role, b.Scope, 0); err != nil {
			return fmt.Errorf("config: binding %s@%s: %w", b.Role, b.Scope, err)
		}
		fmt.Fprintf(os.Stderr, "  binding %s -> %s at %s\n", b.Subject, b.Role, b.Scope)
	}
	for _, i := range cfg.Issuers {
		jwks, err := os.ReadFile(i.JWKSFile)
		if err != nil {
			return fmt.Errorf("config: issuer %s: %w", i.Name, err)
		}
		if _, err := k.PutIssuer(ctx, actor, i.Name, i.Verifier, i.URL, i.Audience, jwks); err != nil {
			return fmt.Errorf("config: issuer %s: %w", i.Name, err)
		}
		fmt.Fprintf(os.Stderr, "  issuer %s (%s, audience %q)\n", i.Name, i.URL, i.Audience)
	}
	for _, m := range cfg.Mappings {
		p, err := k.PrincipalByPath(ctx, m.Principal)
		if err != nil {
			return fmt.Errorf("config: mapping %s: principal %s: %w", m.Name, m.Principal, err)
		}
		if _, err := k.PutMapping(ctx, actor, kernel.Mapping{
			Name: m.Name, Issuer: m.Issuer, Namespaces: m.Namespaces,
			ServiceAccounts: m.ServiceAccounts, Principal: p.ID, TTLSeconds: m.TTLSeconds,
		}); err != nil {
			return fmt.Errorf("config: mapping %s: %w", m.Name, err)
		}
		fmt.Fprintf(os.Stderr, "  mapping %s: %v/%v -> %s\n", m.Name, m.Namespaces, m.ServiceAccounts, m.Principal)
	}
	for _, r := range cfg.PKIRoles {
		if err := k.PutPKIRole(ctx, actor, ca.Role{
			Name: r.Name, Scope: r.Scope, AllowedDomains: r.AllowedDomains,
			AllowSubdomains: r.AllowSubdomains, AllowBareDomains: r.AllowBareDomains,
			AllowIPSANs: r.AllowIPSANs, MaxTTLSeconds: r.MaxTTLSeconds,
		}); err != nil {
			return fmt.Errorf("config: pki role %s: %w", r.Name, err)
		}
		fmt.Fprintf(os.Stderr, "  pki role %s for %v at %s\n", r.Name, r.AllowedDomains, r.Scope)
	}
	for _, r := range cfg.SSHRoles {
		if err := k.PutSSHRole(ctx, actor, r.Name, kernel.SSHRoleSpec{
			Name: r.Name, Scope: r.Scope, AllowedPrincipals: r.AllowedPrincipals,
			PrincipalsFromRoles: r.PrincipalsFromRoles, MaxTTLSec: r.MaxTTLSec,
			AllowPTY: r.AllowPTY,
		}); err != nil {
			return fmt.Errorf("config: ssh role %s: %w", r.Name, err)
		}
		fmt.Fprintf(os.Stderr, "  ssh role %s at %s\n", r.Name, r.Scope)
	}
	for _, p := range cfg.RolePolicies {
		if err := k.PutRolePolicy(ctx, actor, kernel.RolePolicy{
			Role: p.Role, MinTier: p.MinTier, RequiredAMR: p.RequiredAMR,
			MaxTTLSec: p.MaxTTLSec, OwnerScope: p.OwnerScope,
		}); err != nil {
			return fmt.Errorf("config: role policy %s: %w", p.Role, err)
		}
		fmt.Fprintf(os.Stderr, "  role policy %s: tier %d\n", p.Role, p.MinTier)
	}
	return nil
}

// --- serve ----------------------------------------------------------------

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "data directory")
	sealKey := fs.String("seal", "", "seal: a key file path, or a pkcs11: URI for an HSM (default DATA-DIR/seal.key)")
	listen := fs.String("listen", "127.0.0.1:8200", "listen address")
	mount := fs.String("mount", "secrets", "KV mount name clients address")
	prefix := fs.String("tree-prefix", "/secrets", "where that mount lands in the resource tree")
	pkiMount := fs.String("pki-mount", "pki", "mount name for certificate signing")
	sshMount := fs.String("ssh-mount", "ssh", "mount name for SSH certificate signing")
	issuerURL := fs.String("issuer-url", "", "externally reachable OIDC issuer URL (must match what relying parties are configured with)")
	tlsCert := fs.String("tls-cert", "", "TLS certificate (serves plain HTTP if unset)")
	tlsKey := fs.String("tls-key", "", "TLS private key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dataDir == "" {
		return errors.New("serve: -data-dir is required")
	}

	node, k, err := openNode(*dataDir, sealURI(*dataDir, *sealKey))
	if err != nil {
		return err
	}
	defer node.Close()

	h := vaultkv.New(k, vaultkv.Config{
		Mount:      *mount,
		TreePrefix: *prefix,
		PKIMount:   *pkiMount,
		CAName:     "default",
		Status: func() vaultkv.Status {
			s := node.Status()
			return vaultkv.Status{Initialized: s.Initialized, Sealed: s.Sealed, Leader: s.Leader}
		},
	})
	oidcIssuer := *issuerURL
	if oidcIssuer == "" {
		scheme := "http"
		if *tlsCert != "" {
			scheme = "https"
		}
		oidcIssuer = scheme + "://" + *listen
	}
	mux := h.Routes()
	oidc.New(k, oidc.Config{Issuer: oidcIssuer}).Register(mux)
	sshca.New(k, sshca.Config{Mount: *sshMount}).Register(mux)

	srv := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	fmt.Fprintf(os.Stderr, "signet serving on %s (mount %q -> %s)\n", *listen, *mount, *prefix)
	if *tlsCert != "" {
		return srv.ListenAndServeTLS(*tlsCert, *tlsKey)
	}
	return srv.ListenAndServe()
}

// --- token ----------------------------------------------------------------

func cmdToken(args []string) error {
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "data directory")
	sealKey := fs.String("seal", "", "seal: a key file path, or a pkcs11: URI for an HSM (default DATA-DIR/seal.key)")
	principal := fs.String("principal", "", "principal path to mint a token for")
	ttl := fs.Duration("ttl", time.Hour, "token lifetime")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dataDir == "" || *principal == "" {
		return errors.New("token: -data-dir and -principal are required")
	}
	node, k, err := openNode(*dataDir, sealURI(*dataDir, *sealKey))
	if err != nil {
		return err
	}
	defer node.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	p, err := k.PrincipalByPath(ctx, *principal)
	if err != nil {
		return fmt.Errorf("token: %s: %w", *principal, err)
	}
	token, _, err := k.CreateSession(ctx, p.ID, p.ID, *ttl, []string{"operator"}, "offline")
	if err != nil {
		return err
	}
	fmt.Println(token)
	return nil
}

// --- seal ceremonies ------------------------------------------------------

func cmdSeal(args []string) error {
	if len(args) < 1 {
		return errors.New("seal: expected status or rotate")
	}
	fs := flag.NewFlagSet("seal", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "data directory")
	sealKey := fs.String("seal", "", "current seal (default DATA-DIR/seal.key)")
	to := fs.String("to", "", "destination seal for rotate")
	actorPath := fs.String("actor", "/people/root", "principal performing the ceremony")
	yes := fs.Bool("yes", false, "proceed without the confirmation prompt")
	sub := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *dataDir == "" {
		return errors.New("seal: -data-dir is required")
	}

	switch sub {
	case "status":
		return sealStatus(*dataDir, sealURI(*dataDir, *sealKey))
	case "rotate":
		if *to == "" {
			return errors.New("seal rotate: -to is required")
		}
		return sealRotate(*dataDir, sealURI(*dataDir, *sealKey), sealURI(*dataDir, *to), *actorPath, *yes)
	}
	return fmt.Errorf("seal: unknown subcommand %q", sub)
}

func sealStatus(dataDir, sealCfg string) error {
	wrappedBy, err := seal.RootKeyWrappedBy(dataDir)
	if err != nil {
		return fmt.Errorf("seal status: %w", err)
	}
	fmt.Printf("root key wrapped by: %s\n", wrappedBy)

	node, k, err := openNode(dataDir, sealCfg)
	if err != nil {
		// Being unable to open is itself the answer: this is not the seal.
		fmt.Printf("current seal:        cannot open the domain (%v)\n", err)
		return nil
	}
	defer node.Close()
	st := node.Status()
	fmt.Printf("current seal:        %s/%s\n", st.SealName, st.SealKeyID)

	items, err := k.SealInventory(context.Background())
	if err != nil {
		return err
	}
	fmt.Printf("sealed material:     %d items\n", len(items))
	mixed := map[string]int{}
	for _, it := range items {
		by := it.SealedBy
		if by == "" {
			by = "(unsealed)"
		}
		mixed[by]++
		fmt.Printf("  %-4s %-40s %s\n", it.Kind, it.Name, by)
	}
	if len(mixed) > 1 {
		fmt.Println("\nWARNING: material is split across seals — a rotation did not finish.")
		fmt.Println("Re-run `signet seal rotate` with the same destination; it resumes.")
	}
	return nil
}

// sealRotate moves custody of every sealed item, then the root key, then proves
// the result by opening everything with the destination seal alone.
//
// Order matters. Material is rewrapped first and the root key last, because a
// crash between them leaves a domain that still opens with the *old* seal —
// recoverable by re-running. Doing it the other way would leave the store
// unreadable until the ceremony was finished by hand.
func sealRotate(dataDir, fromCfg, toCfg, actorPath string, yes bool) error {
	if fromCfg == toCfg {
		return errors.New("seal rotate: source and destination are the same seal")
	}
	from, err := seal.Open(fromCfg)
	if err != nil {
		return fmt.Errorf("seal rotate: current seal: %w", err)
	}
	defer from.Close()
	to, err := seal.Open(toCfg)
	if err != nil {
		return fmt.Errorf("seal rotate: destination seal: %w", err)
	}
	defer to.Close()

	fmt.Fprintf(os.Stderr, "rotating key custody\n  from: %s/%s\n  to:   %s/%s\n",
		from.Name(), from.KeyID(), to.Name(), to.KeyID())
	if !yes {
		fmt.Fprint(os.Stderr, "\nKeep the current seal until this reports success — an interrupted\n"+
			"ceremony needs both. Proceed? [y/N] ")
		var answer string
		fmt.Scanln(&answer)
		if answer != "y" && answer != "Y" {
			return errors.New("seal rotate: cancelled")
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	node, k, err := openNode(dataDir, fromCfg)
	if err != nil {
		return fmt.Errorf("seal rotate: open with the current seal: %w", err)
	}
	actor, err := k.PrincipalByPath(ctx, actorPath)
	if err != nil {
		node.Close()
		return fmt.Errorf("seal rotate: actor %s: %w", actorPath, err)
	}
	moved, err := k.RotateSeal(ctx, actor.ID, from, to)
	if err != nil {
		node.Close()
		return fmt.Errorf("seal rotate: %w", err)
	}
	for _, m := range moved {
		fmt.Fprintf(os.Stderr, "  rewrapped %s %s\n", m.Kind, m.Name)
	}
	if len(moved) == 0 {
		fmt.Fprintln(os.Stderr, "  (all material was already under the destination seal)")
	}
	node.Close()

	// The root key moves last: until it does, the domain still opens with the
	// old seal, so an interruption here is recoverable by re-running.
	if err := seal.RewrapRootKey(from, to, dataDir); err != nil {
		return fmt.Errorf("seal rotate: root key: %w", err)
	}
	fmt.Fprintln(os.Stderr, "  rewrapped the barrier root key")

	// Prove it. Opening under the destination seal alone is the only honest
	// check; a record that merely claims the new seal proves nothing.
	verifyNode, vk, err := openNode(dataDir, toCfg)
	if err != nil {
		return fmt.Errorf("seal rotate: the domain does not open under the destination seal: %w", err)
	}
	defer verifyNode.Close()
	if err := vk.VerifySealedMaterial(ctx, to); err != nil {
		return fmt.Errorf("seal rotate: verification failed, keep the old seal: %w", err)
	}

	fmt.Printf("\nrotation complete and verified under %s/%s\n", to.Name(), to.KeyID())
	fmt.Println("The old seal is no longer needed to run this domain.")
	fmt.Println("Destroying it also shreds any backup taken before now: those hold")
	fmt.Println("material wrapped by the old seal and nothing else can open them.")
	return nil
}

// --- kv client ------------------------------------------------------------

func cmdKV(args []string) error {
	if len(args) < 1 {
		return errors.New("kv: expected get or put")
	}
	fs := flag.NewFlagSet("kv", flag.ExitOnError)
	addr := fs.String("addr", envOr("SIGNET_ADDR", "http://127.0.0.1:8200"), "server address")
	token := fs.String("token", os.Getenv("SIGNET_TOKEN"), "bearer token")
	mount := fs.String("mount", "secrets", "KV mount name")
	sub := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) < 1 {
		return errors.New("kv: expected a secret path")
	}
	path := strings.TrimPrefix(rest[0], "/")
	url := fmt.Sprintf("%s/v1/%s/data/%s", strings.TrimSuffix(*addr, "/"), *mount, path)

	switch sub {
	case "get":
		body, err := doJSON(http.MethodGet, url, *token, nil)
		if err != nil {
			return err
		}
		var out struct {
			Data struct {
				Data map[string]string `json:"data"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return err
		}
		for k, v := range out.Data.Data {
			fmt.Printf("%s\t%s\n", k, v)
		}
		return nil
	case "put":
		data := map[string]string{}
		for _, kv := range rest[1:] {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				return fmt.Errorf("kv put: %q is not key=value", kv)
			}
			data[k] = v
		}
		payload, _ := json.Marshal(map[string]any{"data": data})
		if _, err := doJSON(http.MethodPut, url, *token, payload); err != nil {
			return err
		}
		fmt.Println("ok")
		return nil
	}
	return fmt.Errorf("kv: unknown subcommand %q", sub)
}

func doJSON(method, url, token string, body []byte) ([]byte, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("X-Vault-Request", "true")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// --- shared ---------------------------------------------------------------

func openNode(dataDir, sealURI string) (*fsm.Node, *kernel.Kernel, error) {
	node, err := fsm.Open(fsm.Config{DataDir: dataDir, Seal: sealURI})
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := node.WaitForLeader(ctx); err != nil {
		node.Close()
		return nil, nil, err
	}
	return node, kernel.New(node.Store(), node, node.Seal()), nil
}

// sealURI resolves the seal configuration. A bare path or an empty value means
// the default file seal beside the data directory; anything with a scheme is
// passed through, which is how a hardware seal is selected:
//
//	-seal 'pkcs11:?module=/usr/lib/softhsm/libsofthsm2.so&token=signet&pin=1234&label=signet-seal'
func sealURI(dataDir, override string) string {
	if override == "" {
		return "file://" + dataDir + "/seal.key"
	}
	if strings.Contains(override, "://") || strings.HasPrefix(override, "pkcs11:") {
		return override
	}
	return "file://" + override
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
