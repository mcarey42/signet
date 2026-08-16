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
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mcarey/signet/internal/dialect/vaultkv"
	"github.com/mcarey/signet/internal/fsm"
	"github.com/mcarey/signet/internal/kernel"
	"github.com/mcarey/signet/internal/op"
	"github.com/mcarey/signet/internal/store"
)

const usage = `signet — unified identity, PKI, RBAC, and secrets (MVP)

  signet genesis  -data-dir DIR [-config FILE]   initialize a domain, print a root token
  signet serve    -data-dir DIR [-listen ADDR]   serve the Vault-compatible API
  signet token    -data-dir DIR -principal PATH  mint a token (server must be stopped)
  signet kv get   -addr URL -token T PATH        read a secret over the API
  signet kv put   -addr URL -token T PATH k=v    write a secret over the API
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
}

func cmdGenesis(args []string) error {
	fs := flag.NewFlagSet("genesis", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "data directory (local disk; never NFS)")
	sealKey := fs.String("seal-key", "", "seal key file (default DATA-DIR/seal.key; created if absent)")
	cfgPath := fs.String("config", "", "declarative config to load (JSON)")
	rootPath := fs.String("root-path", "/people/root", "path of the bootstrap admin principal")
	ttl := fs.Duration("ttl", 12*time.Hour, "root token lifetime")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dataDir == "" {
		return errors.New("genesis: -data-dir is required")
	}
	keyPath := sealKeyPath(*dataDir, *sealKey)

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(keyPath); errors.Is(err, os.ErrNotExist) {
		if err := store.GenerateKeyFile(keyPath); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "genesis: wrote seal key %s — back this up; without it the store is unreadable\n", keyPath)
	}

	node, k, err := openNode(*dataDir, keyPath)
	if err != nil {
		return err
	}
	defer node.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// The bootstrap admin is the one binding in a domain's life with no
	// grantor: there is nobody yet who could be one. Apply permits it exactly
	// once, while the domain holds no bindings at all.
	rootID, err := k.PutPrincipal(ctx, "", "", *rootPath, "human")
	if err != nil {
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

	token, _, err := k.CreateSession(ctx, rootID, rootID, *ttl, []string{"genesis"}, "bootstrap")
	if err != nil {
		return err
	}
	fmt.Printf("domain initialized\n  root principal: %s (%s)\n  root token: %s\n  expires: %s\n",
		*rootPath, rootID, token, time.Now().Add(*ttl).Format(time.RFC3339))
	return nil
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
	return nil
}

// --- serve ----------------------------------------------------------------

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "data directory")
	sealKey := fs.String("seal-key", "", "seal key file (default DATA-DIR/seal.key)")
	listen := fs.String("listen", "127.0.0.1:8200", "listen address")
	mount := fs.String("mount", "secrets", "KV mount name clients address")
	prefix := fs.String("tree-prefix", "/secrets", "where that mount lands in the resource tree")
	tlsCert := fs.String("tls-cert", "", "TLS certificate (serves plain HTTP if unset)")
	tlsKey := fs.String("tls-key", "", "TLS private key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dataDir == "" {
		return errors.New("serve: -data-dir is required")
	}

	node, k, err := openNode(*dataDir, sealKeyPath(*dataDir, *sealKey))
	if err != nil {
		return err
	}
	defer node.Close()

	h := vaultkv.New(k, vaultkv.Config{
		Mount:      *mount,
		TreePrefix: *prefix,
		Status: func() vaultkv.Status {
			s := node.Status()
			return vaultkv.Status{Initialized: s.Initialized, Sealed: s.Sealed, Leader: s.Leader}
		},
	})
	srv := &http.Server{
		Addr:              *listen,
		Handler:           h.Routes(),
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
	sealKey := fs.String("seal-key", "", "seal key file (default DATA-DIR/seal.key)")
	principal := fs.String("principal", "", "principal path to mint a token for")
	ttl := fs.Duration("ttl", time.Hour, "token lifetime")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dataDir == "" || *principal == "" {
		return errors.New("token: -data-dir and -principal are required")
	}
	node, k, err := openNode(*dataDir, sealKeyPath(*dataDir, *sealKey))
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

func openNode(dataDir, sealKey string) (*fsm.Node, *kernel.Kernel, error) {
	node, err := fsm.Open(fsm.Config{DataDir: dataDir, SealKey: sealKey})
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := node.WaitForLeader(ctx); err != nil {
		node.Close()
		return nil, nil, err
	}
	return node, kernel.New(node.Store(), node), nil
}

func sealKeyPath(dataDir, override string) string {
	if override != "" {
		return override
	}
	return dataDir + "/seal.key"
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
