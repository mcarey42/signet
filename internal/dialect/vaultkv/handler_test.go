package vaultkv_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mcarey/signet/internal/dialect/vaultkv"
	"github.com/mcarey/signet/internal/fsm"
	"github.com/mcarey/signet/internal/kernel"
	"github.com/mcarey/signet/internal/store"
)

const testMount = "secrets-home-solcore-dot-net"

// These tests run the real handlers against a real in-process single-node
// kernel — the same path a client takes — because the failures they guard
// against (a JSON string where a client asserts a number) only exist in the
// serialized bytes.
func newServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "seal.key")
	if err := store.GenerateKeyFile(keyPath); err != nil {
		t.Fatal(err)
	}
	node, err := fsm.Open(fsm.Config{DataDir: filepath.Join(dir, "data"), SealKey: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { node.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := node.WaitForLeader(ctx); err != nil {
		t.Fatal(err)
	}

	k := kernel.New(node.Store(), node)
	rootID, err := k.PutPrincipal(ctx, "", "", "/people/root", "human")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.PutBinding(ctx, "", rootID, "domain-admin", "/", 0); err != nil {
		t.Fatal(err)
	}
	token, sess, err := k.CreateSession(ctx, rootID, rootID, time.Hour, []string{"test"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.PutSecret(ctx, sess, "/secrets/cluster-svc/apps/litellm",
		map[string]string{"master-key": "sk-test", "runpod-api-key": "rp-test"}, nil); err != nil {
		t.Fatal(err)
	}

	h := vaultkv.New(k, vaultkv.Config{
		Mount:      testMount,
		TreePrefix: "/secrets",
		Status: func() vaultkv.Status {
			s := node.Status()
			return vaultkv.Status{Initialized: s.Initialized, Sealed: s.Sealed, Leader: s.Leader}
		},
	})
	srv := httptest.NewServer(h.Routes())
	t.Cleanup(srv.Close)
	return srv, token
}

func do(t *testing.T, srv *httptest.Server, method, path, token string, body []byte) (int, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, srv.URL+path, r)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	req.Header.Set("X-Vault-Request", "true") // sent unconditionally by every client
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func TestReadSecret(t *testing.T) {
	srv, token := newServer(t)
	code, body := do(t, srv, "GET", "/v1/"+testMount+"/data/cluster-svc/apps/litellm", token, nil)
	if code != 200 {
		t.Fatalf("status %d: %s", code, body)
	}
	var out struct {
		Data struct {
			Data     map[string]string `json:"data"`
			Metadata map[string]any    `json:"metadata"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	// ESO reads exactly this: data.data, then indexes by `property`.
	if out.Data.Data["master-key"] != "sk-test" {
		t.Errorf("data.data = %v", out.Data.Data)
	}
	if _, ok := out.Data.Metadata["version"]; !ok {
		t.Error("data.metadata.version missing")
	}
}

// A missing secret must be 404 with an EMPTY errors array. That exact shape is
// what the Vault Go client maps to "no secret, no error", which is what drives
// ESO's absent-secret handling.
func TestMissingSecretIs404WithEmptyErrors(t *testing.T) {
	srv, token := newServer(t)
	code, body := do(t, srv, "GET", "/v1/"+testMount+"/data/nope/missing", token, nil)
	if code != 404 {
		t.Fatalf("status = %d, want 404: %s", code, body)
	}
	if !strings.Contains(strings.ReplaceAll(string(body), " ", ""), `"errors":[]`) {
		t.Errorf("body = %s, want an empty errors array", body)
	}
}

// ESO asserts data.ttl is a json.Number without checking; a string panics the
// provider. expire_time must always be present (null means non-expiring).
func TestLookupSelfBugCompatibility(t *testing.T) {
	srv, token := newServer(t)
	code, body := do(t, srv, "GET", "/v1/auth/token/lookup-self", token, nil)
	if code != 200 {
		t.Fatalf("status %d: %s", code, body)
	}

	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber() // the Go client decodes this way, so the test must too
	var out map[string]any
	if err := dec.Decode(&out); err != nil {
		t.Fatal(err)
	}
	data, ok := out["data"].(map[string]any)
	if !ok {
		t.Fatalf("no data object: %s", body)
	}
	if _, isNumber := data["ttl"].(json.Number); !isNumber {
		t.Errorf("data.ttl is %T, must be a JSON number (ESO type-asserts json.Number)", data["ttl"])
	}
	if _, present := data["expire_time"]; !present {
		t.Error("data.expire_time key absent; it must always be present, null when non-expiring")
	}
	if data["type"] != "service" {
		t.Errorf("data.type = %v, want \"service\" (ESO refuses to reuse batch tokens)", data["type"])
	}
}

// The bao CLI runs this preflight on every kv command — even with -mount= —
// and type-asserts options.version to a string without checking.
func TestMountPreflightVersionIsAString(t *testing.T) {
	srv, token := newServer(t)
	code, body := do(t, srv, "GET", "/v1/sys/internal/ui/mounts/"+testMount+"/cluster-svc/apps/litellm", token, nil)
	if code != 200 {
		t.Fatalf("status %d: %s", code, body)
	}
	var out struct {
		Data struct {
			Path    string `json:"path"`
			Type    string `json:"type"`
			Options struct {
				Version any `json:"version"`
			} `json:"options"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if _, isString := out.Data.Options.Version.(string); !isString {
		t.Errorf("options.version is %T, must be the string \"2\" (the CLI panics otherwise)", out.Data.Options.Version)
	}
	if out.Data.Path != testMount+"/" {
		t.Errorf("data.path = %q, want %q", out.Data.Path, testMount+"/")
	}
}

// cert-manager branches on the status code; this homelab's monitoring asserts
// on the body's booleans. Both are contractual.
func TestHealth(t *testing.T) {
	srv, _ := newServer(t)
	code, body := do(t, srv, "GET", "/v1/sys/health", "", nil)
	if code != 200 {
		t.Fatalf("status = %d, want 200", code)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"initialized", "sealed", "standby"} {
		if _, isBool := out[k].(bool); !isBool {
			t.Errorf("%s is %T, must be a JSON boolean", k, out[k])
		}
	}
	if out["initialized"] != true || out["sealed"] != false {
		t.Errorf("health = %v, want initialized=true sealed=false", out)
	}
}

func TestWriteThenRead(t *testing.T) {
	srv, token := newServer(t)
	payload, _ := json.Marshal(map[string]any{"data": map[string]string{"password": "hunter2"}})
	if code, body := do(t, srv, "PUT", "/v1/"+testMount+"/data/apps/newthing", token, payload); code != 200 {
		t.Fatalf("write status %d: %s", code, body)
	}
	code, body := do(t, srv, "GET", "/v1/"+testMount+"/data/apps/newthing", token, nil)
	if code != 200 {
		t.Fatalf("read status %d: %s", code, body)
	}
	if !strings.Contains(string(body), "hunter2") {
		t.Errorf("value did not round trip: %s", body)
	}
}

func TestAuthFailures(t *testing.T) {
	srv, token := newServer(t)

	if code, _ := do(t, srv, "GET", "/v1/"+testMount+"/data/cluster-svc/apps/litellm", "", nil); code != 403 {
		t.Errorf("no token: status = %d, want 403", code)
	}
	if code, _ := do(t, srv, "GET", "/v1/"+testMount+"/data/cluster-svc/apps/litellm", "signet.bogus", nil); code != 403 {
		t.Errorf("bad token: status = %d, want 403", code)
	}
	// A mount this server does not serve is a routing miss, not a permission
	// problem — clients branch differently on the two.
	if code, _ := do(t, srv, "GET", "/v1/other-mount/data/x", token, nil); code != 404 {
		t.Errorf("wrong mount: status = %d, want 404", code)
	}
}
