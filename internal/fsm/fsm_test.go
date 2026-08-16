package fsm_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/mcarey/signet/internal/fsm"
	"github.com/mcarey/signet/internal/kernel"
	"github.com/mcarey/signet/internal/store"
)

// openNode brings up a domain over a fixed directory, so a test can close it
// and open it again the way a restart does.
func openNode(t *testing.T, dir, keyPath string) (*fsm.Node, *kernel.Kernel) {
	t.Helper()
	node, err := fsm.Open(fsm.Config{DataDir: filepath.Join(dir, "data"), SealKey: keyPath})
	if err != nil {
		t.Fatalf("open node: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := node.WaitForLeader(ctx); err != nil {
		node.Close()
		t.Fatalf("wait for leader: %v", err)
	}
	return node, kernel.New(node.Store(), node)
}

// Restarting a node replays committed entries from the last snapshot. Because
// Signet's state is durable, replay must be a no-op for entries already
// applied — otherwise accumulating values drift on every restart.
//
// This test is the regression guard for exactly that: a secret written once
// must still be at version 1 after two restarts.
func TestRestartDoesNotReapplyEntries(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "seal.key")
	if err := store.GenerateKeyFile(keyPath); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	node, k := openNode(t, dir, keyPath)
	rootID, err := k.PutPrincipal(ctx, "", "", "/people/root", "human")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.PutBinding(ctx, "", rootID, "domain-admin", "/", 0); err != nil {
		t.Fatal(err)
	}
	token, sess, err := k.CreateSession(ctx, rootID, rootID, time.Hour, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	version, err := k.PutSecret(ctx, sess, "/secrets/app", map[string]string{"k": "v"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if version != 1 {
		t.Fatalf("first write version = %d, want 1", version)
	}
	if err := node.Close(); err != nil {
		t.Fatal(err)
	}

	for restart := 1; restart <= 2; restart++ {
		node, k = openNode(t, dir, keyPath)
		// The session survives too — it is state, not process memory.
		s, err := k.LookupSession(ctx, token)
		if err != nil {
			t.Fatalf("restart %d: session lost: %v", restart, err)
		}
		sec, err := k.GetSecret(ctx, s, "/secrets/app")
		if err != nil {
			t.Fatalf("restart %d: read: %v", restart, err)
		}
		if sec.Version != 1 {
			t.Fatalf("restart %d: version = %d, want 1 — committed entries were applied again on replay", restart, sec.Version)
		}
		if sec.Data["k"] != "v" {
			t.Fatalf("restart %d: data = %v", restart, sec.Data)
		}
		if err := node.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

// Authorization survives a restart, and a principal's scope still bounds it.
func TestScopeSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "seal.key")
	if err := store.GenerateKeyFile(keyPath); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	node, k := openNode(t, dir, keyPath)
	rootID, _ := k.PutPrincipal(ctx, "", "", "/people/root", "human")
	if _, err := k.PutBinding(ctx, "", rootID, "domain-admin", "/", 0); err != nil {
		t.Fatal(err)
	}
	esoID, err := k.PutPrincipal(ctx, rootID, "", "/clusters/svc/apps/eso", "workload")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.PutBinding(ctx, rootID, esoID, "kv-reader", "/secrets/cluster-svc", 0); err != nil {
		t.Fatal(err)
	}
	_, rootSess, _ := k.CreateSession(ctx, rootID, rootID, time.Hour, nil, "test")
	if _, err := k.PutSecret(ctx, rootSess, "/secrets/cluster-svc/apps/litellm", map[string]string{"master-key": "sk"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := k.PutSecret(ctx, rootSess, "/secrets/other/thing", map[string]string{"k": "v"}, nil); err != nil {
		t.Fatal(err)
	}
	esoToken, _, err := k.CreateSession(ctx, rootID, esoID, time.Hour, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	node.Close()

	node, k = openNode(t, dir, keyPath)
	defer node.Close()
	esoSess, err := k.LookupSession(ctx, esoToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.GetSecret(ctx, esoSess, "/secrets/cluster-svc/apps/litellm"); err != nil {
		t.Errorf("in-scope read failed after restart: %v", err)
	}
	if _, err := k.GetSecret(ctx, esoSess, "/secrets/other/thing"); err == nil {
		t.Error("out-of-scope read succeeded after restart")
	}
}
