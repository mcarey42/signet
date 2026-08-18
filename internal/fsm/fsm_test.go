package fsm_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/mcarey42/signet/internal/fsm"
	"github.com/mcarey42/signet/internal/kernel"
	"github.com/mcarey42/signet/internal/seal"
	"github.com/mcarey42/signet/internal/store"
)

// openNode brings up a domain over a fixed directory, so a test can close it
// and open it again the way a restart does.
func openNode(t *testing.T, dir, keyPath string) (*fsm.Node, *kernel.Kernel) {
	t.Helper()
	node, err := fsm.Open(fsm.Config{DataDir: filepath.Join(dir, "data"), Seal: "file://" + keyPath})
	if err != nil {
		t.Fatalf("open node: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := node.WaitForLeader(ctx); err != nil {
		node.Close()
		t.Fatalf("wait for leader: %v", err)
	}
	return node, kernel.New(node.Store(), node, node.Seal())
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
	if err := seal.GenerateKeyFile(keyPath); err != nil {
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
		sec, err := k.GetSecret(ctx, s, "/secrets/app", 0)
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
	if err := seal.GenerateKeyFile(keyPath); err != nil {
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
	if _, err := k.GetSecret(ctx, esoSess, "/secrets/cluster-svc/apps/litellm", 0); err != nil {
		t.Errorf("in-scope read failed after restart: %v", err)
	}
	if _, err := k.GetSecret(ctx, esoSess, "/secrets/other/thing", 0); err == nil {
		t.Error("out-of-scope read succeeded after restart")
	}
}

// A node that cannot read its applied-index watermark must refuse to start.
//
// The watermark is silently the barrier's nonce-uniqueness guarantee: nonces
// are derived from the log position, so replaying the log re-uses every nonce
// against different plaintext. AES-GCM nonce reuse leaks the XOR of the
// plaintexts and the authentication key with it. Swallowing this error turned
// one corrupted byte into plaintext recovery and forgery, so it now fails
// closed — refusing to serve is recoverable, a reused keystream is not.
func TestFSMRefusesToStartWithoutItsWatermark(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	path := filepath.Join(dir, "state.db")

	s, err := store.Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Update(1, 5, func(tx *store.Tx) error { return tx.SetAppliedIndex(5) }); err != nil {
		t.Fatal(err)
	}
	if _, err := fsm.New(s); err != nil {
		t.Fatalf("a healthy store should start: %v", err)
	}
	s.Close()

	// Reopen under a DIFFERENT root key: the stored watermark no longer
	// decrypts, which is the same observable condition as a corrupted byte.
	other := make([]byte, 32)
	for i := range other {
		other[i] = byte(i + 99)
	}
	s2, err := store.Open(path, other)
	if err != nil {
		// Failing here is also acceptable — and better. Either way the node
		// does not come up able to replay.
		return
	}
	defer s2.Close()
	if _, err := fsm.New(s2); err == nil {
		t.Fatal("the FSM started despite being unable to read its watermark; it would replay the log and reuse nonces")
	}
}
