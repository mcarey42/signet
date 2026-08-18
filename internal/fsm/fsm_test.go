package fsm_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/mcarey42/signet/internal/fsm"
	"github.com/mcarey42/signet/internal/kernel"
	"github.com/mcarey42/signet/internal/op"
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

// A write that lands at an already-applied index stored nothing, and must not
// be reported as success.
//
// Apply returned a bare op.Result{} when skipping, indistinguishable from a
// real empty result, so Propose handed the caller (empty, nil) — success. With
// raft.db lost beside a surviving state.db, a fresh log restarts at index 1 and
// a whole prefix of the write stream was swallowed: 200s all the way, nothing
// stored, and no audit record either.
func TestSkippedEntryIsNotReportedAsSuccess(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 3)
	}
	s, err := store.Open(filepath.Join(dir, "state.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Update(1, 9, func(tx *store.Tx) error { return tx.SetAppliedIndex(9) }); err != nil {
		t.Fatal(err)
	}
	machine, err := fsm.New(s)
	if err != nil {
		t.Fatal(err)
	}

	// Replay an entry the store has already applied.
	res, ok := machine.Apply(&raft.Log{Index: 4, Term: 1, Data: []byte("anything")}).(op.Result)
	if !ok {
		t.Fatalf("unexpected apply result type")
	}
	if res.Err == nil {
		t.Fatal("a skipped entry reported success; a caller would believe its write landed")
	}
	if !errors.Is(res.Err, fsm.ErrAlreadyApplied) {
		t.Fatalf("expected ErrAlreadyApplied, got: %v", res.Err)
	}
}

// A committed entry that cannot be written must HALT the node, not be skipped.
//
// Raft does not retry a failed Apply; it moves on. So a store failure that
// merely returned an error let the NEXT entry apply and advance the watermark
// past the one that failed — permanently losing a committed change while the
// log still said it happened, with the node serving on state that no longer
// matched its own history. Restart-first gave the other outcome: a write
// reported as failed materialising later.
//
// A deterministic replica missing a committed change has nowhere safe to go.
func TestApplyFailureHaltsRatherThanSkips(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 21)
	}
	s, err := store.Open(filepath.Join(dir, "state.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	machine, err := fsm.New(s)
	if err != nil {
		t.Fatal(err)
	}
	if machine.Halted() != nil {
		t.Fatal("a healthy FSM should not start halted")
	}

	// Break the store underneath it, the way a disk failure would.
	s.Close()

	// A VALID entry, so the failure lands in the store rather than in decoding —
	// a malformed entry is a data problem and correctly does NOT halt.
	raw, err := op.Encode(&op.PutPrincipal{
		Header: op.Header{AtSec: 1000}, ID: "p1", Path: "/people/p1", Type: "human",
	})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := s.Barrier().SealRandom(raw, []byte("signet/op/v1"))
	if err != nil {
		t.Fatal(err)
	}
	res, _ := machine.Apply(&raft.Log{Index: 1, Term: 1, Data: sealed}).(op.Result)
	if res.Err == nil {
		t.Fatal("applying to a broken store reported success")
	}
	if machine.Halted() == nil {
		t.Fatal("the FSM kept going after failing to apply a committed entry")
	}

	// And it refuses everything afterwards, so a later entry cannot advance the
	// watermark past the one that was lost.
	next, _ := machine.Apply(&raft.Log{Index: 2, Term: 1, Data: sealed}).(op.Result)
	if next.Err == nil {
		t.Fatal("a halted FSM applied a subsequent entry")
	}
	if !strings.Contains(next.Err.Error(), "HALTED") {
		t.Fatalf("the refusal should name the halt: %v", next.Err)
	}
}
