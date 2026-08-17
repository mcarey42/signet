package fsm

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
	"github.com/mcarey42/signet/internal/op"
	"github.com/mcarey42/signet/internal/seal"
	"github.com/mcarey42/signet/internal/store"
)

// Node is one Signet domain member: the store, the FSM, and the Raft instance
// that serializes writes into it.
//
// The MVP runs a single voter and carries NO membership machinery — no join,
// no promotion, no network transport. Growing a domain is the multi-node
// milestone, where peers join as non-voters and voter counts stay odd
// (docs/14). Keeping that code absent is deliberate: what is not here cannot
// be half-right.
type Node struct {
	raft  *raft.Raft
	st    *store.Store
	logs  *raftboltdb.BoltStore
	trans *raft.InmemTransport
	id    string
	seal  seal.Seal
}

type Config struct {
	DataDir string
	// Seal is a seal URI: file:///path/to/key or
	// pkcs11:?module=...&token=...&pin=...&label=...
	Seal     string
	NodeID   string
	LogLevel string // raft log level; "ERROR" keeps startup quiet
}

// Open brings up the store and Raft, bootstrapping a single-voter cluster the
// first time.
func Open(cfg Config) (*Node, error) {
	if cfg.NodeID == "" {
		cfg.NodeID = "signet-0"
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "ERROR"
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}

	sl, err := seal.Open(cfg.Seal)
	if err != nil {
		return nil, err
	}
	// The root key exists only in wrapped form on disk; with a hardware seal
	// the data directory cannot be opened without the device.
	rootKey, err := seal.LoadOrCreateRootKey(sl, cfg.DataDir)
	if err != nil {
		sl.Close()
		return nil, err
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "state.db"), rootKey)
	if err != nil {
		sl.Close()
		return nil, err
	}

	logs, err := raftboltdb.NewBoltStore(filepath.Join(cfg.DataDir, "raft.db"))
	if err != nil {
		st.Close()
		return nil, fmt.Errorf("fsm: open raft log: %w", err)
	}
	snaps, err := raft.NewFileSnapshotStore(cfg.DataDir, 2, io.Discard)
	if err != nil {
		logs.Close()
		st.Close()
		return nil, err
	}

	rcfg := raft.DefaultConfig()
	rcfg.LocalID = raft.ServerID(cfg.NodeID)
	rcfg.LogLevel = cfg.LogLevel
	rcfg.LogOutput = os.Stderr

	_, trans := raft.NewInmemTransport(raft.ServerAddress(cfg.NodeID))

	hasState, err := raft.HasExistingState(logs, logs, snaps)
	if err != nil {
		logs.Close()
		st.Close()
		return nil, err
	}

	r, err := raft.NewRaft(rcfg, New(st), logs, logs, snaps, trans)
	if err != nil {
		logs.Close()
		st.Close()
		return nil, fmt.Errorf("fsm: start raft: %w", err)
	}
	if !hasState {
		f := r.BootstrapCluster(raft.Configuration{Servers: []raft.Server{
			{ID: rcfg.LocalID, Address: trans.LocalAddr()},
		}})
		if err := f.Error(); err != nil {
			return nil, fmt.Errorf("fsm: bootstrap: %w", err)
		}
	}
	return &Node{raft: r, st: st, logs: logs, trans: trans, id: cfg.NodeID, seal: sl}, nil
}

func (n *Node) Store() *store.Store { return n.st }

// Seal is the key custodian this node was opened with.
func (n *Node) Seal() seal.Seal { return n.seal }

// WaitForLeader blocks until this node has won its (uncontested) election.
//
// If it never does, the most common cause by far is a node restarted under a
// different identity than it bootstrapped with: Raft's stored configuration
// names the original, so the node is absent from its own cluster and cannot
// vote for itself. That is reported here rather than left as a timeout, because
// a hang gives an operator nothing to act on.
func (n *Node) WaitForLeader(ctx context.Context) error {
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		if n.raft.State() == raft.Leader {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf(
				"fsm: node %q never became leader: %w.\n"+
					"If this domain previously ran under a different node name, that is the cause: "+
					"Raft's stored configuration names the original, so this node is not a member of "+
					"its own cluster and cannot elect itself. Restart it under the name it was "+
					"created with", n.id, ctx.Err())
		case <-tick.C:
		}
	}
}

// Propose encrypts an Op, commits it through Raft, and returns what Apply
// computed. The barrier pass happens here, at propose time, so the Raft log and
// every backup segment built from it hold ciphertext only (docs/03).
func (n *Node) Propose(ctx context.Context, o op.Op) (op.Result, error) {
	raw, err := op.Encode(o)
	if err != nil {
		return op.Result{}, err
	}
	sealed, err := n.st.Barrier().SealRandom(raw, opAAD)
	if err != nil {
		return op.Result{}, err
	}

	timeout := 10 * time.Second
	if dl, ok := ctx.Deadline(); ok {
		timeout = time.Until(dl)
	}
	f := n.raft.Apply(sealed, timeout)
	if err := f.Error(); err != nil {
		return op.Result{}, fmt.Errorf("propose %s: %w", o.OpKind(), err)
	}
	res, ok := f.Response().(op.Result)
	if !ok {
		return op.Result{}, fmt.Errorf("propose %s: unexpected apply result %T", o.OpKind(), f.Response())
	}
	return res, res.Err
}

// Status reports what sys/health needs. Seal and consensus state are server
// questions, not identity questions, so this lives here and not in the kernel.
type Status struct {
	Initialized bool
	Sealed      bool
	Leader      bool
	NodeID      string
	SealName    string
	SealKeyID   string
}

func (n *Node) Status() Status {
	return Status{
		Initialized: true,
		Sealed:      false, // Signet unseals at startup or refuses to start
		Leader:      n.raft.State() == raft.Leader,
		NodeID:      n.id,
		SealName:    n.seal.Name(),
		SealKeyID:   n.seal.KeyID(),
	}
}

func (n *Node) Close() error {
	if err := n.raft.Shutdown().Error(); err != nil {
		return err
	}
	if err := n.logs.Close(); err != nil {
		return err
	}
	if err := n.st.Close(); err != nil {
		return err
	}
	return n.seal.Close()
}
