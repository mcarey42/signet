// Package fsm binds the Raft state machine to the kernel. It is the only
// package that imports Raft, and it holds no business rules of its own: it
// decodes an entry, hands it to kernel.Apply, and records the audit event in
// the same transaction.
package fsm

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync/atomic"

	"github.com/hashicorp/raft"
	"github.com/mcarey42/signet/internal/kernel"
	"github.com/mcarey42/signet/internal/metrics"
	"github.com/mcarey42/signet/internal/op"
	"github.com/mcarey42/signet/internal/store"
	"github.com/mcarey42/signet/internal/trace"
)

// opAAD binds an encrypted log payload to its purpose.
var opAAD = []byte("signet/op/v1")

type FSM struct {
	st      *store.Store
	applied atomic.Uint64
	// halted records that a committed entry could not be applied. See Apply.
	halted atomic.Pointer[error]
}

// New reads the applied-index watermark and FAILS CLOSED if it cannot.
//
// This used to swallow the error, and the consequence was not merely a replay
// bug. The barrier derives its AES-GCM nonce from the log position
// (term, index, seq), so the watermark is silently the guarantee that a given
// nonce is used once. Lose it — one flipped bit in the stored value is enough,
// no key required — and Raft replays the whole log, re-deriving every nonce
// against different plaintext. Nonce reuse in GCM leaks the XOR of the
// plaintexts and the authentication key with it, which turns a corrupted byte
// into plaintext recovery and forgery.
//
// A node that cannot read its own watermark therefore must not start. Refusing
// to serve is a bad morning; serving with a reused keystream is unrecoverable.
func New(st *store.Store) (*FSM, error) {
	i, err := st.AppliedIndex()
	if err != nil {
		return nil, fmt.Errorf(
			"refusing to start: this node cannot read its applied-index watermark (%w). That "+
				"watermark is what keeps the barrier's nonces unique, so starting without it would "+
				"replay the log and encrypt different data under nonces already used. Restore this "+
				"data directory from a backup rather than starting it", err)
	}
	f := &FSM{st: st}
	f.applied.Store(i)
	return f, nil
}

// Apply executes one committed log entry. Everything nondeterministic already
// happened at propose time, so this runs identically on every replay: crash
// recovery, backup restore, and (later) every follower.
//
// Entries at or below the persisted watermark are skipped. Raft replays from
// the last snapshot on restart, but this FSM's state is durable — so without
// the watermark, replayed entries would apply a second time on top of their own
// results and any accumulating value (a secret's version counter) would drift.
// ErrAlreadyApplied is returned for an entry at or below the watermark.
//
// During ordinary replay nobody reads this — Raft is re-feeding entries whose
// effects are already durable, which is exactly what the watermark is for. It
// matters for a PROPOSAL: a client's write that lands at an already-applied
// index stored nothing, and used to be reported as success because a skipped
// Apply returned an empty result indistinguishable from a real one. That is how
// losing raft.db while state.db survived swallowed a whole prefix of the write
// stream, silently, with 200s all the way.
var ErrAlreadyApplied = errors.New(
	"this log index has already been applied to the store, so the write stored nothing. " +
		"The log is behind the state it describes — usually a lost or restored raft.db beside a " +
		"surviving state.db. Do not treat this as success; restore the pair together")

// Halted reports why this FSM stopped applying, or nil.
func (f *FSM) Halted() error {
	if p := f.halted.Load(); p != nil {
		return *p
	}
	return nil
}

func (f *FSM) Apply(l *raft.Log) any {
	// Once halted, nothing further is applied.
	//
	// Raft does not retry a failed Apply; it moves on. So a store failure that
	// merely returned an error let the NEXT entry apply and advance the
	// watermark past the one that failed — permanently losing a committed
	// change while the log still says it happened, with the node serving
	// happily on state that no longer matches its own history.
	//
	// A deterministic replica that cannot apply a committed entry has nowhere
	// safe to go: everything after it is computed from state that is missing a
	// change. So it stops, loudly, and a restart replays from the watermark —
	// which was never advanced — and applies the entry properly.
	if err := f.Halted(); err != nil {
		return op.Result{Err: err}
	}
	if l.Index <= f.applied.Load() {
		return op.Result{Err: ErrAlreadyApplied}
	}
	defer metrics.Time(metrics.ApplyDuration)()
	pt, err := f.st.Barrier().Open(l.Data, opAAD)
	if err != nil {
		return op.Result{Err: fmt.Errorf("fsm: decrypt entry %d: %w", l.Index, err)}
	}
	o, err := op.Decode(pt)
	if err != nil {
		return op.Result{Err: fmt.Errorf("fsm: decode entry %d: %w", l.Index, err)}
	}

	var res op.Result
	if err := f.st.Update(l.Term, l.Index, func(tx *store.Tx) error {
		// kernel.Apply validates fully before writing, so a rejected Op leaves
		// the transaction carrying only its audit record — rejections are
		// recorded, not silently dropped.
		res = kernel.Apply(tx, o)
		rec, err := kernel.NewAuditRecord(l.Term, l.Index, o, res)
		if err != nil {
			return err
		}
		if err := tx.AppendAudit(rec); err != nil {
			return err
		}
		return tx.SetAppliedIndex(l.Index)
	}); err != nil {
		// Not a rejected operation — kernel.Apply records those inside the
		// transaction and commits. This is the STORE failing: out of disk, I/O
		// error, a refused write. The entry is committed to the log and has not
		// taken effect, and it is not safe to continue without it.
		halt := fmt.Errorf(
			"fsm: HALTED at log entry %d: this committed entry could not be written to the store "+
				"(%w). It is not lost — the applied-index watermark was not advanced, so restarting "+
				"replays and applies it. Nothing further will be applied until then, because "+
				"continuing would compute later state from state that is missing a committed "+
				"change. Fix the underlying cause (usually disk) and restart", l.Index, err)
		f.halted.CompareAndSwap(nil, &halt)
		return op.Result{Err: halt}
	}
	f.applied.Store(l.Index)
	trace.Do(trace.AreaApply, "entry.applied", func(e *trace.Event) {
		e.Int("index", int64(l.Index)).Int("term", int64(l.Term)).
			Str("kind", o.OpKind().String()).Err(res.Err)
	})
	return res
}

func (f *FSM) Snapshot() (raft.FSMSnapshot, error) {
	data, err := f.st.SnapshotRaw()
	if err != nil {
		return nil, err
	}
	return &snapshot{data: data}, nil
}

func (f *FSM) Restore(rc io.ReadCloser) error {
	defer rc.Close()
	var data map[string]map[string][]byte
	if err := json.NewDecoder(rc).Decode(&data); err != nil {
		return fmt.Errorf("fsm: decode snapshot: %w", err)
	}
	if err := f.st.RestoreRaw(data); err != nil {
		return err
	}
	// The watermark travels inside the snapshot, so reload it: entries the
	// snapshot already covers must not be replayed over it.
	i, err := f.st.AppliedIndex()
	if err != nil {
		return err
	}
	f.applied.Store(i)
	return nil
}

type snapshot struct{ data map[string]map[string][]byte }

func (s *snapshot) Persist(sink raft.SnapshotSink) error {
	if err := json.NewEncoder(sink).Encode(s.data); err != nil {
		sink.Cancel()
		return err
	}
	return sink.Close()
}

func (s *snapshot) Release() {}
