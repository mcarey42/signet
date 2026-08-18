package store

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// The audit log is hash-chained: every entry carries the hash of the one before
// it, so altering, removing, or inserting a record breaks every hash after it.
//
// # What chaining does and does not catch
//
// Chaining makes *edits* self-evident to anyone holding the log. It does not
// catch **truncation** — lopping off the newest entries leaves a shorter chain
// that is perfectly self-consistent — and it does not catch a **wholesale
// rewrite** by someone who can recompute the chain from the start. Both are
// exactly what an attacker who has taken the node would do.
//
// Detecting those requires something outside the node: a checkpoint of the
// chain head, published somewhere the node cannot retroactively change. That is
// what internal/audit adds on top of this file, and it is why the milestone is
// "anchored audit" rather than "hash-chained audit". Chaining alone would be a
// tamper-evidence claim that does not survive its own threat model.
//
// The chain is computed inside the same transaction as the mutation it
// describes, so it cannot drift from the state it is describing, and it is a
// pure function of (previous head, record bytes) so every replica computes the
// identical chain.

// auditGenesis is the chain's starting value. A fixed, domain-independent
// constant is sufficient: the chain's integrity comes from the links, and its
// attribution from the signed checkpoints over it.
const auditGenesis = "signet/audit/chain/v1"

// GenesisHead is the value the chain starts from, exported so a witness can
// replay an extension that begins at the very first entry.
func GenesisHead() string { return auditGenesis }

// metaAuditHead tracks the newest entry's hash; metaAuditCount how many entries
// the chain contains. Count is kept because a chain that has been truncated is
// self-consistent, so the only local signal is that fewer entries exist than
// were counted — weak on its own (an attacker who can drop entries can edit
// this too), but it turns a silent truncation into one that must be covered up
// deliberately.
const (
	metaAuditHead  = "audit_head"
	metaAuditCount = "audit_count"
)

// AuditEntry is one link in the chain: an opaque record plus its position in
// the chain.
//
// The record is opaque here on purpose. This package chains bytes and knows
// nothing about what an audit record means, which keeps the tamper-evidence
// mechanism independent of the schema it protects — a new Op kind cannot
// accidentally change how the chain is computed.
type AuditEntry struct {
	Seq    uint64          `json:"seq"`
	Prev   string          `json:"prev"`
	Hash   string          `json:"hash"`
	Record json.RawMessage `json:"record"`
}

// ChainHash computes an entry's hash from the previous hash and its record.
//
// Length-prefixing the previous hash keeps the concatenation unambiguous: with
// bare concatenation, a crafted record could shift the boundary between the two
// inputs and produce a collision with a different (prev, record) pair.
func ChainHash(prev string, record []byte) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d:", len(prev))
	h.Write([]byte(prev))
	fmt.Fprintf(h, "%d:", len(record))
	h.Write(record)
	return "sha256:" + base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// AppendAudit records one event as part of the same transaction as the change
// it describes. Audit is FSM state, not a side effect: keying by log position
// makes it idempotent under replay and restore, and atomic with the mutation —
// a mutation without its audit record is impossible, not merely unlikely
// (docs/15 contract 3).
func (t *Tx) AppendAudit(rec []byte) error {
	if !t.write {
		return ErrReadOnly
	}
	prev, err := t.auditHead()
	if err != nil {
		return err
	}
	count, err := t.AuditCount()
	if err != nil {
		return err
	}
	entry := AuditEntry{
		Seq: count + 1, Prev: prev, Hash: ChainHash(prev, rec), Record: json.RawMessage(rec),
	}
	blob, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	key := fmt.Sprintf("%020d:%020d:%010d", t.term, t.index, t.seq)
	if err := t.Put(BucketAudit, key, blob); err != nil {
		return err
	}
	if err := t.Put(BucketMeta, metaAuditHead, []byte(entry.Hash)); err != nil {
		return err
	}
	return t.Put(BucketMeta, metaAuditCount, []byte(fmt.Sprintf("%d", entry.Seq)))
}

func (t *Tx) auditHead() (string, error) {
	v, ok, err := t.Get(BucketMeta, metaAuditHead)
	if err != nil {
		return "", err
	}
	if !ok {
		return auditGenesis, nil
	}
	return string(v), nil
}

// AuditHead returns the current chain head, which is what a checkpoint commits
// to.
func (t *Tx) AuditHead() (string, error) { return t.auditHead() }

// AuditCount returns how many entries the chain claims to contain.
func (t *Tx) AuditCount() (uint64, error) {
	v, ok, err := t.Get(BucketMeta, metaAuditCount)
	if err != nil || !ok {
		return 0, err
	}
	var n uint64
	if _, err := fmt.Sscanf(string(v), "%d", &n); err != nil {
		return 0, err
	}
	return n, nil
}

// AuditBreak describes where a chain stopped being consistent.
type AuditBreak struct {
	Key      string
	Seq      uint64
	Expected string
	Found    string
	Reason   string
}

func (b *AuditBreak) Error() string {
	return fmt.Sprintf("audit chain broken at entry %d (%s): %s", b.Seq, b.Key, b.Reason)
}

// VerifyAuditChain walks the log in order and recomputes every link.
//
// It returns the number of entries verified and the head it arrived at, or a
// *AuditBreak naming the first entry that does not follow from its predecessor.
// Reporting the first break rather than a boolean matters operationally: the
// break points at when the tampering happened, which is usually the question.
func (t *Tx) VerifyAuditChain() (count uint64, head string, err error) {
	prev := auditGenesis
	var n uint64
	var brk *AuditBreak
	scanErr := t.ScanPrefix(BucketAudit, "", func(key string, val []byte) bool {
		var e AuditEntry
		if err := json.Unmarshal(val, &e); err != nil {
			brk = &AuditBreak{Key: key, Seq: n + 1, Reason: "entry is unreadable: " + err.Error()}
			return false
		}
		n++
		if e.Seq != n {
			brk = &AuditBreak{Key: key, Seq: n, Expected: fmt.Sprint(n), Found: fmt.Sprint(e.Seq),
				Reason: "entry is numbered out of sequence, so an entry was inserted or removed"}
			return false
		}
		if e.Prev != prev {
			brk = &AuditBreak{Key: key, Seq: e.Seq, Expected: prev, Found: e.Prev,
				Reason: "entry does not follow the one before it"}
			return false
		}
		if got := ChainHash(e.Prev, e.Record); got != e.Hash {
			brk = &AuditBreak{Key: key, Seq: e.Seq, Expected: e.Hash, Found: got,
				Reason: "the record does not match its own hash, so the record was altered"}
			return false
		}
		prev = e.Hash
		return true
	})
	if scanErr != nil {
		return n, prev, scanErr
	}
	if brk != nil {
		return n, prev, brk
	}
	return n, prev, nil
}

// ScanAudit visits each audit entry in order.
func (t *Tx) ScanAudit(fn func(key string, e AuditEntry) bool) error {
	return t.ScanPrefix(BucketAudit, "", func(key string, val []byte) bool {
		var e AuditEntry
		if err := json.Unmarshal(val, &e); err != nil {
			return true
		}
		return fn(key, e)
	})
}
