package kernel

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/mcarey/signet/internal/op"
	"github.com/mcarey/signet/internal/store"
)

// Apply is the single write path. Every mutation in Signet passes through this
// function, which is why consistency, audit, and encryption are each enforced
// in exactly one place.
//
// Apply is a PURE FUNCTION of (op, prior state): it reads no clock, draws no
// randomness, performs no I/O, and takes no context. Timestamps and generated
// identifiers arrive inside the Op, resolved by the proposer. This is not
// stylistic — restore replays backup segments through this exact path
// (docs/03), so an impure Apply would reconstruct different state than it
// originally computed (docs/15 contract 1).
//
// State-dependent invariants live here rather than at propose time, because
// Apply is the serialized single writer: checking them here makes them
// serializable for free, closing the TOCTOU window where two independently
// valid proposals interleave into a violation (docs/15 contract 4).
//
// Apply performs all validation before its first write, so a rejected Op
// leaves no partial state — the transaction then carries only the audit record.
func Apply(tx *store.Tx, o op.Op) op.Result {
	switch v := o.(type) {
	case *op.PutPrincipal:
		return applyPutPrincipal(tx, v)
	case *op.PutBinding:
		return applyPutBinding(tx, v)
	case *op.PutSecret:
		return applyPutSecret(tx, v)
	case *op.CreateSession:
		return applyCreateSession(tx, v)
	case *op.RevokeSession:
		return applyRevokeSession(tx, v)
	default:
		return op.Result{Err: fmt.Errorf("kernel: no applier for %T", o)}
	}
}

func applyPutPrincipal(tx *store.Tx, o *op.PutPrincipal) op.Result {
	if err := ValidatePath(o.Path); err != nil {
		return op.Result{Err: err}
	}
	if err := validateType(o.Type); err != nil {
		return op.Result{Err: err}
	}
	if o.ID == "" {
		return op.Result{Err: errors.New("principal: missing stable ID")}
	}
	// A path is a name, and names are unique: it may not be reassigned to a
	// different principal while its current holder exists.
	if raw, ok, err := tx.Get(store.BucketPathIndex, o.Path); err != nil {
		return op.Result{Err: err}
	} else if ok && op.ID(raw) != o.ID {
		return op.Result{Err: fmt.Errorf("principal: path %s already names %s", o.Path, raw)}
	}

	p := Principal{ID: o.ID, Path: o.Path, Type: o.Type}
	blob, err := json.Marshal(p)
	if err != nil {
		return op.Result{Err: err}
	}
	if err := tx.Put(store.BucketPrincipals, string(o.ID), blob); err != nil {
		return op.Result{Err: err}
	}
	if err := tx.Put(store.BucketPathIndex, o.Path, []byte(o.ID)); err != nil {
		return op.Result{Err: err}
	}
	return op.Result{ID: o.ID}
}

func applyPutBinding(tx *store.Tx, o *op.PutBinding) op.Result {
	if err := ValidatePath(o.Scope); err != nil {
		return op.Result{Err: fmt.Errorf("binding scope: %w", err)}
	}
	if !KnownRole(o.Role) {
		return op.Result{Err: fmt.Errorf("binding: unknown role %q", o.Role)}
	}
	if o.ID == "" || o.Subject == "" {
		return op.Result{Err: errors.New("binding: missing ID or subject")}
	}
	if _, ok, err := tx.Get(store.BucketPrincipals, string(o.Subject)); err != nil {
		return op.Result{Err: err}
	} else if !ok {
		return op.Result{Err: fmt.Errorf("binding: subject %s does not exist", o.Subject)}
	}

	// Delegation only narrows. The grantor must already hold admin authority at
	// a scope covering this binding's scope, so no sequence of grants can widen
	// anyone's reach beyond where the granter could already act.
	//
	// The single exception is bootstrap: the very first binding in an empty
	// domain has no grantor, because there is nobody yet who could be one.
	if o.Grantor == "" {
		empty, err := bindingsEmpty(tx)
		if err != nil {
			return op.Result{Err: err}
		}
		if !empty {
			return op.Result{Err: errors.New("binding: missing grantor (bootstrap is only legal in an empty domain)")}
		}
	} else {
		ok, err := HasAuthority(tx, o.Grantor, VerbAdmin, o.Scope, o.AtSec)
		if err != nil {
			return op.Result{Err: err}
		}
		if !ok {
			return op.Result{Err: fmt.Errorf("binding: grantor %s lacks admin authority at %s", o.Grantor, o.Scope)}
		}
	}

	b := Binding{ID: o.ID, Subject: o.Subject, Role: o.Role, Scope: o.Scope, Grantor: o.Grantor, NotAfter: o.NotAfter}
	blob, err := json.Marshal(b)
	if err != nil {
		return op.Result{Err: err}
	}
	if err := tx.Put(store.BucketBindings, bindingKey(o.Subject, o.ID), blob); err != nil {
		return op.Result{Err: err}
	}
	return op.Result{ID: o.ID}
}

func applyPutSecret(tx *store.Tx, o *op.PutSecret) op.Result {
	if err := ValidatePath(o.Path); err != nil {
		return op.Result{Err: err}
	}
	cur := Secret{Path: o.Path, CreatedSec: o.AtSec}
	raw, ok, err := tx.Get(store.BucketSecrets, o.Path)
	if err != nil {
		return op.Result{Err: err}
	}
	if ok {
		if err := json.Unmarshal(raw, &cur); err != nil {
			return op.Result{Err: err}
		}
	}
	if o.CAS != nil && *o.CAS != cur.Version {
		return op.Result{Err: errors.New("check-and-set parameter did not match the current version")}
	}

	next := Secret{
		Path: o.Path, Data: o.Data,
		Version:     cur.Version + 1,
		CreatedSec:  cur.CreatedSec,
		ModifiedSec: o.AtSec,
	}
	blob, err := json.Marshal(next)
	if err != nil {
		return op.Result{Err: err}
	}
	if err := tx.Put(store.BucketSecrets, o.Path, blob); err != nil {
		return op.Result{Err: err}
	}
	return op.Result{Version: next.Version}
}

func applyCreateSession(tx *store.Tx, o *op.CreateSession) op.Result {
	if o.TokenHash == "" || o.ID == "" {
		return op.Result{Err: errors.New("session: missing ID or token hash")}
	}
	if _, ok, err := tx.Get(store.BucketPrincipals, string(o.Principal)); err != nil {
		return op.Result{Err: err}
	} else if !ok {
		return op.Result{Err: fmt.Errorf("session: principal %s does not exist", o.Principal)}
	}
	s := Session{
		ID: o.ID, TokenHash: o.TokenHash, Principal: o.Principal,
		AMR: o.AMR, AuthTime: o.AuthTime, Expiry: o.Expiry,
		Verifier: o.Verifier, SenderBindingRef: o.SenderBindingRef,
	}
	blob, err := json.Marshal(s)
	if err != nil {
		return op.Result{Err: err}
	}
	if err := tx.Put(store.BucketSessions, o.TokenHash, blob); err != nil {
		return op.Result{Err: err}
	}
	return op.Result{ID: o.ID}
}

func applyRevokeSession(tx *store.Tx, o *op.RevokeSession) op.Result {
	if err := tx.Delete(store.BucketSessions, o.TokenHash); err != nil {
		return op.Result{Err: err}
	}
	return op.Result{}
}

func bindingsEmpty(tx *store.Tx) (bool, error) {
	empty := true
	err := tx.ScanPrefix(store.BucketBindings, "", func(string, []byte) bool {
		empty = false
		return false
	})
	return empty, err
}

// AuditRecord is the event written alongside every applied Op. It records what
// was proposed, by whom, at which log position, and whether it was accepted —
// enough provenance to distinguish a legitimately issued change from a forged
// one (docs/11).
type AuditRecord struct {
	Term     uint64 `json:"term"`
	Index    uint64 `json:"index"`
	Kind     string `json:"kind"`
	Actor    op.ID  `json:"actor,omitempty"`
	AtSec    int64  `json:"at"`
	Accepted bool   `json:"accepted"`
	Error    string `json:"error,omitempty"`
	Subject  string `json:"subject,omitempty"` // path or key the Op touched
}

// NewAuditRecord builds the record for one applied Op.
func NewAuditRecord(term, index uint64, o op.Op, res op.Result) ([]byte, error) {
	r := AuditRecord{Term: term, Index: index, Kind: o.OpKind().String(), Accepted: res.Err == nil}
	if res.Err != nil {
		r.Error = res.Err.Error()
	}
	switch v := o.(type) {
	case *op.PutPrincipal:
		r.Actor, r.AtSec, r.Subject = v.Actor, v.AtSec, v.Path
	case *op.PutBinding:
		r.Actor, r.AtSec, r.Subject = v.Actor, v.AtSec, v.Scope
	case *op.PutSecret:
		r.Actor, r.AtSec, r.Subject = v.Actor, v.AtSec, v.Path
	case *op.CreateSession:
		r.Actor, r.AtSec, r.Subject = v.Actor, v.AtSec, string(v.Principal)
	case *op.RevokeSession:
		r.Actor, r.AtSec = v.Actor, v.AtSec
	}
	return json.Marshal(r)
}
