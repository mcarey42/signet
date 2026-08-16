package kernel

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/mcarey42/signet/internal/op"
	"github.com/mcarey42/signet/internal/store"
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
	case *op.PutIssuer:
		return applyPutIssuer(tx, v)
	case *op.PutMapping:
		return applyPutMapping(tx, v)
	case *op.VersionAction:
		return applyVersionAction(tx, v)
	case *op.DestroySecret:
		return applyDestroySecret(tx, v)
	case *op.PutSecretMeta:
		return applyPutSecretMeta(tx, v)
	case *op.PutCA:
		return applyPutCA(tx, v)
	case *op.PutPKIRole:
		return applyPutPKIRole(tx, v)
	case *op.RecordIssuance:
		return applyRecordIssuance(tx, v)
	case *op.PutRolePolicy:
		return applyPutRolePolicy(tx, v)
	case *op.PutKey:
		return applyPutKey(tx, v)
	case *op.PutSSHRole:
		return applyPutSSHRole(tx, v)
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

// Registering a trust anchor decides whose signatures Signet will believe, so
// it is domain-wide authority — no subtree admin can do it (E-13 F7's rule for
// trust-graph writes).
func applyPutIssuer(tx *store.Tx, o *op.PutIssuer) op.Result {
	if o.ID == "" || o.Name == "" || o.URL == "" {
		return op.Result{Err: errors.New("issuer: missing ID, name, or URL")}
	}
	if o.Audience == "" {
		return op.Result{Err: errors.New("issuer: a Signet-specific audience is required")}
	}
	if len(o.JWKS) == 0 {
		return op.Result{Err: errors.New("issuer: no pinned key set")}
	}
	if err := requireDomainAuthority(tx, o.Grantor, o.AtSec); err != nil {
		return op.Result{Err: fmt.Errorf("issuer: %w", err)}
	}
	iss := Issuer{ID: o.ID, Name: o.Name, Verifier: o.Verifier, URL: o.URL, Audience: o.Audience, JWKS: o.JWKS}
	blob, err := json.Marshal(iss)
	if err != nil {
		return op.Result{Err: err}
	}
	if err := tx.Put(store.BucketIssuers, o.Name, blob); err != nil {
		return op.Result{Err: err}
	}
	return op.Result{ID: o.ID}
}

func applyPutMapping(tx *store.Tx, o *op.PutMapping) op.Result {
	if o.ID == "" || o.Name == "" {
		return op.Result{Err: errors.New("mapping: missing ID or name")}
	}
	if len(o.Namespaces) == 0 || len(o.ServiceAccounts) == 0 {
		return op.Result{Err: errors.New("mapping: must name the namespaces and service accounts it accepts")}
	}
	if _, ok, err := tx.Get(store.BucketIssuers, o.Issuer); err != nil {
		return op.Result{Err: err}
	} else if !ok {
		return op.Result{Err: fmt.Errorf("mapping: no registered issuer %q", o.Issuer)}
	}

	// A mapping rule decides who a caller gets to *be*, so it is subject to the
	// same narrowing as a grant: an admin of a subtree may only produce
	// principals inside it. Without this, a delegated admin could map their own
	// workload onto a superior principal — the ESC1 shape.
	target, ok, err := loadPrincipal(tx, o.Principal)
	if err != nil {
		return op.Result{Err: err}
	}
	if !ok {
		return op.Result{Err: fmt.Errorf("mapping: principal %s does not exist", o.Principal)}
	}
	if o.Grantor == "" {
		return op.Result{Err: errors.New("mapping: missing grantor")}
	}
	allowed, err := HasAuthority(tx, o.Grantor, VerbAdmin, target.Path, o.AtSec)
	if err != nil {
		return op.Result{Err: err}
	}
	if !allowed {
		return op.Result{Err: fmt.Errorf("mapping: grantor %s lacks admin authority over %s", o.Grantor, target.Path)}
	}

	m := Mapping{
		ID: o.ID, Name: o.Name, Issuer: o.Issuer,
		Namespaces: o.Namespaces, ServiceAccounts: o.ServiceAccounts,
		Principal: o.Principal, TTLSeconds: o.TTLSeconds, Grantor: o.Grantor,
	}
	blob, err := json.Marshal(m)
	if err != nil {
		return op.Result{Err: err}
	}
	if err := tx.Put(store.BucketMappings, o.Name, blob); err != nil {
		return op.Result{Err: err}
	}
	return op.Result{ID: o.ID}
}

// requireDomainAuthority accepts either the bootstrap moment or an admin at the
// domain root.
func requireDomainAuthority(tx *store.Tx, grantor op.ID, atSec int64) error {
	if grantor == "" {
		empty, err := bindingsEmpty(tx)
		if err != nil {
			return err
		}
		if !empty {
			return errors.New("missing grantor")
		}
		return nil
	}
	ok, err := HasAuthority(tx, grantor, VerbAdmin, "/", atSec)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("grantor %s lacks domain-wide admin authority", grantor)
	}
	return nil
}

func loadPrincipal(tx *store.Tx, id op.ID) (Principal, bool, error) {
	var p Principal
	raw, ok, err := tx.Get(store.BucketPrincipals, string(id))
	if err != nil || !ok {
		return p, ok, err
	}
	return p, true, json.Unmarshal(raw, &p)
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
	case *op.PutRolePolicy:
		r.Actor, r.AtSec, r.Subject = v.Actor, v.AtSec, v.Role
	case *op.PutKey:
		r.Actor, r.AtSec, r.Subject = v.Actor, v.AtSec, v.Purpose+"/"+v.ID
	case *op.PutSSHRole:
		r.Actor, r.AtSec, r.Subject = v.Actor, v.AtSec, v.Name
	case *op.PutCA:
		r.Actor, r.AtSec, r.Subject = v.Actor, v.AtSec, v.Name
	case *op.PutPKIRole:
		r.Actor, r.AtSec, r.Subject = v.Actor, v.AtSec, v.Name
	case *op.RecordIssuance:
		r.Actor, r.AtSec, r.Subject = v.Actor, v.AtSec, v.Serial
	case *op.PutIssuer:
		r.Actor, r.AtSec, r.Subject = v.Actor, v.AtSec, v.Name
	case *op.PutMapping:
		r.Actor, r.AtSec, r.Subject = v.Actor, v.AtSec, v.Name
	case *op.PutPrincipal:
		r.Actor, r.AtSec, r.Subject = v.Actor, v.AtSec, v.Path
	case *op.PutBinding:
		r.Actor, r.AtSec, r.Subject = v.Actor, v.AtSec, v.Scope
	case *op.PutSecret:
		r.Actor, r.AtSec, r.Subject = v.Actor, v.AtSec, v.Path
	case *op.VersionAction:
		r.Actor, r.AtSec, r.Subject = v.Actor, v.AtSec, v.Path
	case *op.DestroySecret:
		r.Actor, r.AtSec, r.Subject = v.Actor, v.AtSec, v.Path
	case *op.PutSecretMeta:
		r.Actor, r.AtSec, r.Subject = v.Actor, v.AtSec, v.Path
	case *op.CreateSession:
		r.Actor, r.AtSec, r.Subject = v.Actor, v.AtSec, string(v.Principal)
	case *op.RevokeSession:
		r.Actor, r.AtSec = v.Actor, v.AtSec
	}
	return json.Marshal(r)
}
