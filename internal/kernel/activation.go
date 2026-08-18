package kernel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/mcarey42/signet/internal/op"
	"github.com/mcarey42/signet/internal/store"
)

// Privileged access management: the split between being *eligible* for an
// authority and *holding* it.
//
// # Why the split is worth the machinery
//
// A standing grant is held by whoever holds the session — including an attacker
// who has just stolen one. Eligibility is not standing access: the authority
// exists on paper, and turning it on is a separate, logged, time-bounded act
// that can require somebody else's agreement. What an attacker inherits from a
// stolen session is then the right to *ask*, which is a much smaller thing and
// a much louder one.
//
// # Why activations are runtime state
//
// An activation is never declarative and never in git (docs/13 F9). Declaring
// "alice is admin from 14:00 to 18:00" in a config repo would mean the elevation
// happens on a commit, reviewed at authoring time and then simply true. The
// point of PAM is that elevation happens at the moment of need, against the
// policy as it stands at that moment.
//
// # The four semantics, each a classic bug if left unstated (docs/13)
//
//  1. An activation is a grant window, and every renewal re-validates BOTH the
//     activation and the binding beneath it. Either vanishing ends the access at
//     the next renewal, with no sweep to run.
//  2. Expiry is clamped to the binding's own NotAfter. Without this you get
//     "eligible until Friday, activated Thursday 23:59 for four hours" — a JIT
//     grant that outlives itself.
//  3. Approval re-validates the binding at grant time, not at request time, so
//     revoking eligibility while a request is pending actually revokes it.
//  4. Nobody approves their own request, however much authority they hold.

// DefaultMaxActivationSec bounds an activation when the binding does not.
const DefaultMaxActivationSec = 4 * 60 * 60

// LoadActivations returns every activation recorded for a subject.
func LoadActivations(tx *store.Tx, subject op.ID) ([]Activation, error) {
	var out []Activation
	err := tx.ScanPrefix(store.BucketActivation, string(subject)+"/", func(_ string, val []byte) bool {
		var a Activation
		if json.Unmarshal(val, &a) == nil {
			out = append(out, a)
		}
		return true
	})
	return out, err
}

func activationKey(subject, id op.ID) string { return string(subject) + "/" + string(id) }

func loadActivation(tx *store.Tx, subject, id op.ID) (*Activation, error) {
	raw, ok, err := tx.Get(store.BucketActivation, activationKey(subject, id))
	if err != nil || !ok {
		return nil, err
	}
	var a Activation
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, err
	}
	return &a, nil
}

func putActivation(tx *store.Tx, a *Activation) error {
	blob, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return tx.Put(store.BucketActivation, activationKey(a.Subject, a.ID), blob)
}

// findBinding locates one of a subject's bindings by ID.
func findBinding(tx *store.Tx, subject, id op.ID) (*Binding, error) {
	bs, err := LoadBindings(tx, subject)
	if err != nil {
		return nil, err
	}
	for i := range bs {
		if bs[i].ID == id {
			return &bs[i], nil
		}
	}
	return nil, nil
}

// applyRequestActivation records a request. It confers nothing on its own: an
// activation that needs approval stays pending, and one that does not becomes
// active here, having passed the same checks either way.
func applyRequestActivation(tx *store.Tx, o *op.RequestActivation) op.Result {
	b, err := findBinding(tx, o.Subject, o.Binding)
	if err != nil {
		return op.Result{Err: err}
	}
	if b == nil {
		return op.Result{Err: fmt.Errorf(
			"activation: no binding %s for this principal. You can only activate an authority you "+
				"are already eligible for", o.Binding)}
	}
	if !b.ActivationRequired {
		return op.Result{Err: fmt.Errorf(
			"activation: binding %s is held outright and needs no activation. Activating it would "+
				"imply it was not already in force, which it is", o.Binding)}
	}
	if b.NotAfter != 0 && o.AtSec >= b.NotAfter {
		return op.Result{Err: fmt.Errorf(
			"activation: eligibility for %s at %s ended at %d. An expired binding cannot be "+
				"activated — that is what its expiry meant", b.Role, b.Scope, b.NotAfter)}
	}

	// Step-up, checked against the facts carried in the Op rather than looked
	// up, so Apply stays pure and every replica reaches the same verdict.
	if err := checkStepUp(b, o.SessionAMR, o.SessionAuthTime, o.AtSec); err != nil {
		return op.Result{Err: err}
	}

	// One live or pending activation per binding. Without this, a requester
	// could stack windows and quietly hold the authority indefinitely.
	existing, err := LoadActivations(tx, o.Subject)
	if err != nil {
		return op.Result{Err: err}
	}
	for i := range existing {
		a := &existing[i]
		if a.Binding != o.Binding {
			continue
		}
		if a.State == ActivationPending {
			return op.Result{Err: fmt.Errorf(
				"activation: request %s for this binding is still pending a decision", a.ID)}
		}
		if a.Live(o.AtSec) {
			return op.Result{Err: fmt.Errorf(
				"activation: %s is already active until %d. Let it expire, or kill it, rather than "+
					"stacking another window on top", a.ID, a.Expiry)}
		}
	}

	a := &Activation{
		ID: o.ID, Subject: o.Subject, Binding: o.Binding,
		Role: b.Role, Scope: b.Scope, Reason: o.Reason,
		State: ActivationPending, RequestedAt: o.AtSec,
	}
	if !b.ApprovalRequired {
		a.State = ActivationActive
		a.Expiry = clampExpiry(b, o.ForSeconds, o.AtSec)
	}
	if err := putActivation(tx, a); err != nil {
		return op.Result{Err: err}
	}
	return op.Result{}
}

// clampExpiry applies both bounds: what the binding allows one activation to
// last, and when eligibility itself ends.
func clampExpiry(b *Binding, forSeconds, nowSec int64) int64 {
	maxSec := b.MaxActivationSec
	if maxSec <= 0 {
		maxSec = DefaultMaxActivationSec
	}
	if forSeconds <= 0 || forSeconds > maxSec {
		forSeconds = maxSec
	}
	expiry := nowSec + forSeconds
	// JIT-on-JIT: an activation may never outlive the eligibility it draws on.
	if b.NotAfter != 0 && expiry > b.NotAfter {
		expiry = b.NotAfter
	}
	return expiry
}

func checkStepUp(b *Binding, amr []string, authTime, nowSec int64) error {
	if len(b.StepUpAMR) == 0 {
		return nil
	}
	have := map[string]bool{}
	for _, m := range amr {
		have[m] = true
	}
	var missing []string
	for _, want := range b.StepUpAMR {
		if !have[want] {
			missing = append(missing, want)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf(
			"activation: this authority requires re-authentication with %v and the session carries "+
				"%v. Elevation is meant to cost something at the moment it happens; the factor you "+
				"used to open the session does not count twice", missing, amr)
	}
	if b.StepUpMaxAgeSec > 0 && (authTime == 0 || nowSec-authTime > b.StepUpMaxAgeSec) {
		return fmt.Errorf(
			"activation: this authority requires authentication within the last %ds and this "+
				"session authenticated %ds ago. Re-authenticate and request again",
			b.StepUpMaxAgeSec, nowSec-authTime)
	}
	return nil
}

// applyActivationAction approves, denies, or kills.
func applyActivationAction(tx *store.Tx, o *op.ActivationAction) op.Result {
	a, err := loadActivation(tx, o.Subject, o.ID)
	if err != nil {
		return op.Result{Err: err}
	}
	if a == nil {
		return op.Result{Err: fmt.Errorf("activation: no such activation %s", o.ID)}
	}

	switch o.Verb {
	case op.ActivationKill:
		if a.State != ActivationActive && a.State != ActivationPending {
			return op.Result{Err: fmt.Errorf("activation: %s is already %s", o.ID, a.State)}
		}
		a.State, a.DecidedBy, a.DecidedAt, a.KillReason = ActivationKilled, o.Actor2, o.AtSec, o.Reason
		return op.Result{Err: putActivation(tx, a)}

	case op.ActivationDeny:
		if a.State != ActivationPending {
			return op.Result{Err: fmt.Errorf("activation: %s is %s, not pending", o.ID, a.State)}
		}
		a.State, a.DecidedBy, a.DecidedAt, a.KillReason = ActivationDenied, o.Actor2, o.AtSec, o.Reason
		return op.Result{Err: putActivation(tx, a)}

	case op.ActivationApprove:
		if a.State != ActivationPending {
			return op.Result{Err: fmt.Errorf("activation: %s is %s, not pending", o.ID, a.State)}
		}
		// Nobody approves their own request, whatever authority they hold. This
		// is the whole point of requiring approval, and the check belongs here
		// rather than in a caller that could be bypassed.
		if o.Actor2 == a.Subject {
			return op.Result{Err: errors.New(
				"activation: an activation cannot be approved by the principal requesting it. " +
					"Separation of duties is the reason approval was required at all")}
		}
		for _, prior := range a.Approvals {
			if prior == o.Actor2 {
				return op.Result{Err: fmt.Errorf(
					"activation: %s has already approved this request; a second approval from the "+
						"same principal is not a second approver", o.Actor2)}
			}
		}

		// Re-validate the binding NOW, not as it stood when the request was
		// made. Revoking eligibility while a request sits in a queue has to
		// actually revoke it, or the queue becomes a way to outlive a decision.
		b, err := findBinding(tx, a.Subject, a.Binding)
		if err != nil {
			return op.Result{Err: err}
		}
		if b == nil {
			a.State, a.DecidedBy, a.DecidedAt = ActivationDenied, o.Actor2, o.AtSec
			a.KillReason = "the underlying eligibility was removed while this request was pending"
			if err := putActivation(tx, a); err != nil {
				return op.Result{Err: err}
			}
			return op.Result{Err: errors.New(
				"activation: the binding this request draws on no longer exists. Approval " +
					"re-checks eligibility at the moment of granting, not when the request was made")}
		}
		if b.NotAfter != 0 && o.AtSec >= b.NotAfter {
			a.State, a.DecidedBy, a.DecidedAt = ActivationDenied, o.Actor2, o.AtSec
			a.KillReason = "eligibility expired while this request was pending"
			if err := putActivation(tx, a); err != nil {
				return op.Result{Err: err}
			}
			return op.Result{Err: fmt.Errorf(
				"activation: eligibility for %s expired at %d, while this request was pending",
				b.Role, b.NotAfter)}
		}

		// The approver must be able to confer what is being conferred.
		// Delegation only narrows, and approving is a form of granting.
		ok, err := HasAuthority(tx, o.Actor2, VerbAdmin, b.Scope, o.AtSec)
		if err != nil {
			return op.Result{Err: err}
		}
		if !ok {
			return op.Result{Err: fmt.Errorf(
				"activation: %s cannot approve an activation at %s without admin authority there. "+
					"Approving is a form of granting, so it narrows the same way", o.Actor2, b.Scope)}
		}

		a.Approvals = append(a.Approvals, o.Actor2)
		need := b.MinApprovers
		if need <= 0 {
			need = 1
		}
		if len(a.Approvals) >= need {
			a.State, a.DecidedBy, a.DecidedAt = ActivationActive, o.Actor2, o.AtSec
			a.Expiry = clampExpiry(b, 0, o.AtSec)
		}
		return op.Result{Err: putActivation(tx, a)}
	}
	return op.Result{Err: fmt.Errorf("activation: unknown verb %q", o.Verb)}
}

// --- service API ----------------------------------------------------------

// Eligibility is one authority a principal could hold, and its current state.
type Eligibility struct {
	Binding    Binding     `json:"binding"`
	Activation *Activation `json:"activation,omitempty"`
	Held       bool        `json:"held"`
}

// Eligible lists what a principal holds outright and what they may activate.
//
// The distinction is the product: an operator should be able to see at a glance
// which of their powers are switched on right now.
func (k *Kernel) Eligible(ctx context.Context, subject op.ID) ([]Eligibility, error) {
	var out []Eligibility
	now := k.now().Unix()
	err := k.store.View(func(tx *store.Tx) error {
		bs, err := LoadBindings(tx, subject)
		if err != nil {
			return err
		}
		acts, err := LoadActivations(tx, subject)
		if err != nil {
			return err
		}
		live := map[op.ID]*Activation{}
		for i := range acts {
			a := &acts[i]
			if a.State == ActivationPending || a.Live(now) {
				live[a.Binding] = a
			}
		}
		for _, b := range bs {
			e := Eligibility{Binding: b}
			if !b.ActivationRequired {
				e.Held = b.NotAfter == 0 || now < b.NotAfter
			} else if a := live[b.ID]; a != nil {
				e.Activation = a
				e.Held = a.Live(now)
			}
			out = append(out, e)
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Binding.Scope < out[j].Binding.Scope })
	return out, err
}

// RequestActivation asks to hold an authority the session's principal is
// eligible for. The session supplies the authentication facts step-up is judged
// against, so a caller cannot assert its own AMR.
func (k *Kernel) RequestActivation(ctx context.Context, s Session, binding op.ID,
	reason string, forSeconds int64) (op.ID, error) {

	if reason == "" {
		return "", errors.New(
			"activation: a reason is required. The record of why an authority was switched on is " +
				"most of what makes this mechanism worth having")
	}
	id, err := newID()
	if err != nil {
		return "", err
	}
	_, err = k.prop.Propose(ctx, &op.RequestActivation{
		Header: k.header(s.Principal), ID: id, Subject: s.Principal, Binding: binding,
		Reason: reason, ForSeconds: forSeconds,
		SessionAuthTime: s.AuthTime, SessionAMR: s.AMR,
	})
	return id, err
}

// DecideActivation approves, denies, or kills one.
func (k *Kernel) DecideActivation(ctx context.Context, actor, subject, id op.ID,
	verb op.ActivationVerb, reason string) error {
	_, err := k.prop.Propose(ctx, &op.ActivationAction{
		Header: k.header(actor), Subject: subject, ID: id, Verb: verb, Actor2: actor, Reason: reason,
	})
	return err
}

// Activations lists a subject's activations, newest first.
func (k *Kernel) Activations(ctx context.Context, subject op.ID) ([]Activation, error) {
	var out []Activation
	err := k.store.View(func(tx *store.Tx) error {
		var e error
		out, e = LoadActivations(tx, subject)
		return e
	})
	sort.Slice(out, func(i, j int) bool { return out[i].RequestedAt > out[j].RequestedAt })
	return out, err
}

// PendingActivations lists every request awaiting a decision, for an approver.
func (k *Kernel) PendingActivations(ctx context.Context) ([]Activation, error) {
	var out []Activation
	err := k.store.View(func(tx *store.Tx) error {
		return tx.ScanPrefix(store.BucketActivation, "", func(_ string, val []byte) bool {
			var a Activation
			if json.Unmarshal(val, &a) == nil && a.State == ActivationPending {
				out = append(out, a)
			}
			return true
		})
	})
	sort.Slice(out, func(i, j int) bool { return out[i].RequestedAt < out[j].RequestedAt })
	return out, err
}
