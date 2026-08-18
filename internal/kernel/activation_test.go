package kernel

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mcarey42/signet/internal/op"
	"github.com/mcarey42/signet/internal/store"
)

// Each test here names a way privileged-access systems actually fail. The
// mechanism is only worth its complexity if these hold.

const (
	alice = op.ID("alice")
	bob   = op.ID("bob")
	carol = op.ID("carol")
)

// bindPAM writes a binding directly, bypassing the grantor check — these tests
// are about activation semantics, not about who may grant.
func bindPAM(t *testing.T, tx *store.Tx, b Binding) op.ID {
	t.Helper()
	if b.ID == "" {
		b.ID = op.ID("b-" + b.Role + "-" + string(b.Subject))
	}
	blob, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Put(store.BucketBindings, bindingKey(b.Subject, b.ID), blob); err != nil {
		t.Fatal(err)
	}
	return b.ID
}

func requestAct(tx *store.Tx, subject, binding op.ID, at int64, forSec int64, amr []string, authTime int64) op.Result {
	return applyRequestActivation(tx, &op.RequestActivation{
		Header: op.Header{Actor: subject, AtSec: at}, ID: op.ID("act-1"),
		Subject: subject, Binding: binding, Reason: "incident 42", ForSeconds: forSec,
		SessionAMR: amr, SessionAuthTime: authTime,
	})
}

func decide(tx *store.Tx, actor, subject, id op.ID, v op.ActivationVerb, at int64) op.Result {
	return applyActivationAction(tx, &op.ActivationAction{
		Header: op.Header{Actor: actor, AtSec: at}, Subject: subject, ID: id, Verb: v, Actor2: actor,
	})
}

func withTx(t *testing.T, fn func(tx *store.Tx)) {
	t.Helper()
	s := newStoreWithRoot(t, newRootKey(t, newSeal(t)))
	if err := s.Update(1, 1, func(tx *store.Tx) error {
		fn(tx)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// The whole point: eligibility must not confer authority.
func TestEligibilityIsNotPossession(t *testing.T) {
	withTx(t, func(tx *store.Tx) {
		id := bindPAM(t, tx, Binding{Subject: alice, Role: "kv-admin", Scope: "/secrets",
			ActivationRequired: true})

		ok, err := HasAuthority(tx, alice, VerbWrite, "/secrets/app", 1000)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Fatal("an un-activated binding granted authority: eligibility is being treated as possession")
		}

		if res := requestAct(tx, alice, id, 1000, 3600, nil, 1000); res.Err != nil {
			t.Fatal(res.Err)
		}
		ok, err = HasAuthority(tx, alice, VerbWrite, "/secrets/app", 1000)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatal("an active activation did not confer the authority")
		}

		// And it stops on its own, with nothing to revoke.
		ok, err = HasAuthority(tx, alice, VerbWrite, "/secrets/app", 1000+3601)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Fatal("authority outlived its activation")
		}
	})
}

// A binding held outright is unaffected by any of this.
func TestOrdinaryBindingStillWorks(t *testing.T) {
	withTx(t, func(tx *store.Tx) {
		bindPAM(t, tx, Binding{Subject: bob, Role: "kv-admin", Scope: "/secrets"})
		ok, err := HasAuthority(tx, bob, VerbWrite, "/secrets/app", 1000)
		if err != nil || !ok {
			t.Fatalf("a plain binding should grant authority: ok=%v err=%v", ok, err)
		}
	})
}

// JIT-on-JIT: an activation may not outlive the eligibility it draws on.
// Without this you get "eligible until Friday, activated Thursday 23:59 for
// four hours" — a time-bound grant that quietly isn't.
func TestActivationCannotOutliveItsEligibility(t *testing.T) {
	withTx(t, func(tx *store.Tx) {
		id := bindPAM(t, tx, Binding{Subject: alice, Role: "kv-admin", Scope: "/secrets",
			ActivationRequired: true, NotAfter: 1500})

		if res := requestAct(tx, alice, id, 1000, 100000, nil, 1000); res.Err != nil {
			t.Fatal(res.Err)
		}
		a, err := loadActivation(tx, alice, "act-1")
		if err != nil {
			t.Fatal(err)
		}
		if a.Expiry != 1500 {
			t.Fatalf("activation expiry should be clamped to the binding's 1500, got %d", a.Expiry)
		}
		ok, _ := HasAuthority(tx, alice, VerbWrite, "/secrets/app", 1501)
		if ok {
			t.Fatal("authority survived past the eligibility that granted it")
		}
	})
}

// A request for longer than policy allows is clamped, not honored.
func TestRequestedDurationIsClamped(t *testing.T) {
	withTx(t, func(tx *store.Tx) {
		id := bindPAM(t, tx, Binding{Subject: alice, Role: "kv-admin", Scope: "/secrets",
			ActivationRequired: true, MaxActivationSec: 600})
		if res := requestAct(tx, alice, id, 1000, 86400, nil, 1000); res.Err != nil {
			t.Fatal(res.Err)
		}
		a, _ := loadActivation(tx, alice, "act-1")
		if a.Expiry != 1600 {
			t.Fatalf("expected clamping to 600s (expiry 1600), got %d", a.Expiry)
		}
	})
}

// Approval means somebody else's approval. This is the single most important
// check in the whole mechanism.
func TestNobodyApprovesTheirOwnRequest(t *testing.T) {
	withTx(t, func(tx *store.Tx) {
		// alice is eligible, and is also a domain admin — she has every right
		// to approve activations in general, just not this one.
		bindPAM(t, tx, Binding{ID: "b-admin", Subject: alice, Role: "domain-admin", Scope: "/"})
		id := bindPAM(t, tx, Binding{ID: "b-pam", Subject: alice, Role: "kv-admin",
			Scope: "/secrets", ActivationRequired: true, ApprovalRequired: true})

		if res := requestAct(tx, alice, id, 1000, 3600, nil, 1000); res.Err != nil {
			t.Fatal(res.Err)
		}
		res := decide(tx, alice, alice, "act-1", op.ActivationApprove, 1010)
		if res.Err == nil {
			t.Fatal("a principal approved their own activation request")
		}
		if !strings.Contains(res.Err.Error(), "Separation of duties") {
			t.Fatalf("unhelpful refusal: %v", res.Err)
		}
		// Assert on the activation itself rather than on HasAuthority: alice
		// legitimately holds write here through her domain-admin binding, and
		// the property under test is that the ACTIVATION did not take effect.
		a, err := loadActivation(tx, alice, "act-1")
		if err != nil {
			t.Fatal(err)
		}
		if a.State != ActivationPending {
			t.Fatalf("a self-approval moved the activation to %s", a.State)
		}
		if len(a.Approvals) != 0 {
			t.Fatalf("a self-approval was counted: %v", a.Approvals)
		}
	})
}

// A pending request confers nothing until decided.
func TestPendingRequestConfersNothing(t *testing.T) {
	withTx(t, func(tx *store.Tx) {
		id := bindPAM(t, tx, Binding{Subject: alice, Role: "kv-admin", Scope: "/secrets",
			ActivationRequired: true, ApprovalRequired: true})
		if res := requestAct(tx, alice, id, 1000, 3600, nil, 1000); res.Err != nil {
			t.Fatal(res.Err)
		}
		a, _ := loadActivation(tx, alice, "act-1")
		if a.State != ActivationPending {
			t.Fatalf("expected pending, got %s", a.State)
		}
		if ok, _ := HasAuthority(tx, alice, VerbWrite, "/secrets/app", 1000); ok {
			t.Fatal("a request awaiting approval already conferred authority")
		}
	})
}

// The approver must be able to confer what is being conferred: approving is a
// form of granting, and granting only narrows.
func TestApproverNeedsAuthorityAtTheScope(t *testing.T) {
	withTx(t, func(tx *store.Tx) {
		id := bindPAM(t, tx, Binding{ID: "b-pam", Subject: alice, Role: "kv-admin",
			Scope: "/secrets", ActivationRequired: true, ApprovalRequired: true})
		// bob has admin somewhere else entirely.
		bindPAM(t, tx, Binding{ID: "b-bob", Subject: bob, Role: "domain-admin", Scope: "/clusters"})

		if res := requestAct(tx, alice, id, 1000, 3600, nil, 1000); res.Err != nil {
			t.Fatal(res.Err)
		}
		res := decide(tx, bob, alice, "act-1", op.ActivationApprove, 1010)
		if res.Err == nil {
			t.Fatal("a principal with no authority at the scope approved an activation there")
		}

		// carol, who does have it, can.
		bindPAM(t, tx, Binding{ID: "b-carol", Subject: carol, Role: "domain-admin", Scope: "/"})
		if res := decide(tx, carol, alice, "act-1", op.ActivationApprove, 1020); res.Err != nil {
			t.Fatalf("a properly-authorized approver was refused: %v", res.Err)
		}
		if ok, _ := HasAuthority(tx, alice, VerbWrite, "/secrets/app", 1030); !ok {
			t.Fatal("an approved activation did not confer authority")
		}
	})
}

// Approval re-validates eligibility at grant time, not request time. Otherwise
// a pending queue becomes a way to outlive a revocation.
func TestApprovalRechecksEligibilityAtGrantTime(t *testing.T) {
	withTx(t, func(tx *store.Tx) {
		id := bindPAM(t, tx, Binding{ID: "b-pam", Subject: alice, Role: "kv-admin",
			Scope: "/secrets", ActivationRequired: true, ApprovalRequired: true, NotAfter: 2000})
		bindPAM(t, tx, Binding{ID: "b-carol", Subject: carol, Role: "domain-admin", Scope: "/"})

		if res := requestAct(tx, alice, id, 1000, 3600, nil, 1000); res.Err != nil {
			t.Fatal(res.Err)
		}
		// Eligibility lapses while the request sits in the queue.
		res := decide(tx, carol, alice, "act-1", op.ActivationApprove, 2001)
		if res.Err == nil {
			t.Fatal("approval granted an authority whose eligibility had expired")
		}
		a, _ := loadActivation(tx, alice, "act-1")
		if a.State != ActivationDenied {
			t.Fatalf("the request should be recorded as denied, got %s", a.State)
		}
		if !strings.Contains(a.KillReason, "expired") {
			t.Fatalf("the record should say why: %q", a.KillReason)
		}
	})
}

// Removing eligibility entirely, mid-queue, has the same effect.
func TestApprovalFailsIfBindingRemovedWhilePending(t *testing.T) {
	withTx(t, func(tx *store.Tx) {
		id := bindPAM(t, tx, Binding{ID: "b-pam", Subject: alice, Role: "kv-admin",
			Scope: "/secrets", ActivationRequired: true, ApprovalRequired: true})
		bindPAM(t, tx, Binding{ID: "b-carol", Subject: carol, Role: "domain-admin", Scope: "/"})
		if res := requestAct(tx, alice, id, 1000, 3600, nil, 1000); res.Err != nil {
			t.Fatal(res.Err)
		}
		if err := tx.Delete(store.BucketBindings, bindingKey(alice, id)); err != nil {
			t.Fatal(err)
		}
		res := decide(tx, carol, alice, "act-1", op.ActivationApprove, 1010)
		if res.Err == nil {
			t.Fatal("approval granted an authority that no longer existed")
		}
	})
}

// Killing an activation ends the access immediately, without touching the
// binding: the eligibility survives, the possession does not.
func TestKillEndsAccessButNotEligibility(t *testing.T) {
	withTx(t, func(tx *store.Tx) {
		id := bindPAM(t, tx, Binding{Subject: alice, Role: "kv-admin", Scope: "/secrets",
			ActivationRequired: true})
		bindPAM(t, tx, Binding{ID: "b-carol", Subject: carol, Role: "domain-admin", Scope: "/"})
		if res := requestAct(tx, alice, id, 1000, 3600, nil, 1000); res.Err != nil {
			t.Fatal(res.Err)
		}
		if ok, _ := HasAuthority(tx, alice, VerbWrite, "/secrets/app", 1010); !ok {
			t.Fatal("precondition: should be active")
		}
		if res := decide(tx, carol, alice, "act-1", op.ActivationKill, 1020); res.Err != nil {
			t.Fatal(res.Err)
		}
		if ok, _ := HasAuthority(tx, alice, VerbWrite, "/secrets/app", 1030); ok {
			t.Fatal("a killed activation still conferred authority")
		}
		// The binding is untouched: alice may ask again.
		if res := applyRequestActivation(tx, &op.RequestActivation{
			Header: op.Header{Actor: alice, AtSec: 1040}, ID: op.ID("act-2"),
			Subject: alice, Binding: id, Reason: "second incident",
		}); res.Err != nil {
			t.Fatalf("eligibility should survive a kill: %v", res.Err)
		}
	})
}

// Windows may not be stacked: one live activation per binding.
func TestActivationsCannotBeStacked(t *testing.T) {
	withTx(t, func(tx *store.Tx) {
		id := bindPAM(t, tx, Binding{Subject: alice, Role: "kv-admin", Scope: "/secrets",
			ActivationRequired: true})
		if res := requestAct(tx, alice, id, 1000, 3600, nil, 1000); res.Err != nil {
			t.Fatal(res.Err)
		}
		res := applyRequestActivation(tx, &op.RequestActivation{
			Header: op.Header{Actor: alice, AtSec: 1100}, ID: op.ID("act-2"),
			Subject: alice, Binding: id, Reason: "again",
		})
		if res.Err == nil {
			t.Fatal("a second activation was stacked on a live one")
		}
	})
}

// Step-up: the factor used to open the session does not count twice.
func TestStepUpIsRequiredAndMustBeRecent(t *testing.T) {
	withTx(t, func(tx *store.Tx) {
		id := bindPAM(t, tx, Binding{Subject: alice, Role: "kv-admin", Scope: "/secrets",
			ActivationRequired: true, StepUpAMR: []string{"hwk"}, StepUpMaxAgeSec: 300})

		// Wrong factor.
		res := requestAct(tx, alice, id, 1000, 3600, []string{"pwd"}, 1000)
		if res.Err == nil {
			t.Fatal("activation succeeded without the required step-up factor")
		}
		// Right factor, but the authentication is stale.
		res = requestAct(tx, alice, id, 2000, 3600, []string{"pwd", "hwk"}, 1000)
		if res.Err == nil {
			t.Fatal("activation succeeded on a stale authentication")
		}
		if !strings.Contains(res.Err.Error(), "Re-authenticate") {
			t.Fatalf("the refusal should say what to do: %v", res.Err)
		}
		// Right factor, fresh.
		if res := requestAct(tx, alice, id, 1100, 3600, []string{"pwd", "hwk"}, 1000); res.Err != nil {
			t.Fatalf("a fresh step-up should be accepted: %v", res.Err)
		}
	})
}

// Activating something already held outright is refused rather than silently
// accepted: it would imply the authority was not already in force.
func TestActivatingAHeldBindingIsRefused(t *testing.T) {
	withTx(t, func(tx *store.Tx) {
		id := bindPAM(t, tx, Binding{Subject: alice, Role: "kv-admin", Scope: "/secrets"})
		res := requestAct(tx, alice, id, 1000, 3600, nil, 1000)
		if res.Err == nil {
			t.Fatal("activation of a plainly-held binding was accepted")
		}
	})
}

// You cannot activate an authority you were never eligible for.
func TestCannotActivateAnAuthorityYouDoNotHave(t *testing.T) {
	withTx(t, func(tx *store.Tx) {
		res := requestAct(tx, alice, op.ID("no-such-binding"), 1000, 3600, nil, 1000)
		if res.Err == nil {
			t.Fatal("an activation was created for a binding that does not exist")
		}
	})
}

// Two approvals from the same principal are not two approvers.
func TestSameApproverCannotCountTwice(t *testing.T) {
	withTx(t, func(tx *store.Tx) {
		id := bindPAM(t, tx, Binding{ID: "b-pam", Subject: alice, Role: "kv-admin",
			Scope: "/secrets", ActivationRequired: true, ApprovalRequired: true, MinApprovers: 2})
		bindPAM(t, tx, Binding{ID: "b-carol", Subject: carol, Role: "domain-admin", Scope: "/"})
		bindPAM(t, tx, Binding{ID: "b-bob", Subject: bob, Role: "domain-admin", Scope: "/"})
		if res := requestAct(tx, alice, id, 1000, 3600, nil, 1000); res.Err != nil {
			t.Fatal(res.Err)
		}
		if res := decide(tx, carol, alice, "act-1", op.ActivationApprove, 1010); res.Err != nil {
			t.Fatal(res.Err)
		}
		if ok, _ := HasAuthority(tx, alice, VerbWrite, "/secrets/app", 1015); ok {
			t.Fatal("one approval satisfied a two-approver requirement")
		}
		if res := decide(tx, carol, alice, "act-1", op.ActivationApprove, 1020); res.Err == nil {
			t.Fatal("the same approver counted twice")
		}
		if res := decide(tx, bob, alice, "act-1", op.ActivationApprove, 1030); res.Err != nil {
			t.Fatal(res.Err)
		}
		if ok, _ := HasAuthority(tx, alice, VerbWrite, "/secrets/app", 1035); !ok {
			t.Fatal("two distinct approvals did not activate")
		}
	})
}

// Activation confers only what the binding says, at the scope it says.
func TestActivationDoesNotWidenScopeOrRole(t *testing.T) {
	withTx(t, func(tx *store.Tx) {
		id := bindPAM(t, tx, Binding{Subject: alice, Role: "kv-reader", Scope: "/secrets/app",
			ActivationRequired: true})
		if res := requestAct(tx, alice, id, 1000, 3600, nil, 1000); res.Err != nil {
			t.Fatal(res.Err)
		}
		if ok, _ := HasAuthority(tx, alice, VerbRead, "/secrets/app/x", 1010); !ok {
			t.Fatal("the granted authority is missing")
		}
		if ok, _ := HasAuthority(tx, alice, VerbWrite, "/secrets/app/x", 1010); ok {
			t.Fatal("activation widened the role")
		}
		if ok, _ := HasAuthority(tx, alice, VerbRead, "/secrets/other", 1010); ok {
			t.Fatal("activation widened the scope")
		}
	})
}
