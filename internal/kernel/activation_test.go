package kernel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"github.com/mcarey42/signet/internal/audit"
	"strings"
	"testing"
	"time"

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

// Ending someone else's activation is an administrative act.
//
// Regression: kill and deny performed NO authority check at all — only approve
// did — while the HTTP handler's comment claimed enforcement happened inside
// Apply. Any authenticated principal could therefore end anyone's elevated
// access, or refuse anyone's request: a denial of service against privileged
// access, at exactly the moment it is needed.
func TestKillAndDenyRequireAuthority(t *testing.T) {
	withTx(t, func(tx *store.Tx) {
		id := bindPAM(t, tx, Binding{ID: "b-pam", Subject: alice, Role: "kv-admin",
			Scope: "/secrets", ActivationRequired: true})
		// bob is authenticated but holds nothing anywhere.
		if res := requestAct(tx, alice, id, 1000, 3600, nil, 1000); res.Err != nil {
			t.Fatal(res.Err)
		}

		if res := decide(tx, bob, alice, "act-1", op.ActivationKill, 1010); res.Err == nil {
			t.Fatal("a principal with no authority killed another's activation")
		}
		if ok, _ := HasAuthority(tx, alice, VerbWrite, "/secrets/app", 1015); !ok {
			t.Fatal("the unauthorized kill took effect anyway")
		}

		// carol, who has admin at the scope, can.
		bindPAM(t, tx, Binding{ID: "b-carol", Subject: carol, Role: "domain-admin", Scope: "/"})
		if res := decide(tx, carol, alice, "act-1", op.ActivationKill, 1020); res.Err != nil {
			t.Fatalf("an authorized kill was refused: %v", res.Err)
		}
	})
}

// Denying a pending request needs the same authority as approving one.
func TestDenyRequiresAuthority(t *testing.T) {
	withTx(t, func(tx *store.Tx) {
		id := bindPAM(t, tx, Binding{ID: "b-pam", Subject: alice, Role: "kv-admin",
			Scope: "/secrets", ActivationRequired: true, ApprovalRequired: true})
		if res := requestAct(tx, alice, id, 1000, 3600, nil, 1000); res.Err != nil {
			t.Fatal(res.Err)
		}
		if res := decide(tx, bob, alice, "act-1", op.ActivationDeny, 1010); res.Err == nil {
			t.Fatal("a principal with no authority denied another's request")
		}
		a, _ := loadActivation(tx, alice, "act-1")
		if a.State != ActivationPending {
			t.Fatalf("the unauthorized denial took effect: %s", a.State)
		}
	})
}

// A principal may always give up their own elevated access. Making that hard
// would only discourage people from doing it.
func TestPrincipalMayAlwaysKillTheirOwnActivation(t *testing.T) {
	withTx(t, func(tx *store.Tx) {
		id := bindPAM(t, tx, Binding{ID: "b-pam", Subject: alice, Role: "kv-admin",
			Scope: "/secrets", ActivationRequired: true})
		if res := requestAct(tx, alice, id, 1000, 3600, nil, 1000); res.Err != nil {
			t.Fatal(res.Err)
		}
		if res := decide(tx, alice, alice, "act-1", op.ActivationKill, 1010); res.Err != nil {
			t.Fatalf("alice could not stand down her own activation: %v", res.Err)
		}
		if ok, _ := HasAuthority(tx, alice, VerbWrite, "/secrets/app", 1020); ok {
			t.Fatal("access survived the principal's own kill")
		}
	})
}

// PAM must hold for OFFLINE credentials too, which is where it matters most.
//
// filterRoles decides which roles get embedded in a JWT or SSH certificate.
// It checked NotAfter, scope, tier and AMR — but not ActivationRequired. So a
// principal merely ELIGIBLE for a role got that role baked into a bearer
// credential with no live activation, while the online path correctly denied
// the same authority. The bypass landed on exactly the credential class no
// relying party re-checks with us.
func TestOfflineCredentialsRespectActivation(t *testing.T) {
	withTx(t, func(tx *store.Tx) {
		id := bindPAM(t, tx, Binding{ID: "b-pam", Subject: alice, Role: "kv-admin",
			Scope: "/secrets", ActivationRequired: true})
		s := Session{Principal: alice, Expiry: 0}
		req := IssueRequest{Scope: "/secrets/app", TTL: 15 * time.Minute}
		now := time.Unix(1000, 0)

		// Eligible only: the role must not be embeddable.
		roles, _, err := (&Kernel{}).filterRoles(tx, s, req, now)
		if err != nil {
			t.Fatal(err)
		}
		if len(roles) != 0 {
			t.Fatalf("an un-activated PAM role was embedded in an offline credential: %v", roles)
		}

		// Activated: now it may be carried.
		if res := requestAct(tx, alice, id, 1000, 600, nil, 1000); res.Err != nil {
			t.Fatal(res.Err)
		}
		roles, ttl, err := (&Kernel{}).filterRoles(tx, s, req, now)
		if err != nil {
			t.Fatal(err)
		}
		if len(roles) != 1 || roles[0] != "kv-admin" {
			t.Fatalf("an active PAM role should be carried, got %v", roles)
		}

		// And the credential must not outlive the elevation. A 15-minute token
		// minted against a 10-minute window would carry the elevated role for
		// five minutes after the elevation ended, with nobody to ask.
		if ttl > 600*time.Second {
			t.Fatalf("credential TTL %s outlives the activation window (600s)", ttl)
		}

		// Once killed, it stops being embeddable again.
		bindPAM(t, tx, Binding{ID: "b-carol", Subject: carol, Role: "domain-admin", Scope: "/"})
		if res := decide(tx, carol, alice, "act-1", op.ActivationKill, 1100); res.Err != nil {
			t.Fatal(res.Err)
		}
		roles, _, err = (&Kernel{}).filterRoles(tx, s, req, time.Unix(1100, 0))
		if err != nil {
			t.Fatal(err)
		}
		if len(roles) != 0 {
			t.Fatalf("a killed activation still yielded an offline role: %v", roles)
		}
	})
}

// Revoking a session is self-service or an administrative act, never a free
// action against anyone whose token hash you happen to know.
func TestRevokeSessionRequiresAuthority(t *testing.T) {
	withTx(t, func(tx *store.Tx) {
		sess := Session{ID: "s1", TokenHash: "hash-1", Principal: alice, Expiry: 1 << 40}
		blob, _ := jsonMarshalB(sess)
		if err := tx.Put(store.BucketSessions, "hash-1", blob); err != nil {
			t.Fatal(err)
		}

		// bob holds nothing and must not be able to cut alice off.
		res := applyRevokeSession(tx, &op.RevokeSession{
			Header: op.Header{Actor: bob, AtSec: 1000}, TokenHash: "hash-1"})
		if res.Err == nil {
			t.Fatal("an unrelated principal revoked another's session")
		}
		if _, ok, _ := tx.Get(store.BucketSessions, "hash-1"); !ok {
			t.Fatal("the session was deleted despite the refusal")
		}

		// alice may always revoke her own, and the record says whose it was.
		res = applyRevokeSession(tx, &op.RevokeSession{
			Header: op.Header{Actor: alice, AtSec: 1000}, TokenHash: "hash-1"})
		if res.Err != nil {
			t.Fatalf("a principal could not revoke their own session: %v", res.Err)
		}
		if res.Subject != string(alice) {
			t.Fatalf("the revocation is unattributable: subject = %q", res.Subject)
		}

		// Revoking again is idempotent rather than an error, and does not
		// reveal whether the hash was ever live.
		if res := applyRevokeSession(tx, &op.RevokeSession{
			Header: op.Header{Actor: bob, AtSec: 1000}, TokenHash: "hash-1"}); res.Err != nil {
			t.Fatalf("a repeated revocation should be idempotent: %v", res.Err)
		}
	})
}

// An audit record must distinguish the most serious grant in the system from
// the most trivial one.
func TestBindingAuditRecordNamesRoleAndRecipient(t *testing.T) {
	admin, _ := NewAuditRecord(1, 1, &op.PutBinding{
		Header:  op.Header{Actor: alice, AtSec: 1000},
		Subject: bob, Role: "domain-admin", Scope: "/",
	}, op.Result{})
	reader, _ := NewAuditRecord(1, 1, &op.PutBinding{
		Header:  op.Header{Actor: alice, AtSec: 1000},
		Subject: bob, Role: "kv-reader", Scope: "/",
	}, op.Result{})

	if string(admin) == string(reader) {
		t.Fatal("granting domain-admin at / is indistinguishable from kv-reader at / in the audit log")
	}
	for _, want := range []string{"domain-admin", string(bob)} {
		if !strings.Contains(string(admin), want) {
			t.Fatalf("the record should name %q: %s", want, admin)
		}
	}
}

// Witnessing a domain for the first time is administrative.
//
// Any principal with write authority could self-sign a checkpoint for ANY
// domain name using their own key, have it pinned, and permanently lock out the
// real domain — the witness would thereafter refuse the genuine article as a
// key change. Pinning decides who this node believes for a name; that is not a
// routine write.
func TestEstablishingANewWitnessedDomainNeedsAdmin(t *testing.T) {
	withTx(t, func(tx *store.Tx) {
		key, cp, entries, pub := testCheckpoint(t, "victim.example.net", 3)

		// bob can write but is not an admin.
		bindPAM(t, tx, Binding{ID: "b-bob", Subject: bob, Role: "kv-writer", Scope: "/"})
		res := applyPutWitness(tx, &op.PutWitness{
			Header:     op.Header{Actor: bob, AtSec: 1000},
			Checkpoint: cp, Entries: entries, PubKeyPEM: pub, Grantor: bob,
		})
		if res.Err == nil {
			t.Fatal("a non-admin pinned a key for a domain this node had never seen")
		}
		if !strings.Contains(res.Err.Error(), "admin authority at /") {
			t.Fatalf("unhelpful refusal: %v", res.Err)
		}
		if _, ok, _ := tx.Get(store.BucketWitness, "victim.example.net"); ok {
			t.Fatal("a record was written despite the refusal")
		}

		// carol, an admin, may establish it.
		bindPAM(t, tx, Binding{ID: "b-carol", Subject: carol, Role: "domain-admin", Scope: "/"})
		res = applyPutWitness(tx, &op.PutWitness{
			Header:     op.Header{Actor: carol, AtSec: 1000},
			Checkpoint: cp, Entries: entries, PubKeyPEM: pub, Grantor: carol,
		})
		if res.Err != nil {
			t.Fatalf("an admin should be able to establish a witnessed domain: %v", res.Err)
		}

		// And once established, an ordinary writer may extend it.
		cp2, ents2 := testExtension(t, key, "victim.example.net", 3, 2)
		if res := applyPutWitness(tx, &op.PutWitness{
			Header:     op.Header{Actor: bob, AtSec: 1100},
			Checkpoint: cp2, Entries: ents2, PubKeyPEM: pub, Grantor: bob,
		}); res.Err != nil {
			t.Fatalf("extending an established record should not need admin: %v", res.Err)
		}
	})
}

// A stored conflict is the evidence the mechanism exists to hold, so nothing
// may overwrite it — including a later witnessing that would otherwise succeed.
func TestAStoredConflictCannotBeOverwritten(t *testing.T) {
	withTx(t, func(tx *store.Tx) {
		bindPAM(t, tx, Binding{ID: "b-carol", Subject: carol, Role: "domain-admin", Scope: "/"})
		key, cp, entries, pub := testCheckpoint(t, "home.example.net", 3)
		if res := applyPutWitness(tx, &op.PutWitness{
			Header:     op.Header{Actor: carol, AtSec: 1000},
			Checkpoint: cp, Entries: entries, PubKeyPEM: pub, Grantor: carol,
		}); res.Err != nil {
			t.Fatal(res.Err)
		}

		// A forked history at the same count: different head, same number.
		_, forkedCP, _, _ := testCheckpointWithKey(t, key, "home.example.net", 3, "forked")
		res := applyPutWitness(tx, &op.PutWitness{
			Header:     op.Header{Actor: carol, AtSec: 1100},
			Checkpoint: forkedCP, PubKeyPEM: pub, Grantor: carol,
		})
		if res.Err == nil {
			t.Fatal("a rewritten history was accepted")
		}
		raw, _, _ := tx.Get(store.BucketWitness, "home.example.net")
		if !strings.Contains(string(raw), "conflict") {
			t.Fatalf("the conflict was not persisted: %s", raw)
		}

		// A subsequent, otherwise-valid witnessing must not clear it.
		if res := applyPutWitness(tx, &op.PutWitness{
			Header:     op.Header{Actor: carol, AtSec: 1200},
			Checkpoint: cp, Entries: entries, PubKeyPEM: pub, Grantor: carol,
		}); res.Err == nil {
			t.Fatal("a later witnessing cleared a stored conflict")
		}
		raw, _, _ = tx.Get(store.BucketWitness, "home.example.net")
		if !strings.Contains(string(raw), "conflict") {
			t.Fatal("the conflict was erased by a later call")
		}
	})
}

// --- witness test helpers -------------------------------------------------

func testKeyPair(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// testCheckpoint builds a fresh chain of n entries and a signed checkpoint over
// it, returning the signing key, the checkpoint, the entries, and the key PEM.
func testCheckpoint(t *testing.T, domain string, n int) (*ecdsa.PrivateKey, []byte, []byte, string) {
	t.Helper()
	key := testKeyPair(t)
	cp, ents, pub := buildCheckpoint(t, key, domain, store.GenesisHead(), 0, n, "real")
	return key, cp, ents, pub
}

func testCheckpointWithKey(t *testing.T, key *ecdsa.PrivateKey, domain string, n int, tag string) (*ecdsa.PrivateKey, []byte, []byte, string) {
	t.Helper()
	cp, ents, pub := buildCheckpoint(t, key, domain, store.GenesisHead(), 0, n, tag)
	return key, cp, ents, pub
}

func testExtension(t *testing.T, key *ecdsa.PrivateKey, domain string, from, n int) ([]byte, []byte) {
	t.Helper()
	head := store.GenesisHead()
	for i := 1; i <= from; i++ {
		rec, _ := jsonMarshalB(map[string]any{"kind": "PutSecret", "tag": "real", "i": i})
		head = store.ChainHash(head, rec)
	}
	cp, ents, _ := buildCheckpoint(t, key, domain, head, uint64(from), n, "real")
	return cp, ents
}

func buildCheckpoint(t *testing.T, key *ecdsa.PrivateKey, domain, head string,
	from uint64, n int, tag string) (cpJSON, entsJSON []byte, pubPEM string) {
	t.Helper()
	var ents []store.AuditEntry
	seq := from
	for i := 1; i <= n; i++ {
		seq++
		rec, _ := jsonMarshalB(map[string]any{"kind": "PutSecret", "tag": tag, "i": int(seq)})
		h := store.ChainHash(head, rec)
		ents = append(ents, store.AuditEntry{Seq: seq, Prev: head, Hash: h, Record: rec})
		head = h
	}
	signed, err := audit.Sign(&audit.Checkpoint{
		Domain: domain, Count: seq, Head: head, AtSec: 1000}, "kid", key)
	if err != nil {
		t.Fatal(err)
	}
	cpJSON, _ = jsonMarshalB(signed)
	entsJSON, _ = jsonMarshalB(ents)
	pem, err := encodePublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return cpJSON, entsJSON, pem
}

// A grant may not outlive the authority it was made under.
//
// PE-02: nothing clamped a new binding's expiry to the grantor's own, so a
// time-bounded admin could mint an UNBOUNDED copy before expiring — laundering
// a temporary grant into a permanent one.
func TestGrantCannotOutliveTheGrantorsAuthority(t *testing.T) {
	withTx(t, func(tx *store.Tx) {
		// bob must exist as a principal, or every grant below is refused for
		// that reason instead of the one under test.
		mustPutPrincipal(t, tx, string(bob), "/people/bob", "")
		bindPAM(t, tx, Binding{ID: "b-root", Subject: carol, Role: "domain-admin", Scope: "/"})
		// alice is admin at /secrets, but only until 2000.
		bindPAM(t, tx, Binding{ID: "b-alice", Subject: alice, Role: "domain-admin",
			Scope: "/secrets", NotAfter: 2000})

		// An unbounded grant is refused.
		res := applyPutBinding(tx, &op.PutBinding{
			Header: op.Header{Actor: alice, AtSec: 1000}, ID: "new-1",
			Subject: bob, Role: "kv-admin", Scope: "/secrets", Grantor: alice,
		})
		if res.Err == nil {
			t.Fatal("a time-bounded admin minted an unbounded binding")
		}
		// So is one that reaches past the grantor's own expiry.
		res = applyPutBinding(tx, &op.PutBinding{
			Header: op.Header{Actor: alice, AtSec: 1000}, ID: "new-2",
			Subject: bob, Role: "kv-admin", Scope: "/secrets", Grantor: alice, NotAfter: 9999,
		})
		if res.Err == nil {
			t.Fatal("a grant outlived the authority behind it")
		}
		// Within the horizon is fine.
		if res := applyPutBinding(tx, &op.PutBinding{
			Header: op.Header{Actor: alice, AtSec: 1000}, ID: "new-3",
			Subject: bob, Role: "kv-admin", Scope: "/secrets", Grantor: alice, NotAfter: 1500,
		}); res.Err != nil {
			t.Fatalf("a grant inside the grantor's horizon should be allowed: %v", res.Err)
		}
		// And an unbounded admin may still grant without limit.
		if res := applyPutBinding(tx, &op.PutBinding{
			Header: op.Header{Actor: carol, AtSec: 1000}, ID: "new-4",
			Subject: bob, Role: "kv-admin", Scope: "/secrets", Grantor: carol,
		}); res.Err != nil {
			t.Fatalf("an unbounded admin should grant without limit: %v", res.Err)
		}
	})
}

// PE-04: an admin holding its authority only through a live activation must not
// be able to mint a STANDING binding, which would make the elevation permanent
// and falsify "kill ends the access, nothing to sweep".
func TestActivatedAdminCannotMakeItsElevationPermanent(t *testing.T) {
	withTx(t, func(tx *store.Tx) {
		// Only the first principal in an empty domain may be grantorless.
		mustPutPrincipal(t, tx, string(bob), "/people/bob", "")
		bindPAM(t, tx, Binding{ID: "b-boot", Subject: bob, Role: "domain-admin", Scope: "/"})
		mustPutPrincipal(t, tx, string(alice), "/people/alice", bob)
		id := bindPAM(t, tx, Binding{ID: "b-pam", Subject: alice, Role: "domain-admin",
			Scope: "/secrets", ActivationRequired: true, MaxActivationSec: 600})
		if res := requestAct(tx, alice, id, 1000, 600, nil, 1000); res.Err != nil {
			t.Fatal(res.Err)
		}
		if ok, _ := HasAuthority(tx, alice, VerbAdmin, "/secrets", 1010); !ok {
			t.Fatal("precondition: the activation should confer admin")
		}

		res := applyPutBinding(tx, &op.PutBinding{
			Header: op.Header{Actor: alice, AtSec: 1010}, ID: "standing",
			Subject: alice, Role: "kv-admin", Scope: "/secrets", Grantor: alice,
		})
		if res.Err == nil {
			t.Fatal("an activated admin minted a standing binding, outliving its own window")
		}
		// A grant inside the window is still permitted.
		if res := applyPutBinding(tx, &op.PutBinding{
			Header: op.Header{Actor: alice, AtSec: 1010}, ID: "inside",
			Subject: bob, Role: "kv-reader", Scope: "/secrets", Grantor: alice, NotAfter: 1500,
		}); res.Err != nil {
			t.Fatalf("a grant inside the activation window should be allowed: %v", res.Err)
		}
	})
}

// PE-03: a principal may not be re-homed, and creating one is authorized.
//
// Authority travels with the stable ID via bindings, while delegation-narrows
// is checked against the mutable path — so moving a principal let a subtree
// admin drag a superior into their own subtree and then pass the narrowing
// check against it, carrying all its authority along.
func TestPrincipalsCannotBeRehomedOrCreatedUnauthorized(t *testing.T) {
	withTx(t, func(tx *store.Tx) {
		mustPutPrincipal(t, tx, "root", "/people/root", "")
		bindPAM(t, tx, Binding{ID: "b-root", Subject: "root", Role: "domain-admin", Scope: "/"})
		bindPAM(t, tx, Binding{ID: "b-sub", Subject: alice, Role: "domain-admin", Scope: "/clusters/lab"})

		// alice cannot drag root into her subtree.
		res := applyPutPrincipal(tx, &op.PutPrincipal{
			Header: op.Header{Actor: alice, AtSec: 1000},
			ID:     "root", Path: "/clusters/lab/people/root", Type: "human", Grantor: alice,
		})
		if res.Err == nil {
			t.Fatal("a subtree admin re-homed a superior principal into its own subtree")
		}
		if !strings.Contains(res.Err.Error(), "may not be moved") {
			t.Fatalf("unhelpful refusal: %v", res.Err)
		}

		// Nor create one outside her scope.
		res = applyPutPrincipal(tx, &op.PutPrincipal{
			Header: op.Header{Actor: alice, AtSec: 1000},
			ID:     "newguy", Path: "/people/newguy", Type: "human", Grantor: alice,
		})
		if res.Err == nil {
			t.Fatal("a subtree admin created a principal outside its scope")
		}

		// Inside her scope she may.
		if res := applyPutPrincipal(tx, &op.PutPrincipal{
			Header: op.Header{Actor: alice, AtSec: 1000},
			ID:     "labguy", Path: "/clusters/lab/people/labguy", Type: "human", Grantor: alice,
		}); res.Err != nil {
			t.Fatalf("a subtree admin should create inside its own scope: %v", res.Err)
		}
	})
}

func mustPutPrincipal(t *testing.T, tx *store.Tx, id, path string, grantor op.ID) {
	t.Helper()
	if res := applyPutPrincipal(tx, &op.PutPrincipal{
		Header: op.Header{Actor: grantor, AtSec: 1000},
		ID:     op.ID(id), Path: path, Type: "human", Grantor: grantor,
	}); res.Err != nil {
		t.Fatal(res.Err)
	}
}

// A mapping hands out everything the target can do, so the grantor must be
// able to confer all of it — not merely control where the target lives.
//
// PE-05, the same path-versus-ID seam as PE-03: bindings attach to the stable
// ID and their scopes are unrelated to the principal's place in the tree, so a
// subtree admin could map onto a principal that happens to live in their
// subtree while holding authority far outside it.
func TestMappingChecksWhatTheTargetCanDoNotWhereItLives(t *testing.T) {
	withTx(t, func(tx *store.Tx) {
		mustPutPrincipal(t, tx, "root", "/people/root", "")
		bindPAM(t, tx, Binding{ID: "b-root", Subject: "root", Role: "domain-admin", Scope: "/"})
		// An issuer must exist, or every mapping below is refused for THAT
		// reason and the assertions would pass without testing anything.
		if res := applyPutIssuer(tx, &op.PutIssuer{
			Header: op.Header{Actor: "root", AtSec: 1000}, ID: "iss1", Name: "kind",
			Verifier: "k8s-sa", URL: "https://k8s.example", Audience: "signet",
			JWKS:    []byte(`{"keys":[{"kty":"RSA","kid":"k","n":"AQAB","e":"AQAB"}]}`),
			Grantor: "root",
		}); res.Err != nil {
			t.Fatal(res.Err)
		}
		// alice administers one subtree.
		bindPAM(t, tx, Binding{ID: "b-alice", Subject: alice, Role: "domain-admin",
			Scope: "/clusters/lab"})
		// A principal that LIVES in alice's subtree but holds authority outside it.
		mustPutPrincipal(t, tx, "runner", "/clusters/lab/apps/runner", "root")
		bindPAM(t, tx, Binding{ID: "b-runner", Subject: "runner", Role: "kv-admin",
			Scope: "/secrets/production"})

		res := applyPutMapping(tx, &op.PutMapping{
			Header: op.Header{Actor: alice, AtSec: 1000}, ID: "m1", Name: "ci",
			Issuer: "kind", Namespaces: []string{"ci"}, ServiceAccounts: []string{"runner"},
			Principal: "runner", Grantor: alice,
		})
		if res.Err == nil {
			t.Fatal("a subtree admin mapped onto a principal holding authority outside that subtree")
		}
		if !strings.Contains(res.Err.Error(), "cannot confer") {
			t.Fatalf("unhelpful refusal: %v", res.Err)
		}

		// A target whose authority is inside alice's subtree is fine.
		mustPutPrincipal(t, tx, "inside", "/clusters/lab/apps/inside", "root")
		bindPAM(t, tx, Binding{ID: "b-inside", Subject: "inside", Role: "kv-reader",
			Scope: "/clusters/lab/secrets"})
		if res := applyPutMapping(tx, &op.PutMapping{
			Header: op.Header{Actor: alice, AtSec: 1000}, ID: "m2", Name: "ci2",
			Issuer: "kind", Namespaces: []string{"ci"}, ServiceAccounts: []string{"inside"},
			Principal: "inside", Grantor: alice,
		}); res.Err != nil {
			t.Fatalf("a target wholly inside the grantor's scope should be mappable: %v", res.Err)
		}

		// And root, who can confer anything, may map the first one.
		if res := applyPutMapping(tx, &op.PutMapping{
			Header: op.Header{Actor: "root", AtSec: 1000}, ID: "m3", Name: "ci3",
			Issuer: "kind", Namespaces: []string{"ci"}, ServiceAccounts: []string{"runner"},
			Principal: "runner", Grantor: "root",
		}); res.Err != nil {
			t.Fatalf("a domain admin should be able to map anything: %v", res.Err)
		}
	})
}
