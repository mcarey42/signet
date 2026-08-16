package kernel

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/mcarey42/signet/internal/keys"
	"github.com/mcarey42/signet/internal/op"
	"github.com/mcarey42/signet/internal/store"
)

// captureSerializer records what the mint path handed it, so a test can assert
// on the claims a dialect would actually receive.
type captureSerializer struct {
	got    Claims
	forged []string // roles to smuggle in, for the verify-after-sign test
}

func (c *captureSerializer) Serialize(claims Claims, k *keys.Key) ([]byte, error) {
	c.got = claims
	out := claims
	if c.forged != nil {
		out.Roles = c.forged
	}
	return json.Marshal(out)
}

func (c *captureSerializer) Verify(cred []byte, claims Claims, k *keys.Key) error {
	var got Claims
	if err := json.Unmarshal(cred, &got); err != nil {
		return err
	}
	if len(got.Roles) != len(claims.Roles) {
		return errRoleMismatch
	}
	for i := range got.Roles {
		if got.Roles[i] != claims.Roles[i] {
			return errRoleMismatch
		}
	}
	return nil
}

var errRoleMismatch = errTest("credential carries roles that were not authorized")

type errTest string

func (e errTest) Error() string { return string(e) }

// issueFixture builds a domain with a principal holding several roles at
// different tiers, and returns a kernel wired to an in-process proposer.
func issueFixture(t *testing.T) (*Kernel, Session) {
	t.Helper()
	s := newStore(t, newSealKey(t))
	k := New(s, directProposer{s})
	ctx := context.Background()

	rootID, err := k.PutPrincipal(ctx, "", "", "/people/root", "human")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.PutBinding(ctx, "", rootID, "domain-admin", "/", 0); err != nil {
		t.Fatal(err)
	}
	userID, err := k.PutPrincipal(ctx, rootID, "", "/people/user", "human")
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"kv-reader", "kv-writer", "kv-admin"} {
		if _, err := k.PutBinding(ctx, rootID, userID, role, "/", 0); err != nil {
			t.Fatal(err)
		}
	}
	// kv-admin is crown-jewel: online-only, never embeddable offline.
	if err := k.PutRolePolicy(ctx, rootID, RolePolicy{Role: "kv-admin", MinTier: TierOnlineOnly, OwnerScope: "/"}); err != nil {
		t.Fatal(err)
	}
	// kv-writer requires a hardware factor the test session will not have.
	if err := k.PutRolePolicy(ctx, rootID, RolePolicy{Role: "kv-writer", MinTier: TierOffline, RequiredAMR: "webauthn", OwnerScope: "/"}); err != nil {
		t.Fatal(err)
	}
	_, sess, err := k.CreateSession(ctx, rootID, userID, time.Hour, []string{"k8s-sa"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	key, err := keys.Generate(keys.PurposeToken, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if err := k.InstallKey(ctx, rootID, key, true); err != nil {
		t.Fatal(err)
	}
	return k, sess
}

// directProposer applies Ops straight to the store, which is what makes kernel
// tests fast: the real FSM keeps the Proposer interface honest elsewhere.
type directProposer struct{ s *store.Store }

func (d directProposer) Propose(_ context.Context, o op.Op) (op.Result, error) {
	var res op.Result
	index := nextIndex()
	err := d.s.Update(1, index, func(tx *store.Tx) error {
		res = Apply(tx, o)
		return tx.SetAppliedIndex(index)
	})
	if err != nil {
		return op.Result{}, err
	}
	return res, res.Err
}

var testIndex uint64

func nextIndex() uint64 { testIndex++; return testIndex }

// The flagship invariant of the offline milestone: a role the caller genuinely
// holds, but which policy marks online-only, must never reach a credential that
// relying parties verify without asking anyone (E-01 K-2).
func TestOnlineOnlyRolesAreNeverEmbedded(t *testing.T) {
	k, sess := issueFixture(t)
	ser := &captureSerializer{}

	if _, claims, err := k.Issue(context.Background(), sess, IssueRequest{
		Audience: "test", Purpose: keys.PurposeToken, TTL: time.Minute,
	}, ser); err != nil {
		t.Fatal(err)
	} else {
		for _, r := range claims.Roles {
			if r == "kv-admin" {
				t.Error("an online-only role was embedded in an offline credential")
			}
			if r == "kv-writer" {
				t.Error("a role requiring a hardware factor was embedded for a session without one")
			}
		}
		if len(claims.Roles) != 1 || claims.Roles[0] != "kv-reader" {
			t.Errorf("roles = %v, want exactly [kv-reader]", claims.Roles)
		}
	}
}

// A session established with the required factor does carry the gated role —
// the gate is a condition, not a blanket refusal.
func TestRequiredAMRIsSatisfiable(t *testing.T) {
	s := newStore(t, newSealKey(t))
	k := New(s, directProposer{s})
	ctx := context.Background()
	rootID, _ := k.PutPrincipal(ctx, "", "", "/people/root", "human")
	if _, err := k.PutBinding(ctx, "", rootID, "domain-admin", "/", 0); err != nil {
		t.Fatal(err)
	}
	userID, _ := k.PutPrincipal(ctx, rootID, "", "/people/user", "human")
	if _, err := k.PutBinding(ctx, rootID, userID, "kv-writer", "/", 0); err != nil {
		t.Fatal(err)
	}
	if err := k.PutRolePolicy(ctx, rootID, RolePolicy{Role: "kv-writer", MinTier: TierOffline, RequiredAMR: "webauthn", OwnerScope: "/"}); err != nil {
		t.Fatal(err)
	}
	key, _ := keys.Generate(keys.PurposeToken, time.Now().Unix())
	if err := k.InstallKey(ctx, rootID, key, true); err != nil {
		t.Fatal(err)
	}
	_, strong, err := k.CreateSession(ctx, rootID, userID, time.Hour, []string{"webauthn"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	_, claims, err := k.Issue(ctx, strong, IssueRequest{Audience: "t", Purpose: keys.PurposeToken, TTL: time.Minute}, &captureSerializer{})
	if err != nil {
		t.Fatal(err)
	}
	if len(claims.Roles) != 1 || claims.Roles[0] != "kv-writer" {
		t.Errorf("roles = %v, want [kv-writer] for a webauthn session", claims.Roles)
	}
}

// Verify-after-sign is not decorative: a serializer that adds a role it was not
// given must have its output rejected rather than returned.
func TestVerifyAfterSignCatchesAnInventedRole(t *testing.T) {
	k, sess := issueFixture(t)
	forging := &captureSerializer{forged: []string{"kv-reader", "kv-admin"}}

	if _, _, err := k.Issue(context.Background(), sess, IssueRequest{
		Audience: "test", Purpose: keys.PurposeToken, TTL: time.Minute,
	}, forging); err == nil {
		t.Fatal("a credential carrying an unauthorized role was released")
	}
}

// Constraints compose strictest-wins: the shortest applicable ceiling governs,
// even though rights themselves are additive.
func TestTTLIsClampedByTheStrictestPolicy(t *testing.T) {
	s := newStore(t, newSealKey(t))
	k := New(s, directProposer{s})
	ctx := context.Background()
	rootID, _ := k.PutPrincipal(ctx, "", "", "/people/root", "human")
	if _, err := k.PutBinding(ctx, "", rootID, "domain-admin", "/", 0); err != nil {
		t.Fatal(err)
	}
	userID, _ := k.PutPrincipal(ctx, rootID, "", "/people/user", "human")
	for _, role := range []string{"kv-reader", "kv-writer"} {
		if _, err := k.PutBinding(ctx, rootID, userID, role, "/", 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := k.PutRolePolicy(ctx, rootID, RolePolicy{Role: "kv-writer", MinTier: TierShortLeash, MaxTTLSec: 60, OwnerScope: "/"}); err != nil {
		t.Fatal(err)
	}
	key, _ := keys.Generate(keys.PurposeToken, time.Now().Unix())
	if err := k.InstallKey(ctx, rootID, key, true); err != nil {
		t.Fatal(err)
	}
	_, sess, _ := k.CreateSession(ctx, rootID, userID, time.Hour, nil, "test")

	_, claims, err := k.Issue(ctx, sess, IssueRequest{Audience: "t", Purpose: keys.PurposeToken, TTL: time.Hour}, &captureSerializer{})
	if err != nil {
		t.Fatal(err)
	}
	if lifetime := claims.ExpirySec - claims.IssuedSec; lifetime > 60 {
		t.Errorf("lifetime %ds, want clamped to the 60s ceiling kv-writer sets", lifetime)
	}
}

// A credential must not outlive the session that authorized it.
func TestCredentialNeverOutlivesItsSession(t *testing.T) {
	s := newStore(t, newSealKey(t))
	k := New(s, directProposer{s})
	ctx := context.Background()
	rootID, _ := k.PutPrincipal(ctx, "", "", "/people/root", "human")
	if _, err := k.PutBinding(ctx, "", rootID, "domain-admin", "/", 0); err != nil {
		t.Fatal(err)
	}
	key, _ := keys.Generate(keys.PurposeToken, time.Now().Unix())
	if err := k.InstallKey(ctx, rootID, key, true); err != nil {
		t.Fatal(err)
	}
	_, brief, err := k.CreateSession(ctx, rootID, rootID, 30*time.Second, nil, "test")
	if err != nil {
		t.Fatal(err)
	}
	_, claims, err := k.Issue(ctx, brief, IssueRequest{Audience: "t", Purpose: keys.PurposeToken, TTL: time.Hour}, &captureSerializer{})
	if err != nil {
		t.Fatal(err)
	}
	if claims.ExpirySec > brief.Expiry {
		t.Errorf("credential outlives its session by %ds", claims.ExpirySec-brief.Expiry)
	}
}

// Scope decides which bindings apply: a credential minted for one subtree does
// not carry roles granted only in a sibling.
func TestScopeSelectsWhichBindingsApply(t *testing.T) {
	s := newStore(t, newSealKey(t))
	k := New(s, directProposer{s})
	ctx := context.Background()
	rootID, _ := k.PutPrincipal(ctx, "", "", "/people/root", "human")
	if _, err := k.PutBinding(ctx, "", rootID, "domain-admin", "/", 0); err != nil {
		t.Fatal(err)
	}
	userID, _ := k.PutPrincipal(ctx, rootID, "", "/people/user", "human")
	if _, err := k.PutBinding(ctx, rootID, userID, "kv-reader", "/clusters/lab", 0); err != nil {
		t.Fatal(err)
	}
	key, _ := keys.Generate(keys.PurposeToken, time.Now().Unix())
	if err := k.InstallKey(ctx, rootID, key, true); err != nil {
		t.Fatal(err)
	}
	_, sess, _ := k.CreateSession(ctx, rootID, userID, time.Hour, nil, "test")

	_, in, err := k.Issue(ctx, sess, IssueRequest{Audience: "t", Scope: "/clusters/lab/apps", Purpose: keys.PurposeToken, TTL: time.Minute}, &captureSerializer{})
	if err != nil {
		t.Fatal(err)
	}
	if len(in.Roles) != 1 {
		t.Errorf("in-scope roles = %v, want [kv-reader]", in.Roles)
	}
	_, out, err := k.Issue(ctx, sess, IssueRequest{Audience: "t", Scope: "/clusters/prod", Purpose: keys.PurposeToken, TTL: time.Minute}, &captureSerializer{})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Roles) != 0 {
		t.Errorf("sibling-scope roles = %v, want none", out.Roles)
	}
}
