package kernel

import (
	"context"
	"testing"
	"time"

	"github.com/mcarey42/signet/internal/ca"
	"github.com/mcarey42/signet/internal/keys"
	"github.com/mcarey42/signet/internal/op"
	"github.com/mcarey42/signet/internal/seal"
)

// rotationFixture builds a domain with a CA and both signing keys under one
// seal, which is what a rotation has to move.
func rotationFixture(t *testing.T) (*Kernel, seal.Seal, op.ID) {
	t.Helper()
	sl := newSeal(t)
	s := newStore(t, sl)
	k := New(s, directProposer{s}, sl)
	ctx := context.Background()

	rootID, err := k.PutPrincipal(ctx, "", "", "/people/root", "human")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.PutBinding(ctx, "", rootID, "domain-admin", "/", 0); err != nil {
		t.Fatal(err)
	}
	for _, purpose := range []keys.Purpose{keys.PurposeToken, keys.PurposeSSH} {
		key, err := keys.Generate(purpose, time.Now().Unix())
		if err != nil {
			t.Fatal(err)
		}
		if err := k.InstallKey(ctx, rootID, key, true); err != nil {
			t.Fatal(err)
		}
	}
	res, err := ca.Genesis("Test", []string{"example.com"}, nil, 10*365*24*time.Hour, 365*24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := k.InstallCA(ctx, rootID, "default", res.Material); err != nil {
		t.Fatal(err)
	}
	return k, sl, rootID
}

// Rotation is a custody change, not a re-key: every key keeps its identity, so
// credentials already issued under it stay valid. If this ever stops being
// true, rotating a seal becomes an outage.
func TestRotateSealPreservesKeyIdentity(t *testing.T) {
	k, from, actor := rotationFixture(t)
	ctx := context.Background()

	before, err := k.ActiveKey(ctx, keys.PurposeToken)
	if err != nil {
		t.Fatal(err)
	}
	beforePub, err := before.JWK(from)
	if err != nil {
		t.Fatal(err)
	}

	to := newSeal(t)
	moved, err := k.RotateSeal(ctx, actor, from, to)
	if err != nil {
		t.Fatal(err)
	}
	if len(moved) != 3 {
		t.Fatalf("rewrapped %d items, want 3 (two keys and a CA)", len(moved))
	}

	// Point the kernel at the destination seal, as a restarted server would.
	k.seal = to
	after, err := k.ActiveKey(ctx, keys.PurposeToken)
	if err != nil {
		t.Fatal(err)
	}
	if after.ID != before.ID {
		t.Errorf("key id changed: %s -> %s", before.ID, after.ID)
	}
	afterPub, err := after.JWK(to)
	if err != nil {
		t.Fatal(err)
	}
	// Same public key means every token already in the wild still verifies.
	if beforePub["n"] != afterPub["n"] || beforePub["kid"] != afterPub["kid"] {
		t.Error("the public key changed, which would invalidate issued credentials")
	}
	if err := k.VerifySealedMaterial(ctx, to); err != nil {
		t.Errorf("material does not open under the destination seal: %v", err)
	}
}

// After a rotation the old seal must be useless against the store — otherwise
// destroying it would not actually shrink the attack surface.
func TestRotatedMaterialNoLongerOpensUnderTheOldSeal(t *testing.T) {
	k, from, actor := rotationFixture(t)
	ctx := context.Background()
	to := newSeal(t)
	if _, err := k.RotateSeal(ctx, actor, from, to); err != nil {
		t.Fatal(err)
	}
	if err := k.VerifySealedMaterial(ctx, from); err == nil {
		t.Fatal("the old seal still opens the rotated material")
	}
}

// A ceremony can be interrupted. Re-running it must finish the job rather than
// failing on its own progress.
func TestRotateSealIsIdempotentAndResumable(t *testing.T) {
	k, from, actor := rotationFixture(t)
	ctx := context.Background()
	to := newSeal(t)

	if _, err := k.RotateSeal(ctx, actor, from, to); err != nil {
		t.Fatal(err)
	}
	// Running again with the same destination: everything is already there, so
	// nothing should move and nothing should fail.
	k.seal = to
	moved, err := k.RotateSeal(ctx, actor, to, to)
	if err != nil {
		t.Fatalf("re-running the ceremony failed: %v", err)
	}
	if len(moved) != 0 {
		t.Errorf("re-run moved %d items, want 0", len(moved))
	}
}

// A half-finished rotation must be visible, because the operator's next
// decision — whether it is safe to destroy the old seal — depends on it.
func TestSealInventorySurfacesAMixedState(t *testing.T) {
	k, from, actor := rotationFixture(t)
	ctx := context.Background()
	to := newSeal(t)

	// Move exactly one item, as an interrupted ceremony would.
	if err := k.rewrapCA(ctx, actor, "default", from, to); err != nil {
		t.Fatal(err)
	}
	items, err := k.SealInventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, it := range items {
		seen[it.SealedBy] = true
	}
	if len(seen) < 2 {
		t.Fatalf("inventory reports one seal for a mixed domain: %v", seen)
	}
}

// Verification must open the material rather than trust its labelling: a record
// that merely claims the new seal proves nothing.
func TestVerifyOpensRatherThanTrustsLabels(t *testing.T) {
	k, from, actor := rotationFixture(t)
	ctx := context.Background()
	to := newSeal(t)
	if _, err := k.RotateSeal(ctx, actor, from, to); err != nil {
		t.Fatal(err)
	}
	// A third seal has the right shape and the wrong key.
	if err := k.VerifySealedMaterial(ctx, newSeal(t)); err == nil {
		t.Fatal("verification passed under a seal that cannot open the material")
	}
}
