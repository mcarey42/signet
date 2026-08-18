package kernel

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/mcarey42/signet/internal/audit"
	"github.com/mcarey42/signet/internal/keys"
	"github.com/mcarey42/signet/internal/op"
	"github.com/mcarey42/signet/internal/store"
)

// VerifyAudit walks this domain's audit chain and reports the first break.
//
// It also compares the walked length against the count the store recorded. A
// truncated log is internally consistent, so that comparison is the only local
// signal it happened — an attacker who can drop entries can also edit the
// count, which is exactly why a local check is not the end of the story and
// checkpoints are witnessed elsewhere.
func (k *Kernel) VerifyAudit(ctx context.Context) (count uint64, head string, err error) {
	var claimed uint64
	err = k.store.View(func(tx *store.Tx) error {
		var vErr error
		count, head, vErr = tx.VerifyAuditChain()
		if vErr != nil {
			return vErr
		}
		claimed, vErr = tx.AuditCount()
		return vErr
	})
	if err != nil {
		return count, head, err
	}
	if claimed != count {
		return count, head, fmt.Errorf(
			"the audit chain verifies over %d entries but this store recorded %d. Entries have been "+
				"removed; the remaining chain is self-consistent, which is what truncation looks "+
				"like from the inside", count, claimed)
	}
	return count, head, nil
}

// AuditEntries returns entries (after, upTo] in chain order, which is what a
// witness needs to verify an extension rather than take it on trust.
func (k *Kernel) AuditEntries(ctx context.Context, after, upTo uint64) ([]store.AuditEntry, error) {
	var out []store.AuditEntry
	err := k.store.View(func(tx *store.Tx) error {
		return tx.ScanAudit(func(_ string, e store.AuditEntry) bool {
			if e.Seq > after && (upTo == 0 || e.Seq <= upTo) {
				out = append(out, e)
			}
			return upTo == 0 || e.Seq < upTo
		})
	})
	return out, err
}

// Checkpoint produces a signed statement of this domain's chain head.
//
// The chain is verified before it is signed. Signing a head this node has not
// just re-derived would let a corrupted store launder itself into a statement
// that looks authoritative — the signature would be perfectly valid and the
// claim false.
func (k *Kernel) Checkpoint(ctx context.Context, domain, node string) (*audit.Signed, error) {
	count, head, err := k.VerifyAudit(ctx)
	if err != nil {
		return nil, fmt.Errorf("refusing to checkpoint a chain that does not verify: %w", err)
	}
	applied, err := k.store.AppliedIndex()
	if err != nil {
		return nil, err
	}

	key, err := k.ActiveKey(ctx, keys.PurposeAudit)
	if err != nil {
		return nil, fmt.Errorf(
			"this domain has no audit signing key: %w. Genesis creates one; a domain initialized "+
				"before checkpoints existed needs `signet audit init-key`", err)
	}
	signer, err := key.Signer(k.seal)
	if err != nil {
		return nil, err
	}
	return audit.Sign(&audit.Checkpoint{
		Domain: domain, Node: node, Count: count, Head: head,
		Index: applied, AtSec: k.now().Unix(),
	}, key.ID, signer)
}

// AuditPublicKey returns the public half of the checkpoint signing key, which a
// witness pins so it can verify later checkpoints.
func (k *Kernel) AuditPublicKey(ctx context.Context) (*ecdsa.PublicKey, string, error) {
	key, err := k.ActiveKey(ctx, keys.PurposeAudit)
	if err != nil {
		return nil, "", err
	}
	pub, err := key.Public(k.seal)
	if err != nil {
		return nil, "", err
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, "", fmt.Errorf("audit key is %T, expected ECDSA", pub)
	}
	return ec, key.ID, nil
}

// Witness verifies another domain's checkpoint against what this node has
// already witnessed, and records the result.
//
// pub is the peer's checkpoint key, pinned by the caller. A conflict is stored
// rather than merely returned: the whole value of a witness is that it holds
// evidence after the fact, and evidence that vanished with the error would be
// worth nothing.
// Witness hands another domain's checkpoint to this node, which verifies it and
// records the result.
//
// This is now a thin proposer: everything that decides anything happens inside
// Apply, serialized by consensus. pub is the peer's checkpoint key, and Apply
// re-verifies against it rather than trusting that this call did.
func (k *Kernel) Witness(ctx context.Context, grantor op.ID, signed *audit.Signed,
	entries []store.AuditEntry, pub *ecdsa.PublicKey) (*audit.Witnessed, error) {

	cp, err := json.Marshal(signed)
	if err != nil {
		return nil, err
	}
	ents, err := json.Marshal(entries)
	if err != nil {
		return nil, err
	}
	pem, err := encodePublicKey(pub)
	if err != nil {
		return nil, err
	}
	claim, err := signed.Claim()
	if err != nil {
		return nil, err
	}
	_, proposeErr := k.prop.Propose(ctx, &op.PutWitness{
		Header: k.header(grantor), Checkpoint: cp, Entries: ents,
		PubKeyPEM: pem, Grantor: grantor,
	})
	// Read back what was recorded either way: on a conflict the caller wants
	// the evidence, not just the error.
	rec, readErr := k.Witnessed(ctx, claim.Domain)
	if readErr != nil {
		return nil, readErr
	}
	return rec, proposeErr
}

// Witnessed returns what this node holds for a domain, or nil.
func (k *Kernel) Witnessed(ctx context.Context, domain string) (*audit.Witnessed, error) {
	var out *audit.Witnessed
	err := k.store.View(func(tx *store.Tx) error {
		v, ok, err := tx.Get(store.BucketWitness, domain)
		if err != nil || !ok {
			return err
		}
		var w audit.Witnessed
		if err := json.Unmarshal(v, &w); err != nil {
			return err
		}
		out = &w
		return nil
	})
	return out, err
}

// AllWitnessed lists every domain this node witnesses.
func (k *Kernel) AllWitnessed(ctx context.Context) ([]*audit.Witnessed, error) {
	var out []*audit.Witnessed
	err := k.store.View(func(tx *store.Tx) error {
		return tx.ScanPrefix(store.BucketWitness, "", func(_ string, v []byte) bool {
			var w audit.Witnessed
			if err := json.Unmarshal(v, &w); err == nil {
				out = append(out, &w)
			}
			return true
		})
	})
	return out, err
}

func encodePublicKey(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

// ParsePublicKeyPEM reads a PKIX public key, for a witness re-checking a peer
// against the key it pinned earlier.
func ParsePublicKeyPEM(p []byte) (*ecdsa.PublicKey, error) {
	blk, _ := pem.Decode(p)
	if blk == nil {
		return nil, errors.New("not PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("this is a %T key; audit checkpoints are ECDSA-signed", pub)
	}
	return ec, nil
}

// applyPutWitness verifies a peer checkpoint and merges it into what this node
// already holds — all of it here, under the serialized writer.
func applyPutWitness(tx *store.Tx, o *op.PutWitness) op.Result {
	var signed audit.Signed
	if err := json.Unmarshal(o.Checkpoint, &signed); err != nil {
		return op.Result{Err: fmt.Errorf("witness: unreadable checkpoint: %w", err)}
	}
	pub, err := ParsePublicKeyPEM([]byte(o.PubKeyPEM))
	if err != nil {
		return op.Result{Err: fmt.Errorf("witness: %w", err)}
	}
	c, err := audit.Open(&signed, pub)
	if err != nil {
		return op.Result{Err: err}
	}
	if c.Domain == "" {
		return op.Result{Err: errors.New("witness: this checkpoint names no domain")}
	}
	var entries []store.AuditEntry
	if len(o.Entries) > 0 {
		if err := json.Unmarshal(o.Entries, &entries); err != nil {
			return op.Result{Err: fmt.Errorf("witness: unreadable entries: %w", err)}
		}
	}

	prior := &audit.Witnessed{}
	raw, ok, err := tx.Get(store.BucketWitness, c.Domain)
	if err != nil {
		return op.Result{Err: err}
	}
	if ok {
		if err := json.Unmarshal(raw, prior); err != nil {
			return op.Result{Err: err}
		}
	} else {
		// Beginning to witness a domain decides what this node will hold
		// evidence ABOUT, and pins the key it will believe. Left open to any
		// writer, anyone could self-sign a checkpoint for a name they do not
		// own, get their key pinned, and permanently lock out the real domain.
		// Establishing a new one is therefore administrative; extending an
		// existing record is not.
		allowed, err := HasAuthority(tx, o.Grantor, VerbAdmin, "/", o.AtSec)
		if err != nil {
			return op.Result{Err: err}
		}
		if !allowed {
			return op.Result{Err: fmt.Errorf(
				"witness: beginning to witness %q requires admin authority at /. Pinning a key for "+
					"a domain this node has never seen decides who it will believe for that name, "+
					"and it cannot be undone by whoever asks next", c.Domain)}
		}
	}

	if prior.Conflict != nil {
		return op.Result{Err: fmt.Errorf(
			"witness: this node already holds proof that %q rewrote its log (%s). Further "+
				"checkpoints are not accepted until that is resolved deliberately",
			c.Domain, prior.Conflict.Reason)}
	}

	pinned := string(o.PubKeyPEM)
	if prior.PinnedKey == "" {
		prior.PinnedKey = pinned
	} else if prior.PinnedKey != pinned {
		prior.Conflict = &audit.Conflict{
			DetectedAt: o.AtSec, Count: c.Count, Was: prior.Head, Now: c.Head,
			Reason: fmt.Sprintf(
				"%q now signs its checkpoints with a different key than the one this witness "+
					"pinned. Either it rotated its audit key without telling anyone, or this is "+
					"not the same domain any more", c.Domain),
		}
		if err := storeWitnessRecord(tx, c.Domain, prior); err != nil {
			return op.Result{Err: err}
		}
		return op.Result{Err: errors.New(prior.Conflict.Reason)}
	}
	if prior.First == nil {
		prior.First = &signed
	}

	extendErr := prior.Extend(c, entries, time.Unix(o.AtSec, 0))
	if extendErr == nil {
		prior.Checkpoint = &signed
	}
	// Stored either way: on success this advances the head, on a conflict it
	// keeps the proof, which is the whole reason a witness exists.
	if err := storeWitnessRecord(tx, c.Domain, prior); err != nil {
		return op.Result{Err: err}
	}
	if extendErr != nil {
		return op.Result{Err: extendErr}
	}
	return op.Result{Subject: c.Domain}
}

func storeWitnessRecord(tx *store.Tx, domain string, w *audit.Witnessed) error {
	blob, err := json.Marshal(w)
	if err != nil {
		return err
	}
	return tx.Put(store.BucketWitness, domain, blob)
}

// EnsureAuditKey creates the checkpoint signing key if the domain has none.
func (k *Kernel) EnsureAuditKey(ctx context.Context, grantor op.ID) error {
	if _, err := k.ActiveKey(ctx, keys.PurposeAudit); err == nil {
		return nil
	}
	key, err := keys.Generate(keys.PurposeAudit, k.now().Unix())
	if err != nil {
		return err
	}
	return k.InstallKey(ctx, grantor, key, true)
}
