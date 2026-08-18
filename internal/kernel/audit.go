package kernel

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

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
func (k *Kernel) Witness(ctx context.Context, grantor op.ID, signed *audit.Signed,
	entries []store.AuditEntry, pub *ecdsa.PublicKey) (*audit.Witnessed, error) {

	c, err := audit.Open(signed, pub)
	if err != nil {
		return nil, err
	}
	if c.Domain == "" {
		return nil, errors.New("this checkpoint names no domain, so there is nothing to witness it for")
	}

	prior, err := k.Witnessed(ctx, c.Domain)
	if err != nil {
		return nil, err
	}
	if prior == nil {
		prior = &audit.Witnessed{}
	}
	if prior.Conflict != nil {
		return prior, fmt.Errorf(
			"this witness already holds proof that %q rewrote its log (%s). Further checkpoints are "+
				"not accepted until that is resolved deliberately", c.Domain, prior.Conflict.Reason)
	}
	if prior.First == nil {
		prior.First = signed
	}
	// Pin the checkpoint key on first sight and refuse a silent change. The
	// caller has already verified against `pub`; this is what stops a later
	// call quietly substituting a different key and continuing the record.
	pinned, err := encodePublicKey(pub)
	if err != nil {
		return nil, err
	}
	if prior.PinnedKey == "" {
		prior.PinnedKey = pinned
	} else if prior.PinnedKey != pinned {
		// A changed checkpoint key is itself evidence, so it is recorded rather
		// than merely refused: a node rebuilt from scratch loses its audit key,
		// which is one of the more common shapes a rewrite actually takes.
		prior.Conflict = &audit.Conflict{
			DetectedAt: k.now().Unix(), Count: c.Count, Was: prior.Head, Now: c.Head,
			Reason: fmt.Sprintf(
				"%q now signs its checkpoints with a different key than the one this witness "+
					"pinned. Either it rotated its audit key without telling anyone, or this is "+
					"not the same domain any more", c.Domain),
		}
		if err := k.storeWitness(ctx, grantor, c.Domain, prior); err != nil {
			return prior, err
		}
		return prior, errors.New(prior.Conflict.Reason)
	}

	extendErr := prior.Extend(c, entries, k.now())
	if extendErr == nil {
		prior.Checkpoint = signed
	}
	// Persist either way. On success this advances the witnessed head; on a
	// conflict it stores the proof, which is the whole reason a witness exists.
	if err := k.storeWitness(ctx, grantor, c.Domain, prior); err != nil {
		return prior, err
	}
	return prior, extendErr
}

func (k *Kernel) storeWitness(ctx context.Context, grantor op.ID, domain string, w *audit.Witnessed) error {
	blob, err := json.Marshal(w)
	if err != nil {
		return err
	}
	_, err = k.prop.Propose(ctx, &op.PutWitness{
		Header: k.header(grantor), Domain: domain, Record: blob, Grantor: grantor,
	})
	return err
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

func applyPutWitness(tx *store.Tx, o *op.PutWitness) op.Result {
	if o.Domain == "" {
		return op.Result{Err: errors.New("witness: missing domain")}
	}
	if err := tx.Put(store.BucketWitness, o.Domain, o.Record); err != nil {
		return op.Result{Err: err}
	}
	return op.Result{}
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
