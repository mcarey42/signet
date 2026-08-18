// Package audit anchors the hash-chained log to something outside the node
// that produced it.
//
// # Why chaining is not enough
//
// internal/store chains every audit entry to its predecessor, which makes an
// edit break every hash after it. That is worth having, but it assumes the
// attacker cannot recompute the chain — and an attacker who has taken the node
// can. They hold the store, the keys, and all the time in the world. Against
// that adversary a hash chain proves nothing on its own: they truncate the log,
// or rewrite it from the genesis value, and what remains is perfectly
// self-consistent.
//
// What defeats that is a statement about the chain made *before* the tampering,
// held somewhere the attacker does not control. That is a checkpoint: a signed
// claim that "at count N the chain head was H", handed to a witness.
//
// # Why witnesses verify rather than merely store
//
// A witness that only filed checkpoints away would catch a rewrite that
// contradicts one it happens to hold, and miss everything between checkpoints.
// So a witness here is asked to accept an *extension*: the entries since the
// last checkpoint it saw, which it replays onto the head it already holds. If
// they do not chain, it refuses and keeps the head it had.
//
// That turns the witness into an append-only enforcer rather than a filing
// cabinet, and it means the guarantee degrades gracefully: whatever a witness
// has accepted is provably a prefix of what it accepts later.
package audit

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/mcarey42/signet/internal/store"
)

// Checkpoint is a signed claim about the state of one domain's audit chain.
type Checkpoint struct {
	Domain string `json:"domain"`
	Node   string `json:"node"`
	// Count is how many entries the chain contains, and Head the hash of the
	// last one. Together they are the whole claim: a later checkpoint with the
	// same count and a different head is proof of tampering that needs no
	// further evidence.
	Count uint64 `json:"count"`
	Head  string `json:"head"`
	Index uint64 `json:"index"` // raft applied index, for operator orientation
	AtSec int64  `json:"at"`
}

// Signed is a checkpoint plus the signature over the exact bytes transmitted.
type Signed struct {
	Payload   string `json:"payload"` // base64 of the checkpoint JSON
	KeyID     string `json:"kid"`
	Alg       string `json:"alg"`
	Signature []byte `json:"sig"`
}

// Sign serializes a checkpoint and signs those bytes.
func Sign(c *Checkpoint, keyID string, signer crypto.Signer) (*Signed, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(raw)
	sig, err := signer.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("audit: signing the checkpoint: %w", err)
	}
	return &Signed{
		Payload: base64.StdEncoding.EncodeToString(raw),
		KeyID:   keyID, Alg: "ES256", Signature: sig,
	}, nil
}

// Open verifies a signed checkpoint against a public key and returns its claim.
func Open(s *Signed, pub *ecdsa.PublicKey) (*Checkpoint, error) {
	raw, err := base64.StdEncoding.DecodeString(s.Payload)
	if err != nil {
		return nil, fmt.Errorf("audit: the checkpoint payload is not valid base64: %w", err)
	}
	digest := sha256.Sum256(raw)
	if !ecdsa.VerifyASN1(pub, digest[:], s.Signature) {
		return nil, errors.New(
			"audit: the checkpoint's signature does not verify. It was altered, or produced by " +
				"something that does not hold the key it names")
	}
	var c Checkpoint
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// Claim returns a signed checkpoint's contents WITHOUT verifying it, for
// reading state that was verified when it was accepted. Never use it on
// something that just arrived: an unverified claim is only an assertion.
func (s *Signed) Claim() (*Checkpoint, error) {
	raw, err := base64.StdEncoding.DecodeString(s.Payload)
	if err != nil {
		return nil, err
	}
	var c Checkpoint
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// Witnessed is what a witness holds for one domain: the furthest checkpoint it
// has verified, kept so a later claim can be checked against it.
type Witnessed struct {
	Domain string `json:"domain"`
	Count  uint64 `json:"count"`
	Head   string `json:"head"`
	AtSec  int64  `json:"at"`
	// PinnedKey is the peer's checkpoint key, in PKIX PEM, fixed on first
	// witness. A witness that accepted a new key whenever one was offered would
	// be witnessing whoever asked, not the domain it thinks it is watching.
	PinnedKey  string    `json:"pinned_key,omitempty"`
	Checkpoint *Signed   `json:"checkpoint"`
	First      *Signed   `json:"first,omitempty"` // the earliest one still held, as evidence
	Conflict   *Conflict `json:"conflict,omitempty"`
	History    []HeadAtN `json:"history,omitempty"`
}

// HeadAtN records that a domain claimed a particular head at a particular
// count. Keeping a few of these is what lets a witness produce evidence rather
// than merely an assertion when it later sees a contradiction.
type HeadAtN struct {
	Count uint64 `json:"count"`
	Head  string `json:"head"`
	AtSec int64  `json:"at"`
}

// Conflict is proof that a domain's log was rewritten: two different heads
// claimed for the same count, or a count that went backwards.
type Conflict struct {
	DetectedAt int64  `json:"detected_at"`
	Count      uint64 `json:"count"`
	Was        string `json:"was"`
	Now        string `json:"now"`
	Reason     string `json:"reason"`
}

// Extend advances a witness record with a new checkpoint and the entries that
// justify it.
//
// entries are the audit entries after the witness's current count, in order.
// The witness replays them onto the head it already holds, which is what makes
// this an append-only check rather than a filing operation: an extension that
// does not continue the chain the witness already accepted is refused, and the
// refusal is recorded as a conflict rather than being discarded.
func (w *Witnessed) Extend(c *Checkpoint, entries []store.AuditEntry, now time.Time) error {
	if w.Domain != "" && w.Domain != c.Domain {
		return fmt.Errorf(
			"audit: this record is for domain %q and the checkpoint is for %q. A witness keeps one "+
				"record per domain; they are never combined", w.Domain, c.Domain)
	}

	// A count that goes backwards is a truncation claim, which no honest node
	// makes: an audit chain only grows.
	if c.Count < w.Count {
		w.Conflict = &Conflict{
			DetectedAt: now.Unix(), Count: c.Count, Was: w.Head, Now: c.Head,
			Reason: fmt.Sprintf(
				"the domain now claims %d entries having previously been witnessed at %d. An audit "+
					"chain only grows, so this is a truncation", c.Count, w.Count),
		}
		return errors.New(w.Conflict.Reason)
	}

	// The same count with a different head is unambiguous proof of a rewrite,
	// and needs no entries to demonstrate.
	if c.Count == w.Count {
		if w.Head != "" && c.Head != w.Head {
			w.Conflict = &Conflict{
				DetectedAt: now.Unix(), Count: c.Count, Was: w.Head, Now: c.Head,
				Reason: fmt.Sprintf(
					"the domain claims head %s at %d entries, but %s was witnessed at that same "+
						"count. The log was rewritten", c.Head, c.Count, w.Head),
			}
			return errors.New(w.Conflict.Reason)
		}
		return nil // nothing new; re-witnessing the same state is harmless
	}

	// Growing: replay the supplied entries onto the head we hold.
	if uint64(len(entries)) != c.Count-w.Count {
		return fmt.Errorf(
			"audit: this checkpoint moves the chain from %d to %d entries, so %d entries are needed "+
				"to justify it and %d were supplied. A witness verifies extensions rather than "+
				"taking them on trust", w.Count, c.Count, c.Count-w.Count, len(entries))
	}
	head := w.Head
	if head == "" {
		head = store.GenesisHead()
	}
	seq := w.Count
	for _, e := range entries {
		seq++
		if e.Seq != seq {
			return fmt.Errorf(
				"audit: entry %d arrived numbered %d; the extension is not a contiguous run", seq, e.Seq)
		}
		if e.Prev != head {
			w.Conflict = &Conflict{
				DetectedAt: now.Unix(), Count: seq, Was: head, Now: e.Prev,
				Reason: fmt.Sprintf(
					"entry %d follows %s, but this witness holds %s at that point. The history it "+
						"was shown before and the history it is being shown now have diverged",
					seq, e.Prev, head),
			}
			return errors.New(w.Conflict.Reason)
		}
		if got := store.ChainHash(e.Prev, e.Record); got != e.Hash {
			return fmt.Errorf(
				"audit: entry %d does not match its own hash (%s vs %s), so its record was altered",
				seq, got, e.Hash)
		}
		head = e.Hash
	}
	if head != c.Head {
		return fmt.Errorf(
			"audit: replaying the supplied entries ends at %s but the checkpoint claims %s. The "+
				"checkpoint does not describe the entries offered to justify it", head, c.Head)
	}

	w.Domain, w.Count, w.Head, w.AtSec = c.Domain, c.Count, c.Head, now.Unix()
	w.History = append(w.History, HeadAtN{Count: c.Count, Head: c.Head, AtSec: now.Unix()})
	if len(w.History) > 32 {
		// Keep the earliest as evidence of how far back this witness goes, and
		// a recent tail; the middle adds nothing a conflict could not show.
		w.History = append(w.History[:1], w.History[len(w.History)-31:]...)
	}
	return nil
}
