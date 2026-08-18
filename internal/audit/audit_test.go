package audit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mcarey42/signet/internal/store"
)

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// chain builds n entries starting from a head, as a node's store would.
func chain(from string, n int, tag string) ([]store.AuditEntry, string) {
	head := from
	var out []store.AuditEntry
	for i := 1; i <= n; i++ {
		rec, _ := json.Marshal(map[string]any{"kind": "PutSecret", "tag": tag, "i": i})
		h := store.ChainHash(head, rec)
		out = append(out, store.AuditEntry{Seq: uint64(i), Prev: head, Hash: h, Record: rec})
		head = h
	}
	return out, head
}

func seqFrom(entries []store.AuditEntry, start uint64) []store.AuditEntry {
	out := make([]store.AuditEntry, 0, len(entries))
	for _, e := range entries {
		e.Seq += start
		out = append(out, e)
	}
	return out
}

func wantErr(t *testing.T, err error, contains string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a refusal mentioning %q, got acceptance", contains)
	}
	if !strings.Contains(err.Error(), contains) {
		t.Fatalf("expected the refusal to mention %q, got: %v", contains, err)
	}
}

func TestCheckpointSignatureRoundTrips(t *testing.T) {
	key := testKey(t)
	c := &Checkpoint{Domain: "home.example.net", Count: 5, Head: "sha256:abc", AtSec: 1000}
	s, err := Sign(c, "kid1", key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(s, &key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if got.Count != 5 || got.Head != "sha256:abc" || got.Domain != "home.example.net" {
		t.Fatalf("round trip lost the claim: %+v", got)
	}

	// A checkpoint from a different key must not pass, however well formed.
	other := testKey(t)
	_, err = Open(s, &other.PublicKey)
	wantErr(t, err, "signature does not verify")

	// Nor may the claim be edited after signing.
	tampered := *s
	edited, _ := json.Marshal(&Checkpoint{Domain: "home.example.net", Count: 99, Head: "sha256:xyz"})
	tampered.Payload = base64.StdEncoding.EncodeToString(edited)
	_, err = Open(&tampered, &key.PublicKey)
	wantErr(t, err, "signature does not verify")
}

// The ordinary path: a witness accepts an extension it can verify by replay.
func TestWitnessAcceptsVerifiableExtension(t *testing.T) {
	entries, head := chain(store.GenesisHead(), 5, "real")
	w := &Witnessed{}
	if err := w.Extend(&Checkpoint{Domain: "home.example.net", Count: 5, Head: head},
		entries, time.Now()); err != nil {
		t.Fatalf("a valid extension should be accepted: %v", err)
	}
	if w.Count != 5 || w.Head != head {
		t.Fatalf("witness did not advance: %+v", w)
	}

	// And continues from where it left off.
	more, head2 := chain(head, 3, "real")
	if err := w.Extend(&Checkpoint{Domain: "home.example.net", Count: 8, Head: head2},
		seqFrom(more, 5), time.Now()); err != nil {
		t.Fatalf("a continuation should be accepted: %v", err)
	}
	if w.Count != 8 {
		t.Fatalf("expected 8 entries witnessed, got %d", w.Count)
	}
}

// A witness must not take an extension on trust: without the entries that
// justify it, there is nothing to verify.
func TestWitnessRefusesUnjustifiedExtension(t *testing.T) {
	entries, head := chain(store.GenesisHead(), 5, "real")
	w := &Witnessed{}
	if err := w.Extend(&Checkpoint{Domain: "d", Count: 5, Head: head}, entries, time.Now()); err != nil {
		t.Fatal(err)
	}
	err := w.Extend(&Checkpoint{Domain: "d", Count: 9, Head: "sha256:whatever"}, nil, time.Now())
	wantErr(t, err, "entries are needed to justify it")
	if w.Count != 5 {
		t.Fatal("the witness advanced on an unjustified claim")
	}
}

// The headline case: a node rewrites its history and presents a different head
// for a count the witness already saw. This is what a hash chain alone cannot
// catch, and it needs no entries to prove.
func TestWitnessDetectsRewrittenHistory(t *testing.T) {
	real, realHead := chain(store.GenesisHead(), 5, "real")
	w := &Witnessed{}
	if err := w.Extend(&Checkpoint{Domain: "home.example.net", Count: 5, Head: realHead},
		real, time.Now()); err != nil {
		t.Fatal(err)
	}

	// The attacker rebuilds five entries that say something else entirely.
	_, forgedHead := chain(store.GenesisHead(), 5, "sanitized")
	if forgedHead == realHead {
		t.Fatal("precondition: the forged chain should differ")
	}
	err := w.Extend(&Checkpoint{Domain: "home.example.net", Count: 5, Head: forgedHead}, nil, time.Now())
	wantErr(t, err, "The log was rewritten")

	if w.Conflict == nil {
		t.Fatal("the witness did not retain proof of the conflict")
	}
	if w.Conflict.Was != realHead || w.Conflict.Now != forgedHead {
		t.Fatalf("the conflict does not name both heads: %+v", w.Conflict)
	}
	// The witness keeps what it saw first; it is not talked out of it.
	if w.Head != realHead {
		t.Fatalf("the witness abandoned the head it had verified: %s", w.Head)
	}
}

// A rewrite that also grows must fail on replay: the entries offered do not
// continue the history this witness already accepted.
func TestWitnessDetectsForkedHistoryOnReplay(t *testing.T) {
	real, realHead := chain(store.GenesisHead(), 5, "real")
	w := &Witnessed{}
	if err := w.Extend(&Checkpoint{Domain: "d", Count: 5, Head: realHead}, real, time.Now()); err != nil {
		t.Fatal(err)
	}

	// A forged history of 8 entries, built from genesis rather than from the
	// head this witness holds.
	forged, forgedHead := chain(store.GenesisHead(), 8, "sanitized")
	err := w.Extend(&Checkpoint{Domain: "d", Count: 8, Head: forgedHead}, forged[5:], time.Now())
	wantErr(t, err, "have diverged")
	if w.Conflict == nil {
		t.Fatal("a forked history left no evidence")
	}
	if w.Count != 5 || w.Head != realHead {
		t.Fatal("the witness accepted part of a forked history")
	}
}

// Truncation: the node claims fewer entries than were witnessed. An audit chain
// only grows, so this needs no further evidence to reject.
func TestWitnessDetectsTruncation(t *testing.T) {
	real, realHead := chain(store.GenesisHead(), 5, "real")
	w := &Witnessed{}
	if err := w.Extend(&Checkpoint{Domain: "d", Count: 5, Head: realHead}, real, time.Now()); err != nil {
		t.Fatal(err)
	}
	shortHead := real[2].Hash
	err := w.Extend(&Checkpoint{Domain: "d", Count: 3, Head: shortHead}, nil, time.Now())
	wantErr(t, err, "this is a truncation")
	if w.Conflict == nil {
		t.Fatal("truncation left no evidence")
	}
}

// An entry whose record was altered must fail even if it links correctly, or
// the witness would be verifying structure and not content.
func TestWitnessDetectsAlteredEntryInExtension(t *testing.T) {
	entries, _ := chain(store.GenesisHead(), 3, "real")
	entries[1].Record = json.RawMessage(`{"kind":"PutSecret","tag":"altered"}`)
	w := &Witnessed{}
	err := w.Extend(&Checkpoint{Domain: "d", Count: 3, Head: entries[2].Hash}, entries, time.Now())
	wantErr(t, err, "does not match its own hash")
}

// A checkpoint whose head does not match the entries offered for it is refused:
// the two must describe the same history.
func TestWitnessRefusesCheckpointThatDoesNotMatchItsEntries(t *testing.T) {
	entries, _ := chain(store.GenesisHead(), 3, "real")
	w := &Witnessed{}
	err := w.Extend(&Checkpoint{Domain: "d", Count: 3, Head: "sha256:something-else"}, entries, time.Now())
	wantErr(t, err, "does not describe the entries offered")
}

// One witness record holds one domain, never a mixture.
func TestWitnessKeepsDomainsSeparate(t *testing.T) {
	entries, head := chain(store.GenesisHead(), 3, "real")
	w := &Witnessed{}
	if err := w.Extend(&Checkpoint{Domain: "home.example.net", Count: 3, Head: head}, entries, time.Now()); err != nil {
		t.Fatal(err)
	}
	err := w.Extend(&Checkpoint{Domain: "aws.example.net", Count: 3, Head: head}, nil, time.Now())
	wantErr(t, err, "never combined")
}

// Re-witnessing the same state is harmless, so a scheduled witness run that
// fires with nothing new does not produce a false alarm.
func TestReWitnessingIdenticalStateIsAccepted(t *testing.T) {
	entries, head := chain(store.GenesisHead(), 4, "real")
	w := &Witnessed{}
	if err := w.Extend(&Checkpoint{Domain: "d", Count: 4, Head: head}, entries, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := w.Extend(&Checkpoint{Domain: "d", Count: 4, Head: head}, nil, time.Now()); err != nil {
		t.Fatalf("re-witnessing unchanged state should be accepted: %v", err)
	}
	if w.Conflict != nil {
		t.Fatal("re-witnessing unchanged state raised a false conflict")
	}
}
