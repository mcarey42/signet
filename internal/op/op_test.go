package op

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCodecRoundTrip(t *testing.T) {
	cas := uint64(3)
	cases := []Op{
		&PutPrincipal{Header: Header{Actor: "a", AtSec: 100}, ID: "p1", Path: "/people/mcarey", Type: "human"},
		&PutBinding{Header: Header{Actor: "a", AtSec: 101}, ID: "b1", Subject: "p1", Role: "kv-reader", Scope: "/secrets", Grantor: "a", NotAfter: 900},
		&PutSecret{Header: Header{AtSec: 102}, Path: "/secrets/app", Data: map[string]string{"k": "v"}, CAS: &cas},
		&CreateSession{Header: Header{AtSec: 103}, ID: "s1", TokenHash: "deadbeef", Principal: "p1", AMR: []string{"webauthn"}, AuthTime: 103, Expiry: 200},
		&RevokeSession{Header: Header{AtSec: 104}, TokenHash: "deadbeef"},
	}
	for _, want := range cases {
		raw, err := Encode(want)
		if err != nil {
			t.Fatalf("encode %s: %v", want.OpKind(), err)
		}
		got, err := Decode(raw)
		if err != nil {
			t.Fatalf("decode %s: %v", want.OpKind(), err)
		}
		if got.OpKind() != want.OpKind() {
			t.Fatalf("kind: got %s want %s", got.OpKind(), want.OpKind())
		}
		a, _ := json.Marshal(want)
		b, _ := json.Marshal(got)
		if string(a) != string(b) {
			t.Errorf("%s round trip:\n got %s\nwant %s", want.OpKind(), b, a)
		}
	}
}

// The raw bearer token must never be representable in a log entry. If someone
// adds a plaintext token field to CreateSession, this fails.
func TestCreateSessionCarriesOnlyTokenHash(t *testing.T) {
	raw, err := Encode(&CreateSession{ID: "s1", TokenHash: "hash-only", Principal: "p1"})
	if err != nil {
		t.Fatal(err)
	}
	var probe map[string]any
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatal(err)
	}
	body := probe["b"].(map[string]any)
	for k := range body {
		if strings.Contains(k, "token") && k != "token_hash" {
			t.Errorf("CreateSession carries a token-ish field %q; only token_hash may travel through the log", k)
		}
	}
}

// A node that cannot faithfully apply an entry must stop, not improvise:
// unknown kinds and unknown framing versions are hard errors.
func TestDecodeRejectsUnknown(t *testing.T) {
	if _, err := Decode([]byte(`{"v":1,"k":64999,"b":{}}`)); err == nil {
		t.Error("expected error for unknown kind")
	}
	if _, err := Decode([]byte(`{"v":99,"k":1,"b":{}}`)); err == nil {
		t.Error("expected error for unknown format version")
	}
	if _, err := Decode([]byte(`not json`)); err == nil {
		t.Error("expected error for malformed envelope")
	}
}

// The log outlives every binary that writes to it. An entry encoded by this
// build must still decode after fields are added to an Op — the additive
// change any future milestone will make.
func TestForwardCompatibleFieldAddition(t *testing.T) {
	// Simulates a future build's entry: a known kind with an extra field.
	future := []byte(`{"v":1,"k":1,"b":{"at":5,"id":"p1","path":"/people/x","type":"human","future_field":"ignored"}}`)
	got, err := Decode(future)
	if err != nil {
		t.Fatalf("decode entry from a newer build: %v", err)
	}
	p, ok := got.(*PutPrincipal)
	if !ok {
		t.Fatalf("got %T", got)
	}
	if p.Path != "/people/x" || p.ID != "p1" {
		t.Errorf("fields lost: %+v", p)
	}
}

func TestKindTagsAreStable(t *testing.T) {
	// These tags are on disk in every deployment forever. Changing one silently
	// reinterprets history, so they are pinned here deliberately.
	want := map[Kind]uint16{
		KindPutPrincipal: 1, KindPutBinding: 2, KindPutSecret: 3,
		KindCreateSession: 4, KindRevokeSession: 5,
	}
	for k, v := range want {
		if uint16(k) != v {
			t.Errorf("%s tag changed to %d; tags are never reused or renumbered", k, uint16(k))
		}
	}
}
