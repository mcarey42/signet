// Package op defines Signet's write vocabulary: every mutation to domain state
// is an Op, proposed through consensus and applied exactly once.
//
// Two properties make this package a leaf with no dependencies on the rest of
// the system, and they are the reason it is a package at all:
//
//   - The codec is durable. Log entries and backup segments written by any
//     version of Signet must decode in every later version, so Kind tags are
//     never reused and the envelope carries a format version.
//   - Ops carry every nondeterministic input they need — timestamps, generated
//     IDs, token hashes. FSM.Apply is a pure function of (op, prior state), so
//     replaying a log or restoring a backup reproduces state exactly
//     (docs/15 contract 1).
package op

import (
	"encoding/json"
	"fmt"
)

// FormatVersion is the envelope framing version. Bump only when the envelope
// itself changes shape, never for adding an Op kind.
const FormatVersion uint16 = 1

// Kind identifies an Op type on the wire. Values are never reused: a retired
// Op keeps its tag forever so old log entries stay decodable.
type Kind uint16

const (
	KindInvalid       Kind = 0
	KindPutPrincipal  Kind = 1
	KindPutBinding    Kind = 2
	KindPutSecret     Kind = 3
	KindCreateSession Kind = 4
	KindRevokeSession Kind = 5
	KindPutIssuer     Kind = 6
	KindPutMapping    Kind = 7
	KindVersionAction Kind = 8
	KindDestroySecret Kind = 9
	KindPutSecretMeta Kind = 10
)

func (k Kind) String() string {
	switch k {
	case KindPutPrincipal:
		return "PutPrincipal"
	case KindPutBinding:
		return "PutBinding"
	case KindPutSecret:
		return "PutSecret"
	case KindCreateSession:
		return "CreateSession"
	case KindRevokeSession:
		return "RevokeSession"
	case KindPutIssuer:
		return "PutIssuer"
	case KindPutMapping:
		return "PutMapping"
	case KindVersionAction:
		return "VersionAction"
	case KindDestroySecret:
		return "DestroySecret"
	case KindPutSecretMeta:
		return "PutSecretMeta"
	}
	return fmt.Sprintf("Kind(%d)", uint16(k))
}

// ID is a stable, never-reused identifier. Paths are mutable names; every
// internal reference binds to an ID so that deleting and recreating a path
// cannot resurrect authority granted to its predecessor (docs/13 F1).
type ID string

// Header is common to every Op. AtSec is the proposer's (leader's) clock,
// captured before proposing — Apply never reads a clock.
type Header struct {
	Actor ID    `json:"actor,omitempty"`
	AtSec int64 `json:"at"`
}

// Op is one mutation.
type Op interface{ OpKind() Kind }

type PutPrincipal struct {
	Header
	ID   ID     `json:"id"`
	Path string `json:"path"`
	Type string `json:"type"` // human|service|machine|workload|group|domain
}

type PutBinding struct {
	Header
	ID       ID     `json:"id"`
	Subject  ID     `json:"subject"`
	Role     string `json:"role"`
	Scope    string `json:"scope"`
	Grantor  ID     `json:"grantor"`
	NotAfter int64  `json:"not_after,omitempty"` // 0 = no expiry; JIT grants set it
}

type PutSecret struct {
	Header
	Path string            `json:"path"`
	Data map[string]string `json:"data"`
	CAS  *uint64           `json:"cas,omitempty"`
}

// CreateSession carries only the token's hash. The proposer generates the raw
// bearer token and returns it to its caller directly; the raw token never
// enters the Raft log, the FSM, a snapshot, or a backup segment
// (docs/15 contract 2).
type CreateSession struct {
	Header
	ID        ID       `json:"id"`
	TokenHash string   `json:"token_hash"`
	Principal ID       `json:"principal"`
	AMR       []string `json:"amr,omitempty"`
	AuthTime  int64    `json:"auth_time"`
	Expiry    int64    `json:"expiry"` // 0 = non-expiring
	Verifier  string   `json:"verifier,omitempty"`
	// SenderBindingRef is nullable and unused in the MVP, but present from day
	// one so offline dialects need no session-schema migration (docs/13 F9).
	SenderBindingRef string `json:"sbk_ref,omitempty"`
}

type RevokeSession struct {
	Header
	TokenHash string `json:"token_hash"`
}

// VersionMode selects what a VersionAction does to the versions it names.
type VersionMode string

const (
	// VersionDelete is reversible: the data stays, marked deleted.
	VersionDelete VersionMode = "delete"
	// VersionUndelete restores a soft-deleted version.
	VersionUndelete VersionMode = "undelete"
	// VersionDestroy erases the data and cannot be undone.
	VersionDestroy VersionMode = "destroy"
)

// VersionAction soft-deletes, restores, or destroys specific versions of a
// secret. An empty Versions list means the current version.
type VersionAction struct {
	Header
	Path     string      `json:"path"`
	Versions []uint64    `json:"versions,omitempty"`
	Mode     VersionMode `json:"mode"`
}

// DestroySecret removes a secret entirely: metadata and every version.
type DestroySecret struct {
	Header
	Path string `json:"path"`
}

// PutSecretMeta writes the policy attached to a secret rather than its value.
type PutSecretMeta struct {
	Header
	Path           string            `json:"path"`
	CustomMetadata map[string]string `json:"custom_metadata,omitempty"`
	MaxVersions    uint32            `json:"max_versions,omitempty"`
	CASRequired    bool              `json:"cas_required,omitempty"`
}

// PutIssuer registers a pinned attestation trust anchor: the exact `iss` value
// tokens must carry, the Signet-specific audience they must be minted for, and
// the key set that verifies them. Keys are registered out of band and never
// discovered from a URL a request supplies.
type PutIssuer struct {
	Header
	ID       ID     `json:"id"`
	Name     string `json:"name"`
	Verifier string `json:"verifier"`
	URL      string `json:"url"`
	Audience string `json:"audience"`
	JWKS     []byte `json:"jwks"`
	Grantor  ID     `json:"grantor"`
}

// PutMapping records which verified identities become which principal. It is
// an authorization-bearing write — whoever can author mappings can decide who
// gets to be whom — so it obeys delegation-only-narrows exactly like a binding
// (E-01 K-1, the ESC1 lesson).
type PutMapping struct {
	Header
	ID     ID     `json:"id"`
	Name   string `json:"name"` // the "role" a client names at login
	Issuer string `json:"issuer"`
	// Matchers are exact-match lists, never patterns. A matcher language on the
	// authentication path is a policy engine through the back door (docs/13).
	Namespaces      []string `json:"namespaces"`
	ServiceAccounts []string `json:"service_accounts"`
	Principal       ID       `json:"principal"`
	TTLSeconds      int64    `json:"ttl_seconds"`
	Grantor         ID       `json:"grantor"`
}

func (PutPrincipal) OpKind() Kind  { return KindPutPrincipal }
func (PutBinding) OpKind() Kind    { return KindPutBinding }
func (PutSecret) OpKind() Kind     { return KindPutSecret }
func (CreateSession) OpKind() Kind { return KindCreateSession }
func (RevokeSession) OpKind() Kind { return KindRevokeSession }
func (PutIssuer) OpKind() Kind     { return KindPutIssuer }
func (VersionAction) OpKind() Kind { return KindVersionAction }
func (DestroySecret) OpKind() Kind { return KindDestroySecret }
func (PutSecretMeta) OpKind() Kind { return KindPutSecretMeta }
func (PutMapping) OpKind() Kind    { return KindPutMapping }

// Result is what Apply computes for one Op. It is returned to the proposer
// through the consensus future; it is never persisted, so Err may be a plain
// error value.
type Result struct {
	ID      ID
	Version uint64
	Err     error
}

type envelope struct {
	V    uint16          `json:"v"`
	K    Kind            `json:"k"`
	Body json.RawMessage `json:"b"`
}

// Encode frames an Op for the log.
func Encode(o Op) ([]byte, error) {
	body, err := json.Marshal(o)
	if err != nil {
		return nil, fmt.Errorf("op: marshal %s: %w", o.OpKind(), err)
	}
	return json.Marshal(envelope{V: FormatVersion, K: o.OpKind(), Body: body})
}

// Decode reverses Encode. It rejects unknown framing versions and unknown Op
// kinds rather than guessing: a node that cannot faithfully apply an entry
// must stop, not improvise.
func Decode(b []byte) (Op, error) {
	var e envelope
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, fmt.Errorf("op: decode envelope: %w", err)
	}
	if e.V != FormatVersion {
		return nil, fmt.Errorf("op: unsupported format version %d (this build speaks %d)", e.V, FormatVersion)
	}
	var (
		o   Op
		err error
	)
	switch e.K {
	case KindPutPrincipal:
		var v PutPrincipal
		err, o = json.Unmarshal(e.Body, &v), &v
	case KindPutBinding:
		var v PutBinding
		err, o = json.Unmarshal(e.Body, &v), &v
	case KindPutSecret:
		var v PutSecret
		err, o = json.Unmarshal(e.Body, &v), &v
	case KindCreateSession:
		var v CreateSession
		err, o = json.Unmarshal(e.Body, &v), &v
	case KindRevokeSession:
		var v RevokeSession
		err, o = json.Unmarshal(e.Body, &v), &v
	case KindPutIssuer:
		var v PutIssuer
		err, o = json.Unmarshal(e.Body, &v), &v
	case KindPutMapping:
		var v PutMapping
		err, o = json.Unmarshal(e.Body, &v), &v
	case KindVersionAction:
		var v VersionAction
		err, o = json.Unmarshal(e.Body, &v), &v
	case KindDestroySecret:
		var v DestroySecret
		err, o = json.Unmarshal(e.Body, &v), &v
	case KindPutSecretMeta:
		var v PutSecretMeta
		err, o = json.Unmarshal(e.Body, &v), &v
	default:
		return nil, fmt.Errorf("op: unknown kind %d", uint16(e.K))
	}
	if err != nil {
		return nil, fmt.Errorf("op: decode %s: %w", e.K, err)
	}
	return o, nil
}
