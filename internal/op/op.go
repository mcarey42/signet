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
	KindInvalid           Kind = 0
	KindPutPrincipal      Kind = 1
	KindPutBinding        Kind = 2
	KindPutSecret         Kind = 3
	KindCreateSession     Kind = 4
	KindRevokeSession     Kind = 5
	KindPutIssuer         Kind = 6
	KindPutMapping        Kind = 7
	KindVersionAction     Kind = 8
	KindDestroySecret     Kind = 9
	KindPutSecretMeta     Kind = 10
	KindPutCA             Kind = 11
	KindPutPKIRole        Kind = 12
	KindRecordIssue       Kind = 13
	KindPutRolePolicy     Kind = 14
	KindPutKey            Kind = 15
	KindPutSSHRole        Kind = 16
	KindPutTrustBundle    Kind = 17
	KindPutWitness        Kind = 18
	KindRequestActivation Kind = 19
	KindActivationAction  Kind = 20
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
	case KindPutCA:
		return "PutCA"
	case KindPutPKIRole:
		return "PutPKIRole"
	case KindRecordIssue:
		return "RecordIssuance"
	case KindPutRolePolicy:
		return "PutRolePolicy"
	case KindPutKey:
		return "PutKey"
	case KindPutSSHRole:
		return "PutSSHRole"
	case KindPutTrustBundle:
		return "PutTrustBundle"
	case KindPutWitness:
		return "PutWitness"
	case KindRequestActivation:
		return "RequestActivation"
	case KindActivationAction:
		return "ActivationAction"
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
	// PAM fields: eligibility rather than possession. See kernel.Binding.
	ActivationRequired bool     `json:"activation_required,omitempty"`
	MaxActivationSec   int64    `json:"max_activation_sec,omitempty"`
	ApprovalRequired   bool     `json:"approval_required,omitempty"`
	MinApprovers       int      `json:"min_approvers,omitempty"`
	StepUpAMR          []string `json:"step_up_amr,omitempty"`
	StepUpMaxAgeSec    int64    `json:"step_up_max_age_sec,omitempty"`
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

// PutCA installs a certificate authority. The material carries the root
// certificate, the intermediate, and the intermediate's private key — never the
// root's, which the genesis ceremony hands to the operator instead of writing
// anywhere (docs/14, E-13 F6).
type PutCA struct {
	Header
	Name     string `json:"name"`
	Material []byte `json:"material"` // JSON-encoded ca.Material
	Grantor  ID     `json:"grantor"`
}

// PutPKIRole defines what a signing request may ask for.
type PutPKIRole struct {
	Header
	Name    string `json:"name"`
	Role    []byte `json:"role"` // JSON-encoded ca.Role
	Grantor ID     `json:"grantor"`
}

// RecordIssuance appends to the domain's issuance log. Every signature the CA
// key makes is recorded, so a certificate that exists but is absent from the
// log is the signal that the key was used outside Signet (docs/02).
type RecordIssuance struct {
	Header
	Serial    string   `json:"serial"`
	Role      string   `json:"role"`
	Subject   string   `json:"subject"`
	SANs      []string `json:"sans"`
	NotAfter  int64    `json:"not_after"`
	Requester ID       `json:"requester"`
}

// PutRolePolicy sets a role's security floor — the freshness tier and any
// requirement on how strongly the session must have been established. It lives
// on the role rather than on bindings so a second, weaker binding cannot
// downgrade it (E-13 F3).
type PutRolePolicy struct {
	Header
	Role    string `json:"role"`
	Policy  []byte `json:"policy"`
	Grantor ID     `json:"grantor"`
}

// PutKey installs a signing key. Keys are separated by purpose and rotated
// independently; retired keys stay stored so credentials already issued keep
// verifying until they expire.
type PutKey struct {
	Header
	ID      string `json:"id"`
	Purpose string `json:"purpose"`
	Key     []byte `json:"key"`
	Active  bool   `json:"active"`
	Grantor ID     `json:"grantor"`
}

// PutSSHRole defines which SSH principals a role may assert.
type PutSSHRole struct {
	Header
	Name    string `json:"name"`
	Role    []byte `json:"role"`
	Grantor ID     `json:"grantor"`
}

// PutTrustBundle stores the domain's root-signed trust bundle so every node
// serves the identical artifact.
//
// The bundle is opaque here on purpose. It was signed by the offline root, and
// re-encoding it would invalidate that signature — so it is carried and stored
// as the exact bytes that were signed, and this node's opinion of its contents
// never enters into it.
type PutTrustBundle struct {
	Header
	Domain  string `json:"domain"`
	Epoch   uint64 `json:"epoch"`
	Bundle  []byte `json:"bundle"`
	Grantor ID     `json:"grantor"`
}

// PutWitness records what this node has witnessed of another domain's audit
// chain. It is ordinary durable state: a witness that forgot on restart would
// be no witness at all.
type PutWitness struct {
	Header
	Domain  string `json:"domain"`
	Record  []byte `json:"record"`
	Grantor ID     `json:"grantor"`
}

// RequestActivation asks to hold an authority the requester is merely eligible
// for. It creates the record; it does not confer anything.
type RequestActivation struct {
	Header
	ID      ID     `json:"id"`
	Subject ID     `json:"subject"`
	Binding ID     `json:"binding"`
	Reason  string `json:"reason"`
	// ForSeconds is what the requester asked for. Apply clamps it — a request
	// is a request, not an instruction.
	ForSeconds int64 `json:"for_seconds"`
	// SessionAuthTime and SessionAMR carry the requester's authentication facts
	// at propose time, because Apply must be pure: it cannot go and look at a
	// session, and a step-up decision made from stale facts is no decision.
	SessionAuthTime int64    `json:"session_auth_time"`
	SessionAMR      []string `json:"session_amr,omitempty"`
}

// ActivationVerb is what is being done to an activation.
type ActivationVerb string

const (
	ActivationApprove ActivationVerb = "approve"
	ActivationDeny    ActivationVerb = "deny"
	ActivationKill    ActivationVerb = "kill"
)

// ActivationAction approves, denies, or kills an activation.
type ActivationAction struct {
	Header
	Subject ID             `json:"subject"`
	ID      ID             `json:"id"`
	Verb    ActivationVerb `json:"verb"`
	Actor2  ID             `json:"actor_id"` // the deciding principal
	Reason  string         `json:"reason,omitempty"`
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

func (PutPrincipal) OpKind() Kind      { return KindPutPrincipal }
func (PutBinding) OpKind() Kind        { return KindPutBinding }
func (PutSecret) OpKind() Kind         { return KindPutSecret }
func (CreateSession) OpKind() Kind     { return KindCreateSession }
func (RevokeSession) OpKind() Kind     { return KindRevokeSession }
func (PutIssuer) OpKind() Kind         { return KindPutIssuer }
func (VersionAction) OpKind() Kind     { return KindVersionAction }
func (DestroySecret) OpKind() Kind     { return KindDestroySecret }
func (PutSecretMeta) OpKind() Kind     { return KindPutSecretMeta }
func (PutMapping) OpKind() Kind        { return KindPutMapping }
func (PutCA) OpKind() Kind             { return KindPutCA }
func (PutPKIRole) OpKind() Kind        { return KindPutPKIRole }
func (RecordIssuance) OpKind() Kind    { return KindRecordIssue }
func (PutRolePolicy) OpKind() Kind     { return KindPutRolePolicy }
func (PutKey) OpKind() Kind            { return KindPutKey }
func (PutSSHRole) OpKind() Kind        { return KindPutSSHRole }
func (PutTrustBundle) OpKind() Kind    { return KindPutTrustBundle }
func (PutWitness) OpKind() Kind        { return KindPutWitness }
func (RequestActivation) OpKind() Kind { return KindRequestActivation }
func (ActivationAction) OpKind() Kind  { return KindActivationAction }

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
	case KindPutCA:
		var v PutCA
		err, o = json.Unmarshal(e.Body, &v), &v
	case KindPutPKIRole:
		var v PutPKIRole
		err, o = json.Unmarshal(e.Body, &v), &v
	case KindRecordIssue:
		var v RecordIssuance
		err, o = json.Unmarshal(e.Body, &v), &v
	case KindPutRolePolicy:
		var v PutRolePolicy
		err, o = json.Unmarshal(e.Body, &v), &v
	case KindPutKey:
		var v PutKey
		err, o = json.Unmarshal(e.Body, &v), &v
	case KindPutSSHRole:
		var v PutSSHRole
		err, o = json.Unmarshal(e.Body, &v), &v
	case KindPutTrustBundle:
		var v PutTrustBundle
		err, o = json.Unmarshal(e.Body, &v), &v
	case KindPutWitness:
		var v PutWitness
		err, o = json.Unmarshal(e.Body, &v), &v
	case KindRequestActivation:
		var v RequestActivation
		err, o = json.Unmarshal(e.Body, &v), &v
	case KindActivationAction:
		var v ActivationAction
		err, o = json.Unmarshal(e.Body, &v), &v
	default:
		return nil, fmt.Errorf("op: unknown kind %d", uint16(e.K))
	}
	if err != nil {
		return nil, fmt.Errorf("op: decode %s: %w", e.K, err)
	}
	return o, nil
}
