package kernel

import (
	"fmt"

	"github.com/mcarey42/signet/internal/op"
)

// Principal is anything that can hold a credential. The ID is stable and never
// reused; Path is a mutable name (docs/13 F1).
type Principal struct {
	ID   op.ID  `json:"id"`
	Path string `json:"path"`
	Type string `json:"type"`
}

// Binding grants Role at Scope to Subject. Scope inherits downward.
type Binding struct {
	ID      op.ID  `json:"id"`
	Subject op.ID  `json:"subject"`
	Role    string `json:"role"`
	Scope   string `json:"scope"`
	Grantor op.ID  `json:"grantor"`
	// NotAfter makes a grant just-in-time: after it, the binding simply stops
	// being honored. No sweep, no revocation — the authority was never held
	// past T, so nothing needs taking away (docs/13).
	NotAfter int64 `json:"not_after,omitempty"` // 0 = no expiry

	// ActivationRequired splits eligibility from possession: the subject may
	// ask for this authority but does not hold it until an activation is live.
	// This is the PAM half of docs/13 — standing access is what an attacker
	// inherits along with a session, and eligibility is not standing access.
	ActivationRequired bool `json:"activation_required,omitempty"`
	// MaxActivationSec bounds how long one activation may last. Zero means the
	// domain default; an activation is always additionally clamped to NotAfter.
	MaxActivationSec int64 `json:"max_activation_sec,omitempty"`
	// ApprovalRequired makes activation somebody else's decision. MinApprovers
	// defaults to 1, and the requester never counts toward it.
	ApprovalRequired bool `json:"approval_required,omitempty"`
	MinApprovers     int  `json:"min_approvers,omitempty"`
	// StepUpAMR lists authentication methods the requester's session must carry
	// to activate — "the password you already typed" is not a second factor for
	// privilege elevation. StepUpMaxAgeSec additionally requires that
	// authentication to be recent, so a long-lived session cannot coast on an
	// elevation it performed hours ago.
	StepUpAMR       []string `json:"step_up_amr,omitempty"`
	StepUpMaxAgeSec int64    `json:"step_up_max_age_sec,omitempty"`
}

// ActivationState is where an activation sits in its short life.
type ActivationState string

const (
	// ActivationPending is requested but not yet granted: eligible, waiting.
	ActivationPending ActivationState = "pending"
	// ActivationActive is live and conferring authority, until Expiry.
	ActivationActive ActivationState = "active"
	ActivationDenied ActivationState = "denied"
	// ActivationKilled was cut short. Kept rather than deleted: the record of
	// who held what and when is the point of the whole mechanism.
	ActivationKilled ActivationState = "killed"
)

// Activation is runtime state — never declarative, never in git (docs/13 F9).
//
// It is a grant window over one binding, not a grant of its own. Every renewal
// re-validates both this record and the binding beneath it, so revoking either
// ends the access at the next renewal without a sweep.
type Activation struct {
	ID      op.ID  `json:"id"`
	Subject op.ID  `json:"subject"`
	Binding op.ID  `json:"binding"`
	Role    string `json:"role"`
	Scope   string `json:"scope"`
	Reason  string `json:"reason"`

	State       ActivationState `json:"state"`
	RequestedAt int64           `json:"requested_at"`
	// Expiry is set when the activation becomes active, clamped to both the
	// binding's MaxActivationSec and its NotAfter (JIT-on-JIT: no "eligible
	// until Friday, activated Thursday 23:59 for four hours" leak).
	Expiry     int64   `json:"expiry,omitempty"`
	Approvals  []op.ID `json:"approvals,omitempty"`
	DecidedBy  op.ID   `json:"decided_by,omitempty"`
	DecidedAt  int64   `json:"decided_at,omitempty"`
	KillReason string  `json:"kill_reason,omitempty"`
}

// Live reports whether this activation confers authority right now.
func (a *Activation) Live(nowSec int64) bool {
	return a.State == ActivationActive && a.Expiry > nowSec
}

// Session is the runtime half of the model: proof that a principal
// authenticated. It carries no roles — policy is evaluated per use for online
// dialects, and per renewal for offline ones (docs/06).
type Session struct {
	ID op.ID `json:"id"`
	// TokenHash is the stored form; the raw token exists only in the client's
	// hands and in the proposer's return value.
	TokenHash        string   `json:"token_hash"`
	Principal        op.ID    `json:"principal"`
	AMR              []string `json:"amr,omitempty"`
	AuthTime         int64    `json:"auth_time"`
	Expiry           int64    `json:"expiry"` // 0 = non-expiring
	Verifier         string   `json:"verifier,omitempty"`
	SenderBindingRef string   `json:"sbk_ref,omitempty"`
}

// SecretMeta is everything about a secret except its values: the version
// history, the policy attached to it, and the operator's own labels. Values
// live separately, one record per version, so reading metadata never decrypts
// a secret and trimming history is a bounded operation.
type SecretMeta struct {
	Path           string                 `json:"path"`
	CreatedSec     int64                  `json:"created"`
	UpdatedSec     int64                  `json:"updated"`
	CurrentVersion uint64                 `json:"current_version"`
	OldestVersion  uint64                 `json:"oldest_version"`
	MaxVersions    uint32                 `json:"max_versions"`
	CASRequired    bool                   `json:"cas_required"`
	CustomMetadata map[string]string      `json:"custom_metadata,omitempty"`
	Versions       map[uint64]VersionMeta `json:"versions"`
}

// VersionMeta records the fate of one version. Deletion is reversible and
// leaves the data in place; destruction erases it.
type VersionMeta struct {
	CreatedSec  int64 `json:"created"`
	DeletionSec int64 `json:"deletion,omitempty"`
	Destroyed   bool  `json:"destroyed,omitempty"`
}

// Readable reports whether a version still yields data.
func (v VersionMeta) Readable() bool { return v.DeletionSec == 0 && !v.Destroyed }

// Secret is one version's value together with the metadata describing it.
type Secret struct {
	Path    string
	Data    map[string]string
	Version uint64
	Meta    VersionMeta
	All     SecretMeta
}

// DefaultMaxVersions matches Vault's, so operators carry their intuitions over.
const DefaultMaxVersions = 10

// Issuer is a pinned attestation trust anchor (docs/04).
type Issuer struct {
	ID       op.ID  `json:"id"`
	Name     string `json:"name"`
	Verifier string `json:"verifier"`
	URL      string `json:"url"`
	Audience string `json:"audience"`
	JWKS     []byte `json:"jwks"`
}

// Mapping translates a verified identity into a principal. Matchers are exact
// lists, deliberately not patterns.
type Mapping struct {
	ID              op.ID    `json:"id"`
	Name            string   `json:"name"`
	Issuer          string   `json:"issuer"`
	Namespaces      []string `json:"namespaces"`
	ServiceAccounts []string `json:"service_accounts"`
	Principal       op.ID    `json:"principal"`
	TTLSeconds      int64    `json:"ttl_seconds"`
	Grantor         op.ID    `json:"grantor"`
}

// Matches reports whether a verified identity satisfies this rule. An empty
// matcher list matches nothing: a rule must say what it accepts, because a
// rule that accidentally accepts everything is an authentication bypass.
func (m Mapping) Matches(namespace, account string) bool {
	return containsExact(m.Namespaces, namespace) && containsExact(m.ServiceAccounts, account)
}

func containsExact(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// Verb is the kernel's authorization vocabulary. Dialects map their own wire
// surface onto it; the kernel never learns Vault's or OIDC's nouns.
type Verb string

const (
	VerbRead   Verb = "read"
	VerbList   Verb = "list"
	VerbWrite  Verb = "write"
	VerbDelete Verb = "delete"
	VerbAdmin  Verb = "admin"
	// VerbSign is certificate issuance. It is its own verb because the right to
	// mint an identity is not the right to write a secret.
	VerbSign Verb = "sign"
)

// Reserved roles for the MVP. These are Signet-dialect-owned mappings — the
// same shape as Grafana owning "infra-admin -> Admin" — not a general policy
// language (docs/13 F8).
var roleVerbs = map[string]map[Verb]bool{
	"kv-reader":    {VerbRead: true, VerbList: true},
	"kv-writer":    {VerbRead: true, VerbList: true, VerbWrite: true},
	"kv-admin":     {VerbRead: true, VerbList: true, VerbWrite: true, VerbDelete: true},
	"pki-signer":   {VerbSign: true},
	"domain-admin": {VerbRead: true, VerbList: true, VerbWrite: true, VerbDelete: true, VerbAdmin: true, VerbSign: true},
}

// adminRoles may create bindings (subject to delegation-only-narrows).
var adminRoles = map[string]bool{"domain-admin": true}

func KnownRole(r string) bool { _, ok := roleVerbs[r]; return ok }

func roleGrants(role string, v Verb) bool { return roleVerbs[role][v] }

var validPrincipalTypes = map[string]bool{
	"human": true, "service": true, "machine": true,
	"workload": true, "group": true, "domain": true,
}

func validateType(t string) error {
	if !validPrincipalTypes[t] {
		return fmt.Errorf("principal type %q unknown", t)
	}
	return nil
}

func bindingKey(subject, id op.ID) string { return string(subject) + "/" + string(id) }
