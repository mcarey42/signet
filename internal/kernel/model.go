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
	ID       op.ID  `json:"id"`
	Subject  op.ID  `json:"subject"`
	Role     string `json:"role"`
	Scope    string `json:"scope"`
	Grantor  op.ID  `json:"grantor"`
	NotAfter int64  `json:"not_after,omitempty"` // 0 = no expiry
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
