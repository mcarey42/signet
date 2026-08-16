package kernel

import (
	"fmt"

	"github.com/mcarey/signet/internal/op"
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

// Secret is one KV node. The MVP keeps only the latest value plus a monotonic
// version counter — the wire envelope is already KV v2-shaped, so version
// history lands behind an unchanged dialect later (docs/15).
type Secret struct {
	Path        string            `json:"path"`
	Data        map[string]string `json:"data"`
	Version     uint64            `json:"version"`
	CreatedSec  int64             `json:"created"`
	ModifiedSec int64             `json:"modified"`
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
)

// Reserved roles for the MVP. These are Signet-dialect-owned mappings — the
// same shape as Grafana owning "infra-admin -> Admin" — not a general policy
// language (docs/13 F8).
var roleVerbs = map[string]map[Verb]bool{
	"kv-reader":    {VerbRead: true, VerbList: true},
	"kv-writer":    {VerbRead: true, VerbList: true, VerbWrite: true},
	"kv-admin":     {VerbRead: true, VerbList: true, VerbWrite: true, VerbDelete: true},
	"domain-admin": {VerbRead: true, VerbList: true, VerbWrite: true, VerbDelete: true, VerbAdmin: true},
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
