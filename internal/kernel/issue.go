package kernel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/mcarey42/signet/internal/keys"
	"github.com/mcarey42/signet/internal/op"
	"github.com/mcarey42/signet/internal/store"
)

// This is the one mint path: issue → claims → filter → serialize → verify.
//
// Online dialects (KV) never come here; for them the session token *is* the
// credential and policy is evaluated per use. Offline dialects (OIDC, SSH) do,
// because they hand a relying party something it will accept later without
// asking anyone — which is exactly why every guard has to be applied here, once
// (docs/06, charter principles 5 and 6).

// RolePolicy carries a role's security floor. The freshness tier lives on the
// role, never on a binding: if it lived on bindings, a second, weaker binding
// for the same role would silently downgrade it (E-13 F3).
type RolePolicy struct {
	Role        string `json:"role"`
	MinTier     int    `json:"min_tier"`               // 1 offline, 2 short-leash, 3 online-only, 4 step-up
	RequiredAMR string `json:"required_amr,omitempty"` // e.g. "webauthn"
	MaxTTLSec   int64  `json:"max_ttl_sec,omitempty"`
	OwnerScope  string `json:"owner_scope"`
}

// TierOnlineOnly and above may never be embedded in an offline credential.
const (
	TierOffline    = 1
	TierShortLeash = 2
	TierOnlineOnly = 3
	TierStepUp     = 4
)

func applyPutRolePolicy(tx *store.Tx, o *op.PutRolePolicy) op.Result {
	var p RolePolicy
	if err := json.Unmarshal(o.Policy, &p); err != nil {
		return op.Result{Err: fmt.Errorf("role policy: %w", err)}
	}
	if p.Role == "" || !KnownRole(p.Role) {
		return op.Result{Err: fmt.Errorf("role policy: unknown role %q", p.Role)}
	}
	if err := ValidatePath(p.OwnerScope); err != nil {
		return op.Result{Err: fmt.Errorf("role policy scope: %w", err)}
	}
	if p.MinTier < TierOffline || p.MinTier > TierStepUp {
		return op.Result{Err: fmt.Errorf("role policy: tier %d out of range", p.MinTier)}
	}
	if err := requireDomainAuthority(tx, o.Grantor, o.AtSec); err != nil {
		return op.Result{Err: fmt.Errorf("role policy: %w", err)}
	}
	if err := tx.Put(store.BucketRolePolicy, p.Role, o.Policy); err != nil {
		return op.Result{Err: err}
	}
	return op.Result{}
}

func applyPutKey(tx *store.Tx, o *op.PutKey) op.Result {
	if o.ID == "" || o.Purpose == "" || len(o.Key) == 0 {
		return op.Result{Err: errors.New("key: missing id, purpose, or material")}
	}
	if err := requireDomainAuthority(tx, o.Grantor, o.AtSec); err != nil {
		return op.Result{Err: fmt.Errorf("key: %w", err)}
	}
	if err := tx.Put(store.BucketKeys, keyRecordKey(o.Purpose, o.ID), o.Key); err != nil {
		return op.Result{Err: err}
	}
	// The active key for a purpose is a pointer, so rotation is one write and
	// the previous key stays published for verification.
	if o.Active {
		if err := tx.Put(store.BucketKeys, activePointer(o.Purpose), []byte(o.ID)); err != nil {
			return op.Result{Err: err}
		}
	}
	return op.Result{}
}

func keyRecordKey(purpose, id string) string { return purpose + "/" + id }
func activePointer(purpose string) string    { return "active:" + purpose }

// Claims are what a credential asserts. They are produced once, filtered once,
// and handed to a serializer that cannot add to them.
type Claims struct {
	Subject   string         `json:"sub"`
	Principal op.ID          `json:"-"`
	Roles     []string       `json:"groups"`
	Audience  string         `json:"aud"`
	IssuedSec int64          `json:"iat"`
	ExpirySec int64          `json:"exp"`
	NotBefore int64          `json:"nbf"`
	Issuer    string         `json:"iss"`
	AMR       []string       `json:"amr,omitempty"`
	AuthTime  int64          `json:"auth_time,omitempty"`
	Extra     map[string]any `json:"-"`
}

// Serializer turns filtered claims into a credential in some dialect's format,
// then re-checks the bytes it produced.
//
// Serialize receives claims that are already tier-filtered, so a serializer has
// no way to embed a role the gate excluded — the filtering is not a rule
// serializers are asked to follow, it is a property of what they are given.
type Serializer interface {
	Serialize(c Claims, k *keys.Key) ([]byte, error)
	Verify(cred []byte, c Claims, k *keys.Key) error
}

// IssueRequest is one credential request.
type IssueRequest struct {
	Audience string
	Scope    string // the resource-tree scope the credential speaks for
	TTL      time.Duration
	Purpose  keys.Purpose
	Issuer   string
	Extra    map[string]any
}

// Issue mints an offline credential.
func (k *Kernel) Issue(ctx context.Context, s Session, req IssueRequest, ser Serializer) ([]byte, Claims, error) {
	if req.Scope == "" {
		req.Scope = "/"
	}
	if err := ValidatePath(req.Scope); err != nil {
		return nil, Claims{}, err
	}

	now := k.now()
	var (
		claims Claims
		key    *keys.Key
	)
	if err := k.store.View(func(tx *store.Tx) error {
		principal, ok, err := loadPrincipal(tx, s.Principal)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: principal %s", ErrNotFound, s.Principal)
		}

		roles, ttl, err := k.filterRoles(tx, s, req, now)
		if err != nil {
			return err
		}
		claims = Claims{
			Subject: principal.Path, Principal: principal.ID, Roles: roles,
			Audience: req.Audience, Issuer: req.Issuer,
			IssuedSec: now.Unix(), NotBefore: now.Unix(),
			ExpirySec: now.Add(ttl).Unix(),
			AMR:       s.AMR, AuthTime: s.AuthTime,
			Extra: req.Extra,
		}
		key, err = loadActiveKey(tx, req.Purpose)
		return err
	}); err != nil {
		return nil, Claims{}, err
	}

	cred, err := ser.Serialize(claims, key)
	if err != nil {
		return nil, Claims{}, err
	}
	// Verify-after-sign. The serializer re-reads what it produced; a credential
	// that fails here is never returned, because once released it cannot be
	// recalled.
	if err := ser.Verify(cred, claims, key); err != nil {
		return nil, Claims{}, fmt.Errorf("refusing to release credential: %w", err)
	}
	return cred, claims, nil
}

// filterRoles resolves the roles a session may carry offline, and the lifetime
// the strictest of them permits.
//
// Rights are additive — a principal carries the union of its bindings — but
// constraints are not: the shortest TTL and the strictest requirement win. A
// role the caller holds but may not carry offline is simply absent, which is
// how tier 3 becomes structurally impossible to embed rather than merely
// discouraged (E-01 K-2).
func (k *Kernel) filterRoles(tx *store.Tx, s Session, req IssueRequest, now time.Time) ([]string, time.Duration, error) {
	bindings, err := LoadBindings(tx, s.Principal)
	if err != nil {
		return nil, 0, err
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	seen := map[string]bool{}
	var roles []string
	for _, b := range bindings {
		if b.NotAfter != 0 && now.Unix() >= b.NotAfter {
			continue
		}
		// The credential speaks for a scope; only bindings covering it apply.
		if !ScopeCovers(b.Scope, req.Scope) {
			continue
		}
		policy, err := loadRolePolicy(tx, b.Role)
		if err != nil {
			return nil, 0, err
		}
		if policy.MinTier >= TierOnlineOnly {
			continue // never embeddable in something verified offline
		}
		if policy.RequiredAMR != "" && !containsExact(s.AMR, policy.RequiredAMR) {
			continue // the session was not established strongly enough for this role
		}
		if policy.MaxTTLSec > 0 {
			if cap := time.Duration(policy.MaxTTLSec) * time.Second; cap < ttl {
				ttl = cap
			}
		}
		if !seen[b.Role] {
			seen[b.Role] = true
			roles = append(roles, b.Role)
		}
	}
	// A JWT's claims end up in logs and dashboards; stable ordering keeps them
	// diffable.
	sort.Strings(roles)
	// A session never outlives itself.
	if s.Expiry != 0 {
		if max := time.Until(time.Unix(s.Expiry, 0)); max > 0 && max < ttl {
			ttl = max
		}
	}
	if ttl <= 0 {
		return nil, 0, errors.New("session has expired")
	}
	return roles, ttl, nil
}

func loadRolePolicy(tx *store.Tx, role string) (RolePolicy, error) {
	raw, ok, err := tx.Get(store.BucketRolePolicy, role)
	if err != nil {
		return RolePolicy{}, err
	}
	if !ok {
		// No policy means tier 1: offline-embeddable with no extra requirement.
		return RolePolicy{Role: role, MinTier: TierOffline}, nil
	}
	var p RolePolicy
	return p, json.Unmarshal(raw, &p)
}

func loadActiveKey(tx *store.Tx, purpose keys.Purpose) (*keys.Key, error) {
	id, ok, err := tx.Get(store.BucketKeys, activePointer(string(purpose)))
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%w: no active %s key", ErrNotFound, purpose)
	}
	raw, ok, err := tx.Get(store.BucketKeys, keyRecordKey(string(purpose), string(id)))
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%w: %s key %s", ErrNotFound, purpose, id)
	}
	var key keys.Key
	return &key, json.Unmarshal(raw, &key)
}

// --- service methods ------------------------------------------------------

// InstallKey stores a signing key, optionally making it the active one.
func (k *Kernel) InstallKey(ctx context.Context, grantor op.ID, key *keys.Key, active bool) error {
	blob, err := json.Marshal(key)
	if err != nil {
		return err
	}
	_, err = k.prop.Propose(ctx, &op.PutKey{
		Header: k.header(grantor), ID: key.ID, Purpose: string(key.Purpose),
		Key: blob, Active: active, Grantor: grantor,
	})
	return err
}

// PutRolePolicy sets a role's security floor.
func (k *Kernel) PutRolePolicy(ctx context.Context, grantor op.ID, p RolePolicy) error {
	blob, err := json.Marshal(p)
	if err != nil {
		return err
	}
	_, err = k.prop.Propose(ctx, &op.PutRolePolicy{Header: k.header(grantor), Role: p.Role, Policy: blob, Grantor: grantor})
	return err
}

// ActiveKey loads the current signing key for a purpose.
func (k *Kernel) ActiveKey(ctx context.Context, purpose keys.Purpose) (*keys.Key, error) {
	var key *keys.Key
	err := k.store.View(func(tx *store.Tx) error {
		var err error
		key, err = loadActiveKey(tx, purpose)
		return err
	})
	return key, err
}

// PublicKeys returns every key for a purpose, retired ones included: a
// credential signed before a rotation must keep verifying until it expires.
func (k *Kernel) PublicKeys(ctx context.Context, purpose keys.Purpose) ([]*keys.Key, error) {
	var out []*keys.Key
	err := k.store.View(func(tx *store.Tx) error {
		return tx.ScanPrefix(store.BucketKeys, string(purpose)+"/", func(_ string, val []byte) bool {
			var key keys.Key
			if json.Unmarshal(val, &key) == nil {
				out = append(out, &key)
			}
			return true
		})
	})
	return out, err
}
