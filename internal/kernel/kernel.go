package kernel

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/mcarey42/signet/internal/attest"
	"github.com/mcarey42/signet/internal/op"
	"github.com/mcarey42/signet/internal/seal"
	"github.com/mcarey42/signet/internal/store"
)

var (
	ErrNotFound  = errors.New("not found")
	ErrDenied    = errors.New("permission denied")
	ErrNoSession = errors.New("invalid or expired token")
)

// Proposer submits an Op for consensus and returns what Apply computed. The
// kernel defines this port and the fsm package implements it, so the kernel
// never imports Raft.
type Proposer interface {
	Propose(ctx context.Context, o op.Op) (op.Result, error)
}

// Kernel is the dialect-facing service. Dialects call these methods; only the
// kernel constructs and proposes Ops, and authorization happens inside each
// method rather than as a separate call a dialect could forget to make
// (charter principle 5).
type Kernel struct {
	store     *store.Store
	prop      Proposer
	verifiers *attest.Registry
	seal      seal.Seal
	now       func() time.Time
}

// New builds a kernel. The seal is what opens sealed private key material; a
// kernel without one can still serve secrets and policy, but cannot sign.
func New(s *store.Store, p Proposer, sl seal.Seal) *Kernel {
	return &Kernel{store: s, prop: p, verifiers: attest.Default(), seal: sl, now: time.Now}
}

// Seal exposes the seal for the few callers that must open sealed material
// themselves, such as a dialect publishing a public key set.
func (k *Kernel) Seal() seal.Seal { return k.seal }

// SetClock is for tests only.
func (k *Kernel) SetClock(f func() time.Time) { k.now = f }

func (k *Kernel) header(actor op.ID) op.Header {
	return op.Header{Actor: actor, AtSec: k.now().Unix()}
}

// --- Authentication -------------------------------------------------------

// Evidence is what a caller presents to prove who it is. The dialect passes the
// material through untouched: it never parses, inspects, or verifies it, so a
// dialect bug cannot become an authentication bypass.
type Evidence struct {
	// Rule names the mapping rule to evaluate — Vault calls this a "role", and
	// clients send it as one. It selects policy, never trust: the rule decides
	// which registered issuer verifies the material.
	Rule     string
	Material []byte
}

// Login verifies evidence and, if a mapping rule accepts it, mints a session.
//
// The order matters. Verification happens first and against a *pinned* issuer
// chosen by configuration, so evidence minted for another audience or signed by
// another key is rejected before any policy is consulted. Only then does a rule
// decide which principal the proven identity becomes.
func (k *Kernel) Login(ctx context.Context, ev Evidence) (string, Session, error) {
	var (
		mapping Mapping
		issuer  Issuer
	)
	if err := k.store.View(func(tx *store.Tx) error {
		raw, ok, err := tx.Get(store.BucketMappings, ev.Rule)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("no mapping rule named %q", ev.Rule)
		}
		if err := json.Unmarshal(raw, &mapping); err != nil {
			return err
		}
		raw, ok, err = tx.Get(store.BucketIssuers, mapping.Issuer)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("mapping %q names unregistered issuer %q", ev.Rule, mapping.Issuer)
		}
		return json.Unmarshal(raw, &issuer)
	}); err != nil {
		return "", Session{}, err
	}

	verifier, err := k.verifiers.Get(issuer.Verifier)
	if err != nil {
		return "", Session{}, err
	}
	id, err := verifier.Verify(ev.Material, attest.Issuer{
		Name: issuer.Name, URL: issuer.URL, Audience: issuer.Audience, JWKS: issuer.JWKS,
	}, k.now())
	if err != nil {
		return "", Session{}, err
	}
	if !mapping.Matches(id.Namespace, id.Account) {
		return "", Session{}, fmt.Errorf("mapping %q does not accept %s/%s", ev.Rule, id.Namespace, id.Account)
	}

	ttl := time.Duration(mapping.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = time.Hour
	}
	// The session never outlives the evidence that produced it.
	if !id.Expiry.IsZero() {
		if max := time.Until(id.Expiry); max > 0 && max < ttl {
			ttl = max
		}
	}
	return k.CreateSession(ctx, mapping.Principal, mapping.Principal, ttl, []string{id.Verifier}, id.Verifier)
}

// --- Sessions -------------------------------------------------------------

// CreateSession mints a bearer token for a principal.
//
// The raw token is generated here, at propose time; only its hash travels
// through the log. The caller receives the token from this return value — the
// only place it ever exists outside the client (docs/15 contract 2).
func (k *Kernel) CreateSession(ctx context.Context, actor, principal op.ID, ttl time.Duration, amr []string, verifier string) (string, Session, error) {
	token, err := newToken()
	if err != nil {
		return "", Session{}, err
	}
	now := k.now()
	var expiry int64
	if ttl > 0 {
		expiry = now.Add(ttl).Unix()
	}
	id, err := newID()
	if err != nil {
		return "", Session{}, err
	}
	o := &op.CreateSession{
		Header: k.header(actor), ID: id, TokenHash: HashToken(token),
		Principal: principal, AMR: amr, AuthTime: now.Unix(),
		Expiry: expiry, Verifier: verifier,
	}
	if _, err := k.prop.Propose(ctx, o); err != nil {
		return "", Session{}, err
	}
	return token, Session{
		ID: id, TokenHash: o.TokenHash, Principal: principal, AMR: amr,
		AuthTime: now.Unix(), Expiry: expiry, Verifier: verifier,
	}, nil
}

// LookupSession resolves a bearer token. Expiry is evaluated lazily on read —
// there is no sweeper, matching how every other time-bound grant in Signet
// simply stops being honored.
func (k *Kernel) LookupSession(ctx context.Context, token string) (Session, error) {
	var s Session
	err := k.store.View(func(tx *store.Tx) error {
		raw, ok, err := tx.Get(store.BucketSessions, HashToken(token))
		if err != nil {
			return err
		}
		if !ok {
			return ErrNoSession
		}
		return json.Unmarshal(raw, &s)
	})
	if err != nil {
		return Session{}, err
	}
	if s.Expiry != 0 && k.now().Unix() >= s.Expiry {
		return Session{}, ErrNoSession
	}
	return s, nil
}

func (k *Kernel) RevokeSession(ctx context.Context, actor op.ID, token string) error {
	_, err := k.prop.Propose(ctx, &op.RevokeSession{Header: k.header(actor), TokenHash: HashToken(token)})
	return err
}

// --- Secrets --------------------------------------------------------------

// GetSecret authorizes and reads one version. Version 0 means the current one.
// For online dialects like KV, policy is evaluated per use — fresher than any
// renewal interval could be.
func (k *Kernel) GetSecret(ctx context.Context, s Session, path string, version uint64) (Secret, error) {
	if err := ValidatePath(path); err != nil {
		return Secret{}, err
	}
	var sec Secret
	err := k.store.View(func(tx *store.Tx) error {
		ok, err := HasAuthority(tx, s.Principal, VerbRead, path, k.now().Unix())
		if err != nil {
			return err
		}
		if !ok {
			return ErrDenied
		}
		m, found, err := loadSecretMeta(tx, path)
		if err != nil || !found {
			if err == nil {
				err = ErrNotFound
			}
			return err
		}
		if version == 0 {
			version = m.CurrentVersion
		}
		vm, ok := m.Versions[version]
		// A deleted or destroyed version reads as absent. Consumers already
		// treat "no data" and "no secret" identically, so there is no reason to
		// reproduce Vault's 404-with-a-body quirk.
		if !ok || !vm.Readable() {
			return ErrNotFound
		}
		raw, found, err := tx.Get(store.BucketSecretData, secretDataKey(path, version))
		if err != nil || !found {
			if err == nil {
				err = ErrNotFound
			}
			return err
		}
		var data map[string]string
		if err := json.Unmarshal(raw, &data); err != nil {
			return err
		}
		sec = Secret{Path: path, Data: data, Version: version, Meta: vm, All: m}
		return nil
	})
	return sec, err
}

// SecretMetadata reads a secret's version history and policy without touching
// its values.
func (k *Kernel) SecretMetadata(ctx context.Context, s Session, path string) (SecretMeta, error) {
	if err := ValidatePath(path); err != nil {
		return SecretMeta{}, err
	}
	var m SecretMeta
	err := k.store.View(func(tx *store.Tx) error {
		ok, err := HasAuthority(tx, s.Principal, VerbRead, path, k.now().Unix())
		if err != nil {
			return err
		}
		if !ok {
			return ErrDenied
		}
		var found bool
		m, found, err = loadSecretMeta(tx, path)
		if err == nil && !found {
			err = ErrNotFound
		}
		return err
	})
	return m, err
}

// ListSecrets returns the immediate children of a prefix.
//
// Listing is its own verb: knowing which secrets exist is a disclosure even
// when their values stay sealed, so a reader of one subtree cannot enumerate
// another.
func (k *Kernel) ListSecrets(ctx context.Context, s Session, prefix string) ([]string, error) {
	if err := ValidatePath(prefix); err != nil {
		return nil, err
	}
	var keys []string
	err := k.store.View(func(tx *store.Tx) error {
		ok, err := HasAuthority(tx, s.Principal, VerbList, prefix, k.now().Unix())
		if err != nil {
			return err
		}
		if !ok {
			return ErrDenied
		}
		keys, err = listChildren(tx, prefix)
		return err
	})
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, ErrNotFound // Vault reports an empty list as absent
	}
	return keys, nil
}

// VersionAction soft-deletes, restores, or destroys versions of a secret.
func (k *Kernel) VersionAction(ctx context.Context, s Session, path string, versions []uint64, mode op.VersionMode) error {
	if err := ValidatePath(path); err != nil {
		return err
	}
	// Destroying data is not the same authority as replacing it.
	verb := VerbWrite
	if mode == op.VersionDestroy {
		verb = VerbDelete
	}
	if err := k.authorize(s, verb, path); err != nil {
		return err
	}
	_, err := k.prop.Propose(ctx, &op.VersionAction{
		Header: k.header(s.Principal), Path: path, Versions: versions, Mode: mode,
	})
	return err
}

// DestroySecret removes a secret and its whole history.
func (k *Kernel) DestroySecret(ctx context.Context, s Session, path string) error {
	if err := ValidatePath(path); err != nil {
		return err
	}
	if err := k.authorize(s, VerbDelete, path); err != nil {
		return err
	}
	_, err := k.prop.Propose(ctx, &op.DestroySecret{Header: k.header(s.Principal), Path: path})
	return err
}

// PutSecretMetadata writes the policy attached to a secret.
func (k *Kernel) PutSecretMetadata(ctx context.Context, s Session, path string, custom map[string]string, maxVersions uint32, casRequired *bool) error {
	if err := ValidatePath(path); err != nil {
		return err
	}
	if err := k.authorize(s, VerbWrite, path); err != nil {
		return err
	}
	// Weakening a protection is a destructive act, so it needs destructive
	// authority. Lowering MaxVersions makes the next write erase history;
	// clearing CASRequired removes the guard against a blind overwrite. Both
	// were reachable with `write` alone, which let a writer with no delete
	// authority destroy versions it could not delete directly.
	if maxVersions > 0 || (casRequired != nil && !*casRequired) {
		if err := k.needsDeleteToWeaken(ctx, s, path, maxVersions, casRequired); err != nil {
			return err
		}
	}
	_, err := k.prop.Propose(ctx, &op.PutSecretMeta{
		Header: k.header(s.Principal), Path: path,
		CustomMetadata: custom, MaxVersions: maxVersions, CASRequired: casRequired,
	})
	return err
}

// needsDeleteToWeaken requires delete authority when a metadata write would
// lower a protection rather than raise one. Raising stays a plain write.
func (k *Kernel) needsDeleteToWeaken(ctx context.Context, s Session, path string,
	maxVersions uint32, casRequired *bool) error {

	var cur SecretMeta
	var found bool
	if err := k.store.View(func(tx *store.Tx) error {
		m, ok, err := loadSecretMeta(tx, path)
		cur, found = m, ok
		return err
	}); err != nil {
		return err
	}
	if !found {
		return nil // nothing to weaken yet
	}
	weakens := (maxVersions > 0 && cur.MaxVersions > 0 && maxVersions < cur.MaxVersions) ||
		(casRequired != nil && !*casRequired && cur.CASRequired)
	if !weakens {
		return nil
	}
	if err := k.authorize(s, VerbDelete, path); err != nil {
		return fmt.Errorf(
			"this metadata change would weaken a protection on %s, which needs delete authority "+
				"there: lowering max_versions makes the next write erase history, and clearing "+
				"cas_required removes the guard against a blind overwrite: %w", path, err)
	}
	return nil
}

// PutSecret authorizes, then proposes. The CAS check itself runs inside Apply,
// where the serialized writer makes it race-free.
func (k *Kernel) PutSecret(ctx context.Context, s Session, path string, data map[string]string, cas *uint64) (uint64, error) {
	if err := ValidatePath(path); err != nil {
		return 0, err
	}
	if err := k.authorize(s, VerbWrite, path); err != nil {
		return 0, err
	}
	res, err := k.prop.Propose(ctx, &op.PutSecret{Header: k.header(s.Principal), Path: path, Data: data, CAS: cas})
	if err != nil {
		return 0, err
	}
	return res.Version, nil
}

// --- Admin plane ----------------------------------------------------------

// PutPrincipal creates or renames a principal. actor may be empty only during
// genesis bootstrap.
func (k *Kernel) PutPrincipal(ctx context.Context, actor op.ID, id op.ID, path, typ string) (op.ID, error) {
	if id == "" {
		var err error
		if id, err = newID(); err != nil {
			return "", err
		}
	}
	res, err := k.prop.Propose(ctx, &op.PutPrincipal{
		Header: k.header(actor), ID: id, Path: path, Type: typ, Grantor: actor,
	})
	if err != nil {
		return "", err
	}
	return res.ID, nil
}

// PutBinding grants a role. Delegation-only-narrows is enforced inside Apply,
// against the serialized state, not here.
func (k *Kernel) PutBinding(ctx context.Context, grantor, subject op.ID, role, scope string, notAfter int64) (op.ID, error) {
	return k.PutBindingSpec(ctx, grantor, Binding{
		Subject: subject, Role: role, Scope: scope, NotAfter: notAfter,
	})
}

// PutBindingSpec grants a binding with its full shape, including whether it is
// held outright or merely offered for activation.
func (k *Kernel) PutBindingSpec(ctx context.Context, grantor op.ID, b Binding) (op.ID, error) {
	id, err := newID()
	if err != nil {
		return "", err
	}
	res, err := k.prop.Propose(ctx, &op.PutBinding{
		Header: k.header(grantor), ID: id, Subject: b.Subject,
		Role: b.Role, Scope: b.Scope, Grantor: grantor, NotAfter: b.NotAfter,
		ActivationRequired: b.ActivationRequired, MaxActivationSec: b.MaxActivationSec,
		ApprovalRequired: b.ApprovalRequired, MinApprovers: b.MinApprovers,
		StepUpAMR: b.StepUpAMR, StepUpMaxAgeSec: b.StepUpMaxAgeSec,
	})
	if err != nil {
		return "", err
	}
	return res.ID, nil
}

// PutIssuer registers a pinned attestation trust anchor.
func (k *Kernel) PutIssuer(ctx context.Context, grantor op.ID, name, verifier, url, audience string, jwks []byte) (op.ID, error) {
	id, err := newID()
	if err != nil {
		return "", err
	}
	res, err := k.prop.Propose(ctx, &op.PutIssuer{
		Header: k.header(grantor), ID: id, Name: name, Verifier: verifier,
		URL: url, Audience: audience, JWKS: jwks, Grantor: grantor,
	})
	if err != nil {
		return "", err
	}
	return res.ID, nil
}

// PutMapping records which verified identities become which principal.
func (k *Kernel) PutMapping(ctx context.Context, grantor op.ID, m Mapping) (op.ID, error) {
	id, err := newID()
	if err != nil {
		return "", err
	}
	res, err := k.prop.Propose(ctx, &op.PutMapping{
		Header: k.header(grantor), ID: id, Name: m.Name, Issuer: m.Issuer,
		Namespaces: m.Namespaces, ServiceAccounts: m.ServiceAccounts,
		Principal: m.Principal, TTLSeconds: m.TTLSeconds, Grantor: grantor,
	})
	if err != nil {
		return "", err
	}
	return res.ID, nil
}

// PrincipalByPath resolves a name to its stable ID.
func (k *Kernel) PrincipalByPath(ctx context.Context, path string) (Principal, error) {
	var p Principal
	err := k.store.View(func(tx *store.Tx) error {
		id, ok, err := tx.Get(store.BucketPathIndex, path)
		if err != nil {
			return err
		}
		if !ok {
			return ErrNotFound
		}
		raw, ok, err := tx.Get(store.BucketPrincipals, string(id))
		if err != nil {
			return err
		}
		if !ok {
			return ErrNotFound
		}
		return json.Unmarshal(raw, &p)
	})
	return p, err
}

func (k *Kernel) authorize(s Session, v Verb, path string) error {
	var allowed bool
	err := k.store.View(func(tx *store.Tx) error {
		ok, err := HasAuthority(tx, s.Principal, v, path, k.now().Unix())
		allowed = ok
		return err
	})
	if err != nil {
		return err
	}
	if !allowed {
		return ErrDenied
	}
	return nil
}

// --- helpers --------------------------------------------------------------

// HashToken is the stored form of a bearer token.
func HashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "signet." + base64.RawURLEncoding.EncodeToString(b), nil
}

func newID() (op.ID, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return op.ID(hex.EncodeToString(b)), nil
}

// Errorf keeps dialect error wrapping terse.
func Errorf(format string, a ...any) error { return fmt.Errorf(format, a...) }
