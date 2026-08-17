package kernel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/mcarey42/signet/internal/ca"
	"github.com/mcarey42/signet/internal/op"
	"github.com/mcarey42/signet/internal/seal"
	"github.com/mcarey42/signet/internal/store"
)

// The PKI dialect is a serializer over these methods. Certificate issuance is
// the one place where authorization, an independent verification gate, and the
// issuance log all have to line up, so all three live here rather than in the
// dialect (charter principles 5 and 6).

func applyPutCA(tx *store.Tx, o *op.PutCA) op.Result {
	if o.Name == "" || len(o.Material) == 0 {
		return op.Result{Err: errors.New("ca: missing name or material")}
	}
	// Installing an authority is domain-wide power: whoever controls the CA
	// controls every identity it can assert.
	if err := requireDomainAuthority(tx, o.Grantor, o.AtSec); err != nil {
		return op.Result{Err: fmt.Errorf("ca: %w", err)}
	}
	var m ca.Material
	if err := json.Unmarshal(o.Material, &m); err != nil {
		return op.Result{Err: fmt.Errorf("ca: material: %w", err)}
	}
	// Refuse to store anything that is not a loadable authority. This is the
	// public-only load: Apply must stay deterministic and has no seal, which is
	// exactly right — validating the material never requires opening its key.
	if _, err := ca.Load(m, nil); err != nil {
		return op.Result{Err: err}
	}
	// The private half must already be sealed — or held in a device, in which
	// case there is no half to protect — before it reaches the log.
	if len(m.IntermediateKeyPEM) != 0 {
		return op.Result{Err: errors.New(
			"ca: refusing to store a plaintext intermediate key. Key material must be sealed " +
				"before it is proposed, or held inside a token, so that the replicated log never " +
				"contains a key the barrier alone can open")}
	}
	if err := tx.Put(store.BucketCA, o.Name, o.Material); err != nil {
		return op.Result{Err: err}
	}
	return op.Result{}
}

func applyPutPKIRole(tx *store.Tx, o *op.PutPKIRole) op.Result {
	if o.Name == "" {
		return op.Result{Err: errors.New("pki role: missing name")}
	}
	var role ca.Role
	if err := json.Unmarshal(o.Role, &role); err != nil {
		return op.Result{Err: fmt.Errorf("pki role: %w", err)}
	}
	if err := ValidatePath(role.Scope); err != nil {
		return op.Result{Err: fmt.Errorf("pki role scope: %w", err)}
	}
	if len(role.AllowedDomains) == 0 && len(role.AllowedURIPrefix) == 0 {
		return op.Result{Err: errors.New("pki role: must permit at least one domain or URI prefix")}
	}
	// A role is what bounds every certificate issued through it, so defining one
	// narrows exactly like a grant: an admin may only create roles that issue
	// within their own subtree.
	if o.Grantor == "" {
		return op.Result{Err: errors.New("pki role: missing grantor")}
	}
	ok, err := HasAuthority(tx, o.Grantor, VerbAdmin, role.Scope, o.AtSec)
	if err != nil {
		return op.Result{Err: err}
	}
	if !ok {
		return op.Result{Err: fmt.Errorf("pki role: grantor %s lacks admin authority at %s", o.Grantor, role.Scope)}
	}
	if err := tx.Put(store.BucketPKIRoles, o.Name, o.Role); err != nil {
		return op.Result{Err: err}
	}
	return op.Result{}
}

func applyRecordIssuance(tx *store.Tx, o *op.RecordIssuance) op.Result {
	if o.Serial == "" {
		return op.Result{Err: errors.New("issuance: missing serial")}
	}
	rec := IssuanceRecord{
		Serial: o.Serial, Role: o.Role, Subject: o.Subject, SANs: o.SANs,
		NotAfter: o.NotAfter, Requester: o.Requester, IssuedSec: o.AtSec,
	}
	blob, err := json.Marshal(rec)
	if err != nil {
		return op.Result{Err: err}
	}
	if err := tx.Put(store.BucketIssuance, o.Serial, blob); err != nil {
		return op.Result{Err: err}
	}
	return op.Result{}
}

// IssuanceRecord is one line of the domain's append-only issuance log.
type IssuanceRecord struct {
	Serial    string   `json:"serial"`
	Role      string   `json:"role"`
	Subject   string   `json:"subject"`
	SANs      []string `json:"sans"`
	NotAfter  int64    `json:"not_after"`
	Requester op.ID    `json:"requester"`
	IssuedSec int64    `json:"issued"`
}

// --- service methods ------------------------------------------------------

// InstallCA stores a CA created by the genesis ceremony.
func (k *Kernel) InstallCA(ctx context.Context, grantor op.ID, name string, m ca.Material) error {
	// Seal at propose time, so the plaintext key never enters the log at all —
	// not even in an entry that is later compacted away.
	sealed, err := m.Seal(k.seal)
	if err != nil {
		return err
	}
	blob, err := json.Marshal(sealed)
	if err != nil {
		return err
	}
	_, err = k.prop.Propose(ctx, &op.PutCA{Header: k.header(grantor), Name: name, Material: blob, Grantor: grantor})
	return err
}

// PutPKIRole defines a signing role.
func (k *Kernel) PutPKIRole(ctx context.Context, grantor op.ID, role ca.Role) error {
	blob, err := json.Marshal(role)
	if err != nil {
		return err
	}
	_, err = k.prop.Propose(ctx, &op.PutPKIRole{Header: k.header(grantor), Name: role.Name, Role: blob, Grantor: grantor})
	return err
}

// CAChain returns the trust material clients need, which is public by design.
func (k *Kernel) CAChain(ctx context.Context, name string) (root, chain []byte, err error) {
	err = k.store.View(func(tx *store.Tx) error {
		// Public-only: publishing a chain does not require the signing key.
		authority, err := loadCA(tx, name, nil)
		if err != nil {
			return err
		}
		root, chain = authority.RootPEM(), authority.ChainPEM()
		return nil
	})
	return root, chain, err
}

// SignCertificate authorizes a request, issues, verifies, and logs.
//
// The order is deliberate: the caller's authority is checked against the role's
// scope before the CA key is touched at all, the certificate is independently
// re-verified before it is returned, and the issuance is recorded before the
// caller receives anything. A certificate the log does not know about is the
// signal that the key was used outside Signet.
func (k *Kernel) SignCertificate(ctx context.Context, s Session, caName, roleName string, req ca.Request) (*ca.Issued, error) {
	var (
		authority *ca.CA
		role      ca.Role
	)
	if err := k.store.View(func(tx *store.Tx) error {
		raw, ok, err := tx.Get(store.BucketPKIRoles, roleName)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: pki role %q", ErrNotFound, roleName)
		}
		if err := json.Unmarshal(raw, &role); err != nil {
			return err
		}
		allowed, err := HasAuthority(tx, s.Principal, VerbSign, role.Scope, k.now().Unix())
		if err != nil {
			return err
		}
		if !allowed {
			return ErrDenied
		}
		authority, err = loadCA(tx, caName, k.seal)
		return err
	}); err != nil {
		return nil, err
	}

	serial, err := ca.NewSerial()
	if err != nil {
		return nil, err
	}
	issued, err := authority.Sign(req, role, serial, k.now())
	if err != nil {
		return nil, err
	}

	if _, err := k.prop.Propose(ctx, &op.RecordIssuance{
		Header: k.header(s.Principal), Serial: issued.Serial, Role: roleName,
		Subject: issued.Subject, SANs: issued.SANs,
		NotAfter: issued.NotAfter.Unix(), Requester: s.Principal,
	}); err != nil {
		// The certificate exists but the log does not know about it, so it is
		// not handed over. It never left this process.
		return nil, fmt.Errorf("issuance not recorded, certificate withheld: %w", err)
	}
	return issued, nil
}

// IssuerName is how a node's own issuing authority is keyed. Several nodes in
// one domain each store their own, so a node signs with the key it holds rather
// than one shared through the log (docs/02).
func IssuerName(nodeID string) string { return "issuer/" + nodeID }

// SigningAuthority picks the authority this node should sign with: its own
// issuer if it has one, otherwise the shared "default" authority.
//
// The fallback is not a compatibility shim — a single-node domain, or one that
// deliberately replicates a single sealed issuing key, is a perfectly good
// configuration. Per-node issuers are what a domain chooses when it wants
// heterogeneous custody or independent failure.
func (k *Kernel) SigningAuthority(ctx context.Context, nodeID string) (string, error) {
	name := IssuerName(nodeID)
	err := k.store.View(func(tx *store.Tx) error {
		if _, ok, err := tx.Get(store.BucketCA, name); err != nil {
			return err
		} else if ok {
			return nil
		}
		if _, ok, err := tx.Get(store.BucketCA, "default"); err != nil {
			return err
		} else if ok {
			name = "default"
			return nil
		}
		return fmt.Errorf(
			"%w: this domain has no certificate authority. Node %q has no issuer of its own "+
				"(%s) and there is no shared authority. Run the root ceremony, or request and "+
				"install an issuer for this node", ErrNotFound, nodeID, name)
	})
	return name, err
}

// Issuers lists every issuing authority in this domain, which is what an
// operator needs to see when reasoning about who can sign and with what custody.
func (k *Kernel) Issuers(ctx context.Context) (map[string]ca.Material, error) {
	out := map[string]ca.Material{}
	err := k.store.View(func(tx *store.Tx) error {
		return tx.ScanPrefix(store.BucketCA, "", func(name string, val []byte) bool {
			var m ca.Material
			if json.Unmarshal(val, &m) == nil {
				out[name] = m
			}
			return true
		})
	})
	return out, err
}

func loadCA(tx *store.Tx, name string, sl seal.Seal) (*ca.CA, error) {
	raw, ok, err := tx.Get(store.BucketCA, name)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%w: certificate authority %q", ErrNotFound, name)
	}
	var m ca.Material
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return ca.Load(m, sl)
}

// IssuanceLog returns recorded issuances, newest serials last. It is an
// operator view; the audit log proper is separate.
func (k *Kernel) IssuanceLog(ctx context.Context, s Session) ([]IssuanceRecord, error) {
	if err := k.authorize(s, VerbAdmin, "/"); err != nil {
		return nil, err
	}
	var out []IssuanceRecord
	err := k.store.View(func(tx *store.Tx) error {
		return tx.ScanPrefix(store.BucketIssuance, "", func(_ string, val []byte) bool {
			var r IssuanceRecord
			if json.Unmarshal(val, &r) == nil {
				out = append(out, r)
			}
			return true
		})
	})
	return out, err
}

// GenesisCA runs a root ceremony in software. The root private key is returned
// to the caller and never stored.
func GenesisCA(commonName string, permittedDNS []string, permittedIPs []*net.IPNet, rootTTL, interTTL time.Duration) (*ca.GenesisResult, error) {
	return ca.Genesis(commonName, permittedDNS, permittedIPs, rootTTL, interTTL, time.Now())
}

// GenesisCAInHardware runs a root ceremony inside a token. Neither key ever
// exists outside the device, so there is no root key file — and no way to make
// one.
func GenesisCAInHardware(ss seal.SigningSeal, commonName string, permittedDNS []string, permittedIPs []*net.IPNet,
	rootLabel, interLabel string, rootTTL, interTTL time.Duration) (*ca.GenesisResult, error) {
	return ca.HardwareGenesis(ss, commonName, permittedDNS, permittedIPs, rootLabel, interLabel, rootTTL, interTTL, time.Now())
}

// --- SSH roles ------------------------------------------------------------

// sshRole mirrors the SSH dialect's Role. The kernel cannot import the dialect
// — dialects import the kernel, never the reverse (charter principle 5) — so
// the shared shape is declared here and the dialect decodes into its own type.
type sshRole = SSHRoleSpec

// SSHRoleSpec bounds what an SSH signing role may assert.
type SSHRoleSpec struct {
	Name                string              `json:"name"`
	Scope               string              `json:"scope"`
	AllowedPrincipals   []string            `json:"allowed_principals"`
	PrincipalsFromRoles map[string][]string `json:"principals_from_roles,omitempty"`
	MaxTTLSec           int64               `json:"max_ttl_sec"`
	AllowAgentForward   bool                `json:"allow_agent_forwarding,omitempty"`
	AllowPortForward    bool                `json:"allow_port_forwarding,omitempty"`
	AllowPTY            bool                `json:"allow_pty,omitempty"`
}

// SSHRole loads a signing role for the SSH dialect. It is stored alongside the
// X.509 roles because both answer the same question: what may this role mint?
func (k *Kernel) SSHRole(ctx context.Context, name string) (sshRole, error) {
	var r sshRole
	err := k.store.View(func(tx *store.Tx) error {
		raw, ok, err := tx.Get(store.BucketSSHRoles, name)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: ssh role %q", ErrNotFound, name)
		}
		return json.Unmarshal(raw, &r)
	})
	return r, err
}

// PutSSHRole defines an SSH signing role.
func (k *Kernel) PutSSHRole(ctx context.Context, grantor op.ID, name string, role any) error {
	blob, err := json.Marshal(role)
	if err != nil {
		return err
	}
	_, err = k.prop.Propose(ctx, &op.PutSSHRole{Header: k.header(grantor), Name: name, Role: blob, Grantor: grantor})
	return err
}

// AuthorizeSign checks signing authority at a scope, for dialects that need to
// refuse before doing expensive work.
func (k *Kernel) AuthorizeSign(ctx context.Context, s Session, scope string) error {
	return k.authorize(s, VerbSign, scope)
}

func applyPutSSHRole(tx *store.Tx, o *op.PutSSHRole) op.Result {
	if o.Name == "" {
		return op.Result{Err: errors.New("ssh role: missing name")}
	}
	var probe struct {
		Scope             string   `json:"scope"`
		AllowedPrincipals []string `json:"allowed_principals"`
	}
	if err := json.Unmarshal(o.Role, &probe); err != nil {
		return op.Result{Err: fmt.Errorf("ssh role: %w", err)}
	}
	if err := ValidatePath(probe.Scope); err != nil {
		return op.Result{Err: fmt.Errorf("ssh role scope: %w", err)}
	}
	// Defining who may log in as whom is a grant, so it narrows like one.
	if o.Grantor == "" {
		return op.Result{Err: errors.New("ssh role: missing grantor")}
	}
	ok, err := HasAuthority(tx, o.Grantor, VerbAdmin, probe.Scope, o.AtSec)
	if err != nil {
		return op.Result{Err: err}
	}
	if !ok {
		return op.Result{Err: fmt.Errorf("ssh role: grantor %s lacks admin authority at %s", o.Grantor, probe.Scope)}
	}
	if err := tx.Put(store.BucketSSHRoles, o.Name, o.Role); err != nil {
		return op.Result{Err: err}
	}
	return op.Result{}
}
