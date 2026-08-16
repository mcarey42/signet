package attest

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Verifier answers one question: what does this evidence prove?
//
// It never decides what the prover may *do* — that is the kernel's job. A
// verifier that returned authorization decisions would put policy in the
// authentication path, where a single bug becomes a privilege escalation.
type Verifier interface {
	// Name is how a trust registration selects this verifier. Verifiers are
	// chosen by configuration, never inferred from the evidence itself
	// (E-01 AT-0).
	Name() string
	// Verify checks evidence against a pinned issuer and returns the identity
	// it proves.
	Verify(material []byte, iss Issuer, now time.Time) (*Identity, error)
}

// Issuer is a registered, pinned trust anchor for one evidence source.
type Issuer struct {
	Name     string // local handle, e.g. "cluster-svc"
	URL      string // the exact `iss` value tokens must carry
	Audience string // the Signet-specific audience tokens must be minted for
	JWKS     []byte // pinned key set; never fetched from a request-supplied URL
}

// Identity is what a verifier proves: a set of stable facts a mapping rule can
// match on. It is deliberately not a principal — translating facts into a
// principal is a policy decision the kernel makes.
type Identity struct {
	Verifier  string
	Issuer    string
	Subject   string
	Namespace string
	Account   string // ServiceAccount name
	UID       string
	Expiry    time.Time
}

// K8sSA verifies Kubernetes projected ServiceAccount tokens.
//
// Kubernetes already solved the hardest part of workload attestation — proving
// what a workload *is* before it holds any credential — so Signet trusts each
// cluster as an attestation source rather than shipping an agent to every pod.
// This is the same shape ESO and cert-manager already use against Vault, which
// is why they work against Signet unmodified.
type K8sSA struct{}

func (K8sSA) Name() string { return "k8s-sa" }

// k8s puts the interesting facts in a namespaced claim.
type k8sClaims struct {
	Kubernetes struct {
		Namespace      string `json:"namespace"`
		ServiceAccount struct {
			Name string `json:"name"`
			UID  string `json:"uid"`
		} `json:"serviceaccount"`
	} `json:"kubernetes.io"`
}

func (v K8sSA) Verify(material []byte, iss Issuer, now time.Time) (*Identity, error) {
	jwks, err := ParseJWKS(iss.JWKS)
	if err != nil {
		return nil, fmt.Errorf("k8s-sa: issuer %q: %w", iss.Name, err)
	}
	claims, err := VerifyJWS(strings.TrimSpace(string(material)), jwks, iss.URL, iss.Audience, now)
	if err != nil {
		return nil, fmt.Errorf("k8s-sa: %w", err)
	}

	// The subject is authoritative and standard; the namespaced claim carries
	// the UID. Prefer `sub`, and require the two to agree when both are present
	// so a token cannot present one identity in two places.
	ns, sa, err := parseSubject(claims.Subject)
	if err != nil {
		return nil, fmt.Errorf("k8s-sa: %w", err)
	}
	var kc k8sClaims
	_ = json.Unmarshal(claims.Raw, &kc)
	if kc.Kubernetes.Namespace != "" && kc.Kubernetes.Namespace != ns {
		return nil, errors.New("k8s-sa: namespace in sub disagrees with kubernetes.io claim")
	}
	if kc.Kubernetes.ServiceAccount.Name != "" && kc.Kubernetes.ServiceAccount.Name != sa {
		return nil, errors.New("k8s-sa: service account in sub disagrees with kubernetes.io claim")
	}

	return &Identity{
		Verifier:  v.Name(),
		Issuer:    claims.Issuer,
		Subject:   claims.Subject,
		Namespace: ns,
		Account:   sa,
		UID:       kc.Kubernetes.ServiceAccount.UID,
		Expiry:    claims.Expiry,
	}, nil
}

// parseSubject splits "system:serviceaccount:<namespace>:<name>".
func parseSubject(sub string) (namespace, account string, err error) {
	const prefix = "system:serviceaccount:"
	if !strings.HasPrefix(sub, prefix) {
		return "", "", fmt.Errorf("subject %q is not a service account", sub)
	}
	rest := strings.TrimPrefix(sub, prefix)
	ns, name, ok := strings.Cut(rest, ":")
	if !ok || ns == "" || name == "" {
		return "", "", fmt.Errorf("subject %q is malformed", sub)
	}
	return ns, name, nil
}

// Registry holds the verifiers this build supports.
type Registry struct{ byName map[string]Verifier }

func NewRegistry(vs ...Verifier) *Registry {
	r := &Registry{byName: make(map[string]Verifier, len(vs))}
	for _, v := range vs {
		r.byName[v.Name()] = v
	}
	return r
}

// Default is the verifier set the MVP ships. WebAuthn, TPM, cloud instance
// identity, and join tokens join it as their milestones land (docs/04).
func Default() *Registry { return NewRegistry(K8sSA{}) }

func (r *Registry) Get(name string) (Verifier, error) {
	v, ok := r.byName[name]
	if !ok {
		return nil, fmt.Errorf("attest: no verifier named %q", name)
	}
	return v, nil
}
