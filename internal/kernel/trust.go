package kernel

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/mcarey42/signet/internal/op"
	"github.com/mcarey42/signet/internal/store"
	"github.com/mcarey42/signet/internal/trust"
)

// The domain stores its own trust bundle so every node serves the identical
// artifact, and so a consumer fetching from any node gets the same answer.
//
// Signet stores the bundle; it does not author it. Authorship belongs to the
// offline root, which is the whole point — a node that could author its own
// bundle could declare itself an anchor (docs/02, internal/trust).

// PutTrustBundle stores a root-signed bundle for this domain.
//
// The bundle must verify under the root this domain already trusts before it is
// accepted. A node that stored bundles unverified would happily serve a forged
// one to every consumer that asked, which is precisely the attack pinning is
// meant to prevent.
func (k *Kernel) PutTrustBundle(ctx context.Context, grantor op.ID, raw []byte) error {
	var b trust.Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return fmt.Errorf("this does not parse as a trust bundle: %w", err)
	}
	// Establish the pin from what this node already holds: the root certificate
	// its own issuer chains to. That is a fact this node knows independently of
	// the bundle, so it cannot be talked out of it by the bundle itself.
	pin, err := k.rootPin(ctx)
	if err != nil {
		return err
	}
	p, err := trust.Verify(&b, trust.VerifyOptions{
		PinnedSPKI: pin,
		Now:        k.now(),
		Skew:       5 * time.Minute,
	})
	if err != nil {
		return fmt.Errorf(
			"refusing to store this bundle: %w. It was not signed by the root this domain's own "+
				"issuer chains to", err)
	}
	_, err = k.prop.Propose(ctx, &op.PutTrustBundle{
		Header: k.header(grantor), Domain: p.Domain, Epoch: p.Epoch, Bundle: raw, Grantor: grantor,
	})
	return err
}

// TrustBundle returns the stored bundle for a domain, as the exact bytes that
// were signed. It is public: a bundle contains only certificates and metadata
// that consumers are meant to have, and serving it is the point.
func (k *Kernel) TrustBundle(ctx context.Context, domain string) ([]byte, error) {
	var raw []byte
	err := k.store.View(func(tx *store.Tx) error {
		if domain == "" {
			// One domain per store today; return whichever is present rather
			// than making every caller know the domain name to ask for it.
			return tx.ScanPrefix(store.BucketTrust, "", func(_ string, v []byte) bool {
				raw = append([]byte(nil), v...)
				return false
			})
		}
		v, ok, err := tx.Get(store.BucketTrust, domain)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf(
				"no trust bundle for domain %q. Publish one with `signet ca bundle` at the offline "+
					"root, then install it with `signet trust install`", domain)
		}
		raw = v
		return nil
	})
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, errors.New(
			"this domain has no trust bundle yet. Publish one with `signet ca bundle` at the offline " +
				"root, then install it with `signet trust install`")
	}
	return raw, nil
}

// rootPin is the fingerprint of the root this node's issuer chains to.
func (k *Kernel) rootPin(ctx context.Context) (string, error) {
	issuers, err := k.Issuers(ctx)
	if err != nil {
		return "", err
	}
	for _, m := range issuers {
		cert, err := parsePEMCert(m.RootCertPEM)
		if err != nil {
			continue
		}
		return trust.Fingerprint(cert), nil
	}
	return "", errors.New(
		"this node holds no certificate authority, so it has no root to check a bundle against. " +
			"Install an issuer first with `signet ca install`")
}

func parsePEMCert(p []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(p)
	if blk == nil {
		return nil, errors.New("not PEM")
	}
	return x509.ParseCertificate(blk.Bytes)
}

func applyPutTrustBundle(tx *store.Tx, o *op.PutTrustBundle) op.Result {
	if o.Domain == "" {
		return op.Result{Err: errors.New("trust bundle: missing domain")}
	}
	// Rollback protection lives here, inside Apply, so it holds against every
	// path into the log — including a replayed proposal from a node that has
	// been offline and still believes an older bundle is current.
	if cur, ok, err := tx.Get(store.BucketTrust, o.Domain); err != nil {
		return op.Result{Err: err}
	} else if ok {
		var prev trust.Bundle
		if json.Unmarshal(cur, &prev) == nil {
			if p, err := trust.PayloadOf(&prev); err == nil && o.Epoch < p.Epoch {
				return op.Result{Err: fmt.Errorf(
					"trust bundle: this is epoch %d and domain %q already holds epoch %d. The log "+
						"does not move backwards: an older bundle may describe a trust set that has "+
						"since been narrowed", o.Epoch, o.Domain, p.Epoch)}
			}
		}
	}
	if err := tx.Put(store.BucketTrust, o.Domain, o.Bundle); err != nil {
		return op.Result{Err: err}
	}
	return op.Result{}
}
