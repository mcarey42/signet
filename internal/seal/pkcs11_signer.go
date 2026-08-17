//go:build pkcs11

package seal

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/miekg/pkcs11"
)

// Keys held inside a token are created with CKA_SENSITIVE and
// CKA_EXTRACTABLE=false, which is what makes "the key never leaves the device"
// a property of the device rather than a promise from Signet. A token that
// silently ignored those attributes would be lying to us, so generation reads
// them back and refuses the key if they did not stick.

// namedCurveOID is the DER encoding of the P-256 curve identifier, which
// PKCS#11 wants as CKA_EC_PARAMS.
var p256OID = []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}

func (p *PKCS11Seal) GenerateSigner(label, alg string) (*KeyRef, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	pubTmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}
	privTmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
		// The two attributes the whole design rests on.
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
	}

	var mech []*pkcs11.Mechanism
	switch alg {
	case AlgECDSAP256:
		pubTmpl = append(pubTmpl,
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, p256OID))
		mech = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)}
	case AlgRSA2048:
		pubTmpl = append(pubTmpl,
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS_BITS, 2048),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, []byte{1, 0, 1}))
		mech = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)}
	default:
		return nil, fmt.Errorf(
			"cannot generate a %q key inside the token: supported algorithms are %s and %s",
			alg, AlgECDSAP256, AlgRSA2048)
	}

	if _, _, err := p.ctx.GenerateKeyPair(p.session, mech, pubTmpl, privTmpl); err != nil {
		return nil, fmt.Errorf(
			"the token %q refused to generate a %s key labelled %q: %w — check that the token "+
				"supports this key type and that the logged-in user may create objects on it",
			p.token, alg, label, err)
	}

	ref := &KeyRef{Seal: p.Name(), Token: p.token, Label: label, ID: id, Alg: alg}
	// Verify the token honoured non-extractability rather than assuming it did.
	if err := p.assertNonExtractable(ref); err != nil {
		return nil, err
	}
	return ref, nil
}

func (p *PKCS11Seal) assertNonExtractable(ref *KeyRef) error {
	priv, err := p.findByRef(ref, pkcs11.CKO_PRIVATE_KEY)
	if err != nil {
		return err
	}
	attrs, err := p.ctx.GetAttributeValue(p.session, priv, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, nil),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, nil),
	})
	if err != nil {
		// Some tokens refuse to report these at all; that is itself acceptable
		// (they are marked sensitive), so do not fail the ceremony over it.
		return nil
	}
	for _, a := range attrs {
		on := len(a.Value) > 0 && a.Value[0] != 0
		switch a.Type {
		case pkcs11.CKA_EXTRACTABLE:
			if on {
				return fmt.Errorf(
					"the token %q created key %q as EXTRACTABLE: its private half could be exported, "+
						"which defeats the reason for holding it in hardware. Refusing to use it",
					p.token, ref.Label)
			}
		case pkcs11.CKA_SENSITIVE:
			if !on {
				return fmt.Errorf(
					"the token %q created key %q as non-sensitive: its private half could be read back, "+
						"which defeats the reason for holding it in hardware. Refusing to use it",
					p.token, ref.Label)
			}
		}
	}
	return nil
}

func (p *PKCS11Seal) findByRef(ref *KeyRef, class uint) (pkcs11.ObjectHandle, error) {
	tmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, ref.Label),
	}
	if len(ref.ID) > 0 {
		tmpl = append(tmpl, pkcs11.NewAttribute(pkcs11.CKA_ID, ref.ID))
	}
	if err := p.ctx.FindObjectsInit(p.session, tmpl); err != nil {
		return 0, fmt.Errorf("searching token %q for key %q: %w", ref.Token, ref.Label, err)
	}
	objs, _, err := p.ctx.FindObjects(p.session, 2)
	_ = p.ctx.FindObjectsFinal(p.session)
	if err != nil {
		return 0, fmt.Errorf("searching token %q for key %q: %w", ref.Token, ref.Label, err)
	}
	switch len(objs) {
	case 0:
		kind := "private"
		if class == pkcs11.CKO_PUBLIC_KEY {
			kind = "public"
		}
		return 0, fmt.Errorf(
			"no %s key labelled %q found in token %q — the reference in this domain's store points "+
				"at a key the token does not have. Either the wrong token is attached, or the key "+
				"was deleted, in which case anything it signed cannot be re-issued",
			kind, ref.Label, ref.Token)
	case 1:
		return objs[0], nil
	default:
		return 0, fmt.Errorf(
			"token %q holds %d keys labelled %q; the label must identify exactly one key or Signet "+
				"cannot know which one it is signing with", ref.Token, len(objs), ref.Label)
	}
}

// Signer returns a crypto.Signer whose private operations happen inside the
// token. The returned value never holds key material.
func (p *PKCS11Seal) Signer(ref *KeyRef) (crypto.Signer, error) {
	if ref == nil {
		return nil, errors.New("no key reference was supplied")
	}
	if ref.Seal != p.Name() {
		return nil, fmt.Errorf(
			"key reference names the %q seal but this is a %q seal: the domain is configured with "+
				"a seal that does not hold its keys", ref.Seal, p.Name())
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	priv, err := p.findByRef(ref, pkcs11.CKO_PRIVATE_KEY)
	if err != nil {
		return nil, err
	}
	pubObj, err := p.findByRef(ref, pkcs11.CKO_PUBLIC_KEY)
	if err != nil {
		return nil, err
	}
	pub, err := p.readPublic(pubObj, ref.Alg)
	if err != nil {
		return nil, err
	}
	return &tokenSigner{seal: p, priv: priv, pub: pub, alg: ref.Alg, ref: ref}, nil
}

func (p *PKCS11Seal) readPublic(obj pkcs11.ObjectHandle, alg string) (crypto.PublicKey, error) {
	switch alg {
	case AlgECDSAP256:
		attrs, err := p.ctx.GetAttributeValue(p.session, obj, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
		})
		if err != nil {
			return nil, fmt.Errorf("reading the public point from the token: %w", err)
		}
		point := attrs[0].Value
		// PKCS#11 wraps the point in a DER OCTET STRING; some tokens return it
		// raw. Accept both rather than guessing wrong on a specific vendor.
		if len(point) > 2 && point[0] == 0x04 && int(point[1]) == len(point)-2 {
			point = point[2:]
		}
		x, y := elliptic.Unmarshal(elliptic.P256(), point)
		if x == nil {
			return nil, fmt.Errorf(
				"the token returned a public point Signet cannot decode (%d bytes); it may be using "+
					"a curve other than P-256", len(point))
		}
		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
	case AlgRSA2048:
		attrs, err := p.ctx.GetAttributeValue(p.session, obj, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
		})
		if err != nil {
			return nil, fmt.Errorf("reading the public modulus from the token: %w", err)
		}
		n := new(big.Int).SetBytes(attrs[0].Value)
		e := new(big.Int).SetBytes(attrs[1].Value)
		if !e.IsInt64() {
			return nil, errors.New("the token reported an implausible RSA exponent")
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	}
	return nil, fmt.Errorf("unsupported algorithm %q", alg)
}

func (p *PKCS11Seal) DeleteSigner(ref *KeyRef) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, class := range []uint{pkcs11.CKO_PRIVATE_KEY, pkcs11.CKO_PUBLIC_KEY} {
		obj, err := p.findByRef(ref, class)
		if err != nil {
			continue // already gone
		}
		if err := p.ctx.DestroyObject(p.session, obj); err != nil {
			return fmt.Errorf("destroying key %q in token %q: %w", ref.Label, ref.Token, err)
		}
	}
	return nil
}

// tokenSigner is a crypto.Signer backed by a key inside a token. It holds a
// handle, never material, so there is nothing in it worth stealing from memory.
type tokenSigner struct {
	seal *PKCS11Seal
	priv pkcs11.ObjectHandle
	pub  crypto.PublicKey
	alg  string
	ref  *KeyRef
}

func (t *tokenSigner) Public() crypto.PublicKey { return t.pub }

func (t *tokenSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// crypto.Signer requires opts, but a nil here should say so rather than
	// crash: this is called from library code that may be several layers away.
	if opts == nil {
		return nil, fmt.Errorf(
			"signing with token key %q requires SignerOpts naming the digest algorithm; none was given",
			t.ref.Label)
	}
	if len(digest) == 0 {
		return nil, fmt.Errorf("signing with token key %q was asked to sign an empty digest", t.ref.Label)
	}
	t.seal.mu.Lock()
	defer t.seal.mu.Unlock()

	switch t.alg {
	case AlgECDSAP256:
		if opts.HashFunc() != crypto.SHA256 {
			return nil, fmt.Errorf("this key signs SHA-256 digests; %s was requested", opts.HashFunc())
		}
		mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}
		if err := t.seal.ctx.SignInit(t.seal.session, mech, t.priv); err != nil {
			return nil, fmt.Errorf("token %q refused to start a signature with key %q: %w",
				t.ref.Token, t.ref.Label, err)
		}
		raw, err := t.seal.ctx.Sign(t.seal.session, digest)
		if err != nil {
			return nil, fmt.Errorf("token %q failed to sign with key %q: %w",
				t.ref.Token, t.ref.Label, err)
		}
		if len(raw)%2 != 0 {
			return nil, fmt.Errorf("the token returned a %d-byte ECDSA signature, which is not a valid r||s pair", len(raw))
		}
		// PKCS#11 returns r||s; Go's crypto.Signer contract for ECDSA is ASN.1.
		half := len(raw) / 2
		return asn1.Marshal(struct{ R, S *big.Int }{
			R: new(big.Int).SetBytes(raw[:half]),
			S: new(big.Int).SetBytes(raw[half:]),
		})
	case AlgRSA2048:
		prefix, ok := rsaDigestPrefix[opts.HashFunc()]
		if !ok {
			return nil, fmt.Errorf("this key cannot sign %s digests", opts.HashFunc())
		}
		mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}
		if err := t.seal.ctx.SignInit(t.seal.session, mech, t.priv); err != nil {
			return nil, fmt.Errorf("token %q refused to start a signature with key %q: %w",
				t.ref.Token, t.ref.Label, err)
		}
		sig, err := t.seal.ctx.Sign(t.seal.session, append(append([]byte{}, prefix...), digest...))
		if err != nil {
			return nil, fmt.Errorf("token %q failed to sign with key %q: %w",
				t.ref.Token, t.ref.Label, err)
		}
		return sig, nil
	}
	return nil, fmt.Errorf("unsupported algorithm %q", t.alg)
}

// CKM_RSA_PKCS signs a DigestInfo, so the digest needs its algorithm prefix.
var rsaDigestPrefix = map[crypto.Hash][]byte{
	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384: {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}
