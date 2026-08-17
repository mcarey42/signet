//go:build pkcs11

// PKCS#11 seal: the wrapping key lives in a hardware security module and never
// leaves it. Wrap and unwrap are operations performed *by the device*, so a
// compromise of Signet — its memory, its disk, its backups — does not yield the
// key, only the ability to ask the HSM to use it while the process is running.
// That is the difference E-01 DB-3 asks for: key use during uptime instead of
// key exfiltration.
//
// This file is behind a build tag because it links a vendor C library through
// cgo, and Signet's default build is a static pure-Go binary (docs/09). Build
// with:
//
//	go build -tags pkcs11 ./cmd/signet
//
// SoftHSM2 implements the same interface as a real HSM, so it is what the tests
// use: the code path exercised in CI is the one that runs in production.
package seal

import (
	"errors"
	"fmt"
	"strconv"
	"sync"

	"github.com/miekg/pkcs11"
)

type PKCS11Config struct {
	Module string // path to the PKCS#11 .so
	Token  string // token label to search for
	Slot   string // explicit slot ID, if the token label is ambiguous
	Pin    string
	Label  string // label of the AES wrapping key inside the token
}

type PKCS11Seal struct {
	mu      sync.Mutex
	ctx     *pkcs11.Ctx
	session pkcs11.SessionHandle
	key     pkcs11.ObjectHandle
	label   string
	token   string
}

func openPKCS11(cfg PKCS11Config) (Seal, error) {
	if cfg.Module == "" || cfg.Label == "" {
		return nil, errors.New("seal: pkcs11 needs at least module= and label=")
	}
	ctx := pkcs11.New(cfg.Module)
	if ctx == nil {
		return nil, fmt.Errorf("seal: cannot load PKCS#11 module %s", cfg.Module)
	}
	if err := ctx.Initialize(); err != nil {
		return nil, fmt.Errorf("seal: pkcs11 initialize: %w", err)
	}

	slot, err := findSlot(ctx, cfg)
	if err != nil {
		ctx.Destroy()
		return nil, err
	}
	session, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		ctx.Destroy()
		return nil, fmt.Errorf("seal: pkcs11 open session: %w", err)
	}
	if cfg.Pin != "" {
		if err := ctx.Login(session, pkcs11.CKU_USER, cfg.Pin); err != nil {
			ctx.CloseSession(session)
			ctx.Destroy()
			return nil, fmt.Errorf("seal: pkcs11 login: %w", err)
		}
	}

	key, err := findKey(ctx, session, cfg.Label)
	if err != nil {
		ctx.CloseSession(session)
		ctx.Destroy()
		return nil, err
	}
	return &PKCS11Seal{ctx: ctx, session: session, key: key, label: cfg.Label, token: cfg.Token}, nil
}

func findSlot(ctx *pkcs11.Ctx, cfg PKCS11Config) (uint, error) {
	if cfg.Slot != "" {
		n, err := strconv.ParseUint(cfg.Slot, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("seal: slot=%q: %w", cfg.Slot, err)
		}
		return uint(n), nil
	}
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("seal: pkcs11 slot list: %w", err)
	}
	for _, s := range slots {
		info, err := ctx.GetTokenInfo(s)
		if err != nil {
			continue
		}
		if cfg.Token == "" || trimLabel(info.Label) == cfg.Token {
			return s, nil
		}
	}
	return 0, fmt.Errorf("seal: no token labelled %q", cfg.Token)
}

func findKey(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, label string) (pkcs11.ObjectHandle, error) {
	tmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	if err := ctx.FindObjectsInit(session, tmpl); err != nil {
		return 0, fmt.Errorf("seal: pkcs11 find init: %w", err)
	}
	objs, _, err := ctx.FindObjects(session, 2)
	_ = ctx.FindObjectsFinal(session)
	if err != nil {
		return 0, fmt.Errorf("seal: pkcs11 find: %w", err)
	}
	switch len(objs) {
	case 0:
		return 0, fmt.Errorf("seal: no secret key labelled %q in the token", label)
	case 1:
		return objs[0], nil
	default:
		// Ambiguity here would mean silently wrapping under an unknown key.
		return 0, fmt.Errorf("seal: %d keys labelled %q; the label must be unique", len(objs), label)
	}
}

func (p *PKCS11Seal) Name() string  { return "pkcs11" }
func (p *PKCS11Seal) KeyID() string { return p.token + "/" + p.label }

func (p *PKCS11Seal) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ctx == nil {
		return nil
	}
	_ = p.ctx.Logout(p.session)
	_ = p.ctx.CloseSession(p.session)
	p.ctx.Destroy()
	p.ctx = nil
	return nil
}

// Wrap encrypts inside the token. The plaintext crosses into the device and the
// ciphertext comes back; the wrapping key itself is never readable.
func (p *PKCS11Seal) Wrap(plaintext, aad []byte) (*Blob, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// The token generates the IV for GCM, which is why it comes back in the
	// mechanism parameters rather than being chosen here.
	params := pkcs11.NewGCMParams(nil, aad, 128)
	defer params.Free()
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)}
	if err := p.ctx.EncryptInit(p.session, mech, p.key); err != nil {
		return nil, fmt.Errorf("seal: pkcs11 encrypt init: %w", err)
	}
	ct, err := p.ctx.Encrypt(p.session, plaintext)
	if err != nil {
		return nil, fmt.Errorf("seal: pkcs11 encrypt: %w", err)
	}
	return &Blob{Seal: p.Name(), KeyID: p.KeyID(), Nonce: params.IV(), CT: ct}, nil
}

func (p *PKCS11Seal) Unwrap(b *Blob, aad []byte) ([]byte, error) {
	if b == nil {
		return nil, errors.New("seal: nothing to unwrap")
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	params := pkcs11.NewGCMParams(b.Nonce, aad, 128)
	defer params.Free()
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_GCM, params)}
	if err := p.ctx.DecryptInit(p.session, mech, p.key); err != nil {
		return nil, fmt.Errorf("seal: pkcs11 decrypt init: %w", err)
	}
	pt, err := p.ctx.Decrypt(p.session, b.CT)
	if err != nil {
		return nil, fmt.Errorf("seal: pkcs11 decrypt: %w", err)
	}
	return pt, nil
}

func trimLabel(s string) string {
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == 0) {
		s = s[:len(s)-1]
	}
	return s
}
