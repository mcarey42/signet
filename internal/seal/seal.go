// Package seal holds the wrapping key that protects everything else.
//
// A seal answers one question: "unwrap this, if you are entitled to." What
// makes it useful is that Signet never holds the wrapping key itself — with a
// hardware seal it cannot, because the key never leaves the device. That turns
// a compromise of Signet's storage from "the attacker has the keys" into "the
// attacker has ciphertext and needs the HSM too."
//
// Two things ride on the seal:
//
//   - The barrier root key, which protects the store at rest. Signet generates
//     it once, wraps it, and keeps only the wrapped form on disk.
//   - Envelopes around private key material. Signing keys are enveloped under a
//     per-key data key that only the seal can unwrap, so the replicated log
//     holds ciphertext the barrier alone cannot open. This matters more than it
//     first appears: a Raft log is append-only and its backups are immutable,
//     so rotating a key does not unwrite its predecessor. Without the envelope,
//     one barrier compromise at any point in the future exposes every signing
//     key the domain has ever held (docs/11).
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
)

// Blob is something the seal wrapped. It records which seal and which wrapping
// key produced it, so a domain can migrate seals without losing the ability to
// read what the old one wrapped.
type Blob struct {
	Seal  string `json:"seal"`
	KeyID string `json:"key_id"`
	Nonce []byte `json:"nonce,omitempty"`
	CT    []byte `json:"ct"`
}

// Seal wraps and unwraps small blobs — data keys, never bulk data.
type Seal interface {
	// Name identifies the backend, e.g. "file" or "pkcs11".
	Name() string
	// KeyID identifies the wrapping key within that backend.
	KeyID() string
	// Wrap encrypts plaintext. aad binds the result to its purpose so a blob
	// cannot be replayed somewhere it does not belong.
	Wrap(plaintext, aad []byte) (*Blob, error)
	Unwrap(b *Blob, aad []byte) ([]byte, error)
	Close() error
}

// Open builds a seal from a configuration URI:
//
//	file:///var/lib/signet/seal.key
//	pkcs11:?module=/usr/lib/softhsm/libsofthsm2.so&token=signet&pin=1234&label=signet-seal
//
// PKCS#11 support requires a build with the "pkcs11" tag, because it links a
// vendor C library and Signet's default build is deliberately static and
// pure-Go (docs/09).
func Open(uri string) (Seal, error) {
	if uri == "" {
		return nil, errors.New("seal: no seal configured")
	}
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	switch u.Scheme {
	case "file":
		path := u.Path
		if path == "" {
			path = u.Opaque
		}
		return OpenFile(path)
	case "pkcs11":
		q := u.Query()
		return openPKCS11(PKCS11Config{
			Module: q.Get("module"),
			Token:  q.Get("token"),
			Pin:    q.Get("pin"),
			Label:  q.Get("label"),
			Slot:   q.Get("slot"),
		})
	default:
		return nil, fmt.Errorf("seal: unknown scheme %q", u.Scheme)
	}
}

// --- file seal ------------------------------------------------------------

// FileSeal keeps its wrapping key in a file. It is the simplest possible seal
// and the honest default for a single node: the key sits beside the data it
// protects, so it defends against a stolen backup or a leaked store file, not
// against someone who owns the host. Domains that need more use a hardware
// seal, which is the same interface.
type FileSeal struct {
	path  string
	aead  cipher.AEAD
	keyID string
}

const fileSealInfo = "signet/seal/file/v1"

func OpenFile(path string) (*FileSeal, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("seal: read %s: %w", path, err)
	}
	if len(raw) < 32 {
		return nil, fmt.Errorf("seal: %s holds %d bytes, need at least 32 of high-entropy material", path, len(raw))
	}
	key, err := hkdf.Key(sha256.New, raw, nil, fileSealInfo, 32)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	// A stable identifier for this wrapping key, derived so it changes if the
	// file does — which is how a seal migration is noticed rather than guessed.
	id, err := hkdf.Key(sha256.New, raw, nil, fileSealInfo+"/id", 8)
	if err != nil {
		return nil, err
	}
	return &FileSeal{path: path, aead: aead, keyID: fmt.Sprintf("%x", id)}, nil
}

func (f *FileSeal) Name() string  { return "file" }
func (f *FileSeal) KeyID() string { return f.keyID }
func (f *FileSeal) Close() error  { return nil }

func (f *FileSeal) Wrap(plaintext, aad []byte) (*Blob, error) {
	nonce := make([]byte, f.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return &Blob{
		Seal: f.Name(), KeyID: f.keyID, Nonce: nonce,
		CT: f.aead.Seal(nil, nonce, plaintext, aad),
	}, nil
}

func (f *FileSeal) Unwrap(b *Blob, aad []byte) ([]byte, error) {
	if b == nil {
		return nil, errors.New("seal: nothing to unwrap")
	}
	if b.KeyID != "" && b.KeyID != f.keyID {
		return nil, fmt.Errorf("seal: blob was wrapped by key %s, this seal holds %s", b.KeyID, f.keyID)
	}
	pt, err := f.aead.Open(nil, b.Nonce, b.CT, aad)
	if err != nil {
		return nil, fmt.Errorf("seal: unwrap: %w", err)
	}
	return pt, nil
}

// GenerateKeyFile writes a fresh seal key, refusing to clobber one.
func GenerateKeyFile(path string) error {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("seal: create key file: %w", err)
	}
	defer f.Close()
	_, err = f.Write(key)
	return err
}

// --- the barrier root key -------------------------------------------------

const rootKeyAAD = "signet/root-key/v1"

// LoadOrCreateRootKey returns the key the store's barrier is derived from,
// creating and sealing it on first use.
//
// Only the wrapped form is ever written. With a hardware seal this is what
// makes the data directory useless on its own: the file on disk cannot be
// opened without the device that wrapped it.
func LoadOrCreateRootKey(s Seal, dir string) ([]byte, error) {
	path := filepath.Join(dir, "root.seal")
	if raw, err := os.ReadFile(path); err == nil {
		var b Blob
		if err := json.Unmarshal(raw, &b); err != nil {
			return nil, fmt.Errorf("seal: %s: %w", path, err)
		}
		key, err := s.Unwrap(&b, []byte(rootKeyAAD))
		if err != nil {
			return nil, fmt.Errorf("seal: cannot unseal the root key — is this the right seal? %w", err)
		}
		return key, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	b, err := s.Wrap(key, []byte(rootKeyAAD))
	if err != nil {
		return nil, err
	}
	blob, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// --- envelopes ------------------------------------------------------------

// Envelope is sensitive material encrypted under a data key that only the seal
// can recover. The material and its key travel together; neither is usable
// without the seal.
type Envelope struct {
	DEK   *Blob  `json:"dek"`
	Nonce []byte `json:"nonce"`
	CT    []byte `json:"ct"`
}

// NewEnvelope encloses plaintext under a fresh data key wrapped by the seal.
//
// This happens before the material is ever proposed, so the plaintext never
// enters the replicated log — not even briefly.
func NewEnvelope(s Seal, plaintext, aad []byte) (*Envelope, error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, plaintext, aad)

	wrapped, err := s.Wrap(dek, aad)
	if err != nil {
		return nil, err
	}
	// The data key exists in memory only for as long as it takes to use it.
	for i := range dek {
		dek[i] = 0
	}
	return &Envelope{DEK: wrapped, Nonce: nonce, CT: ct}, nil
}

// Open recovers the enclosed material, which requires the seal.
func (e *Envelope) Open(s Seal, aad []byte) ([]byte, error) {
	if e == nil || e.DEK == nil {
		return nil, errors.New("seal: empty envelope")
	}
	dek, err := s.Unwrap(e.DEK, aad)
	if err != nil {
		return nil, err
	}
	defer func() {
		for i := range dek {
			dek[i] = 0
		}
	}()
	blk, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, e.Nonce, e.CT, aad)
	if err != nil {
		return nil, fmt.Errorf("seal: open envelope: %w", err)
	}
	return pt, nil
}
