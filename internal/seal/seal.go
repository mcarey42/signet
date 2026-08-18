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
	"strings"
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
		// "file://relative/seal.key" parses with "relative" as the HOST and
		// "/seal.key" as the path, so taking u.Path alone would silently open
		// the wrong file at the filesystem root. Rejoin them.
		path := u.Host + u.Path
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

// RewrapRootKey moves the barrier root key from one seal to another.
//
// The root key itself does not change, so the barrier and every byte it
// protects are untouched — this is a custody change, not a re-encryption of the
// store. The previous wrapped form is kept beside it as root.seal.prev so an
// interrupted ceremony can be reversed by hand.
// wrappedBy reports whether a blob was wrapped by exactly this seal's key.
//
// Unknown means NO. Re-wrapping something already wrapped correctly is
// harmless; skipping a rewrap that was needed leaves material under a key the
// operator believes has been retired, which is the failure worth avoiding.
func wrappedBy(b *Blob, s Seal) bool {
	if b.Seal != s.Name() {
		return false
	}
	id := s.KeyID()
	if id == "" || b.KeyID == "" || strings.Contains(id, UnidentifiedKey) {
		return false
	}
	return b.KeyID == id
}

func RewrapRootKey(from, to Seal, dir string) error {
	path := filepath.Join(dir, "root.seal")
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("seal: %s: %w", path, err)
	}
	var b Blob
	if err := json.Unmarshal(raw, &b); err != nil {
		return fmt.Errorf("seal: %s: %w", path, err)
	}
	// Already moved: a resumed ceremony must not fail on its own progress.
	//
	// wrappedBy is deliberately strict. Skipping here on a false match is how a
	// rotation silently does nothing: the destination reports the same KeyID as
	// the source, every blob looks already-moved, and `seal status` shows a
	// clean rotation while the material is still held by the retired key.
	if wrappedBy(&b, to) {
		if _, err := to.Unwrap(&b, []byte(rootKeyAAD)); err != nil {
			return fmt.Errorf("seal: root key claims the new seal but does not open under it: %w", err)
		}
		return nil
	}

	key, err := from.Unwrap(&b, []byte(rootKeyAAD))
	if err != nil {
		return fmt.Errorf("seal: cannot unseal the root key with the current seal: %w", err)
	}
	next, err := to.Wrap(key, []byte(rootKeyAAD))
	if err != nil {
		return err
	}
	blob, err := json.Marshal(next)
	if err != nil {
		return err
	}
	// Keep the old form until the new one is durably in place.
	if err := os.WriteFile(path+".prev", raw, 0o600); err != nil {
		return err
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Residue is material left in a data directory that would still open the domain
// under a RETIRED seal.
//
// After rotating from a file seal to a token, root.seal.prev holds the root key
// wrapped by the old seal, and the old key file usually sits beside it. Anyone
// with a copy of the directory therefore has both halves, and the custody
// change is cosmetic: the domain still opens with no device present. The
// rotation used to announce that "the old seal is no longer needed", which was
// true of running the domain and false of opening it.
//
// This is deliberately not deleted automatically. Those same two files are the
// only way back if the destination seal is lost — a real recovery path, and
// destroying it silently would be its own bad surprise. The operator decides;
// the tool's job is to make sure they know they are deciding.
type Residue struct {
	Paths  []string // files that, together, still open the domain
	Reason string
}

// FindResidue reports predecessor material in dir. active is the seal the
// domain now runs under.
func FindResidue(dir string, active Seal) (*Residue, error) {
	prev := filepath.Join(dir, "root.seal.prev")
	if _, err := os.Stat(prev); err != nil {
		return nil, nil // nothing kept from a previous ceremony
	}
	raw, err := os.ReadFile(prev)
	if err != nil {
		return nil, err
	}
	var b Blob
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, err
	}
	// A predecessor wrapped by the seal we now run under is not residue; it is
	// a redundant copy of the same custody.
	if b.Seal == active.Name() && b.KeyID == active.KeyID() {
		return nil, nil
	}
	r := &Residue{Paths: []string{prev}}
	r.Reason = fmt.Sprintf(
		"root.seal.prev holds this domain's root key wrapped by %s/%s, which is not the seal it "+
			"now runs under (%s/%s)", b.Seal, b.KeyID, active.Name(), active.KeyID())
	// A file seal sitting in the same directory completes the pair.
	if b.Seal == "file" {
		for _, name := range []string{"seal.key", filepath.Base(b.KeyID)} {
			p := filepath.Join(dir, name)
			if _, err := os.Stat(p); err == nil && !contains(r.Paths, p) {
				r.Paths = append(r.Paths, p)
			}
		}
	}
	return r, nil
}

// OpensDomain reports whether the residue is self-sufficient: both the wrapped
// root key AND a seal able to unwrap it are present here.
func (r *Residue) OpensDomain() bool { return r != nil && len(r.Paths) > 1 }

// Remove deletes the residue, finalizing a rotation. It is irreversible, and
// it also renders unreadable any backup taken before the rotation.
func (r *Residue) Remove() error {
	for _, p := range r.Paths {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("seal: removing %s: %w", p, err)
		}
	}
	return nil
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// RootKeyWrappedBy reports which seal and wrapping key currently hold the root
// key, without needing either seal to be available.
func RootKeyWrappedBy(dir string) (string, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "root.seal"))
	if err != nil {
		return "", err
	}
	var b Blob
	if err := json.Unmarshal(raw, &b); err != nil {
		return "", err
	}
	return b.Seal + "/" + b.KeyID, nil
}
