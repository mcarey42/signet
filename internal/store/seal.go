package store

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
)

// Seal produces the barrier key that protects everything at rest.
//
// The MVP ships exactly one implementation. TPM, cloud KMS, and Shamir seals
// are the hardening milestone; this stays a small interface rather than a
// plugin surface until a second implementation actually exists.
type Seal interface {
	BarrierKey() ([]byte, error)
}

// KeyFileSeal derives the barrier key from a key file.
//
// The file is expected to hold high-entropy material (genesis writes 32 random
// bytes), so HKDF is the right primitive — this is deliberately NOT a password
// KDF and must not be pointed at a human-chosen passphrase.
type KeyFileSeal struct{ Path string }

const barrierKeyInfo = "signet/barrier/v1"

func (s KeyFileSeal) BarrierKey() ([]byte, error) {
	raw, err := os.ReadFile(s.Path)
	if err != nil {
		return nil, fmt.Errorf("seal: read key file: %w", err)
	}
	if len(raw) < 32 {
		return nil, fmt.Errorf("seal: key file %s holds %d bytes, need at least 32 of high-entropy material", s.Path, len(raw))
	}
	return hkdf.Key(sha256.New, raw, nil, barrierKeyInfo, 32)
}

// GenerateKeyFile writes a fresh 32-byte seal key, refusing to clobber one.
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
