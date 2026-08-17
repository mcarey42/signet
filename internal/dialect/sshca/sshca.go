// Package sshca issues OpenSSH certificates.
//
// This is the cheapest high-value dialect Signet has: a host trusts one CA
// public key and one AuthorizedPrincipalsFile line, and key sprawl across a
// fleet stops being a thing that exists. Certificates are short-lived, so
// removing someone's access is a matter of not renewing it.
//
// DEPENDENCY EXCEPTION (docs/09): this package imports golang.org/x/crypto/ssh.
// The OpenSSH certificate format is a wire format with exact framing — nonce,
// serial, principals, critical options, extensions, signature-key blob — and
// x/crypto/ssh is the implementation OpenSSH-compatible tooling is written
// against. Hand-rolling it to save one dependency would mean hand-rolling the
// part where mistakes are silent, and x/crypto is maintained by the Go team as
// an extension of the standard library.
package sshca

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/mcarey42/signet/internal/kernel"
	"github.com/mcarey42/signet/internal/keys"
	"github.com/mcarey42/signet/internal/seal"
	"golang.org/x/crypto/ssh"
)

// Role bounds what a certificate may claim. It is the kernel's type: the shape
// is stored in the kernel and read here, so there is one definition rather than
// two that can drift apart.
//
// AllowedPrincipals is an exact-match list, deliberately — a pattern language
// for usernames is a way to grant root by accident. PrincipalsFromRoles ties
// "who may log in as what" to the same bindings that govern everything else.
type Role = kernel.SSHRoleSpec

// Request is one signing request.
type Request struct {
	PublicKey  []byte   // authorized_keys format
	Principals []string // requested; must be permitted
	TTL        time.Duration
}

// Serializer renders filtered claims as an SSH certificate.
//
// Like every serializer in the mint path it receives claims the kernel has
// already filtered, so the roles it can translate into SSH principals are only
// the ones the caller may carry offline.
type Serializer struct {
	Role    Role
	Request Request
}

func (s *Serializer) Serialize(c kernel.Claims, k *keys.Key, sl seal.Seal) ([]byte, error) {
	if k.Purpose != keys.PurposeSSH {
		return nil, fmt.Errorf("sshca: cannot sign with a %s key", k.Purpose)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(s.Request.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("sshca: public key: %w", err)
	}

	principals, err := s.permittedPrincipals(c)
	if err != nil {
		return nil, err
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	cert := &ssh.Certificate{
		Key:             pub,
		Serial:          serial,
		CertType:        ssh.UserCert,
		KeyId:           c.Subject, // shows up in sshd's logs: who this was for
		ValidPrincipals: principals,
		ValidAfter:      uint64(c.NotBefore - 60), // a minute of clock slack
		ValidBefore:     uint64(c.ExpirySec),
		Permissions: ssh.Permissions{
			Extensions: s.extensions(),
		},
	}

	signer, err := k.Signer(sl)
	if err != nil {
		return nil, err
	}
	sshSigner, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		return nil, err
	}
	if err := cert.SignCert(rand.Reader, sshSigner); err != nil {
		return nil, fmt.Errorf("sshca: sign: %w", err)
	}
	return ssh.MarshalAuthorizedKey(cert), nil
}

// Verify re-parses the certificate from its own bytes and re-checks it against
// the role — the same rules, applied to what was actually produced rather than
// to what was intended (charter principle 6).
func (s *Serializer) Verify(cred []byte, c kernel.Claims, k *keys.Key, sl seal.Seal) error {
	pub, _, _, _, err := ssh.ParseAuthorizedKey(cred)
	if err != nil {
		return fmt.Errorf("re-parse: %w", err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return errors.New("what was produced is not a certificate")
	}
	if cert.CertType != ssh.UserCert {
		return errors.New("certificate is not a user certificate")
	}
	if len(cert.ValidPrincipals) == 0 {
		// A certificate with no principals is valid for *every* username in
		// OpenSSH. That is the single most dangerous mistake available here.
		return errors.New("certificate has no principals, which OpenSSH reads as all of them")
	}
	permitted, err := s.permittedPrincipals(c)
	if err != nil {
		return err
	}
	allowed := make(map[string]bool, len(permitted))
	for _, p := range permitted {
		allowed[p] = true
	}
	for _, got := range cert.ValidPrincipals {
		if !allowed[got] {
			return fmt.Errorf("certificate asserts principal %q, which was not authorized", got)
		}
	}
	if cert.ValidBefore != uint64(c.ExpirySec) {
		return errors.New("certificate lifetime does not match what was authorized")
	}
	if s.Role.MaxTTLSec > 0 {
		if lifetime := int64(cert.ValidBefore) - c.NotBefore; lifetime > s.Role.MaxTTLSec+60 {
			return fmt.Errorf("lifetime %ds exceeds the role maximum %ds", lifetime, s.Role.MaxTTLSec)
		}
	}
	// The certificate must verify under the CA key that signed it.
	pubKey, err := k.Public(sl)
	if err != nil {
		return err
	}
	caKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return err
	}
	if string(cert.SignatureKey.Marshal()) != string(caKey.Marshal()) {
		return errors.New("certificate is not signed by the expected CA key")
	}
	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return string(auth.Marshal()) == string(caKey.Marshal())
		},
	}
	if err := checker.CheckCert(cert.ValidPrincipals[0], cert); err != nil {
		return fmt.Errorf("certificate does not check out: %w", err)
	}
	return nil
}

// permittedPrincipals resolves which usernames this request may assert, given
// the roles the caller actually carries.
func (s *Serializer) permittedPrincipals(c kernel.Claims) ([]string, error) {
	granted := map[string]bool{}
	for _, p := range s.Role.AllowedPrincipals {
		granted[p] = true
	}
	// Roles reaching here are already tier-filtered, so a role the caller may
	// not carry offline cannot grant an SSH principal either.
	for _, role := range c.Roles {
		for _, p := range s.Role.PrincipalsFromRoles[role] {
			granted[p] = true
		}
	}
	if len(granted) == 0 {
		return nil, errors.New("sshca: the caller's roles grant no SSH principals")
	}

	requested := s.Request.Principals
	if len(requested) == 0 {
		// Asking for nothing means "everything I am entitled to", which is what
		// makes `ssh user@host` work without the client knowing its own rights.
		out := make([]string, 0, len(granted))
		for p := range granted {
			out = append(out, p)
		}
		sortStrings(out)
		return out, nil
	}
	for _, p := range requested {
		if !granted[p] {
			return nil, fmt.Errorf("sshca: principal %q is not permitted", p)
		}
	}
	return requested, nil
}

func (s *Serializer) extensions() map[string]string {
	ext := map[string]string{}
	if s.Role.AllowPTY {
		ext["permit-pty"] = ""
	}
	if s.Role.AllowAgentForward {
		ext["permit-agent-forwarding"] = ""
	}
	if s.Role.AllowPortForward {
		ext["permit-port-forwarding"] = ""
	}
	return ext
}

func randomSerial() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b[:]), nil
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// CAPublicKey renders the CA's public half in authorized_keys form, which is
// what a host puts in TrustedUserCAKeys.
func CAPublicKey(k *keys.Key, sl seal.Seal) ([]byte, error) {
	pub, err := k.Public(sl)
	if err != nil {
		return nil, err
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return ssh.MarshalAuthorizedKey(sshPub), nil
}
