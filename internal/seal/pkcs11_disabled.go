//go:build !pkcs11

package seal

import "errors"

// PKCS11Config is declared in both builds so configuration parsing does not
// have to change shape depending on how the binary was compiled.
type PKCS11Config struct {
	Module string
	Token  string
	Slot   string
	Pin    string
	Label  string
}

// openPKCS11 fails clearly in the default build rather than silently ignoring a
// configured hardware seal — a domain that believes its keys are in an HSM and
// is wrong is worse off than one that refuses to start.
func openPKCS11(PKCS11Config) (Seal, error) {
	return nil, errors.New(
		"seal: this binary was built without PKCS#11 support; rebuild with -tags pkcs11 " +
			"(it links a vendor C library through cgo, which the default static build avoids)")
}
