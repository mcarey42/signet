package kernel

import (
	"errors"
	"fmt"
	"strings"
)

// Signet's path grammar is SPIFFE's segment grammar, lowercased.
//
// Adopting it wholesale means every principal path serializes losslessly to a
// SPIFFE ID in the X.509 dialect, so the kernel and the SPIFFE layer can never
// disagree about what two paths mean — and it kills unicode-confusable, case,
// and empty-segment bugs in one move (docs/13 F11).
const (
	MaxPathLen   = 1024
	MaxPathDepth = 64
)

var ErrEmptyPath = errors.New("path: empty")

// ValidatePath accepts "/" (the domain root) and absolute paths whose segments
// match [a-z0-9._-]+, excluding "." and "..".
func ValidatePath(p string) error {
	if p == "" {
		return ErrEmptyPath
	}
	if p[0] != '/' {
		return fmt.Errorf("path %q: must be absolute", p)
	}
	if len(p) > MaxPathLen {
		return fmt.Errorf("path: %d bytes exceeds limit %d", len(p), MaxPathLen)
	}
	if p == "/" {
		return nil
	}
	if strings.HasSuffix(p, "/") {
		return fmt.Errorf("path %q: trailing slash", p)
	}
	segs := strings.Split(p[1:], "/")
	if len(segs) > MaxPathDepth {
		return fmt.Errorf("path: depth %d exceeds limit %d", len(segs), MaxPathDepth)
	}
	for _, s := range segs {
		if s == "" {
			return fmt.Errorf("path %q: empty segment", p)
		}
		if s == "." || s == ".." {
			return fmt.Errorf("path %q: relative segment %q", p, s)
		}
		for i := 0; i < len(s); i++ {
			c := s[i]
			ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-'
			if !ok {
				return fmt.Errorf("path %q: illegal byte %q in segment %q (allowed: a-z 0-9 . _ -)", p, c, s)
			}
		}
	}
	return nil
}

// ScopeCovers reports whether a binding at scope applies to path. Comparison is
// component-wise, never substring: /clusters/lab does not cover
// /clusters/lab-2 (docs/13, E-01 K-4).
func ScopeCovers(scope, path string) bool {
	if scope == "/" {
		return true
	}
	if scope == path {
		return true
	}
	return strings.HasPrefix(path, scope+"/")
}
