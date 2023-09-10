package fqdn

import (
	"fmt"
	"strings"
)

func UnFQDN(s string) string {
	return strings.TrimSuffix(s, ".")
}

func FQDN(s string) string {
	if IsFqdn(s) {
		return s
	}
	return s + "."
}

func IsFqdn(s string) bool {
	return len(s) > 1 && s[len(s)-1] == '.'
}

func ValidateHostname(fqdn string) (err error) {
	l := len(fqdn)
	if l == 0 {
		return fmt.Errorf("invalid hostname length: %d", l)
	}

	parts := strings.Split(fqdn, ".")
	lastPart := len(parts) - 1
	for i, p := range parts {
		if len(p) == 0 {
			if i == lastPart {
				break
			}

			return fmt.Errorf("empty hostname part at index %d", i)
		}

		if r := p[0]; !isValidHostFirstRune(rune(r)) {
			return fmt.Errorf("invalid hostname part at index %d: invalid char %q at index %d", i, r, 0)
		}

		for j, r := range p[1:] {
			if !isValidHostRune(r) {
				return fmt.Errorf("invalid hostname part at index %d: invalid char %q at index %d", i, r, j+1)
			}
		}
	}

	return nil
}

// isValidHostRune returns true if r is a valid rune for a hostname part.
func isValidHostRune(r rune) (ok bool) {
	return r == '-' || isValidHostFirstRune(r)
}

// isValidHostFirstRune returns true if r is a valid first rune for a hostname
// part.
func isValidHostFirstRune(r rune) (ok bool) {
	return (r >= 'a' && r <= 'z') ||
		(r >= 'A' && r <= 'Z') ||
		(r >= '0' && r <= '9')
}
