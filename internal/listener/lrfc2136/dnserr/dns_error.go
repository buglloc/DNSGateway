package dnserr

import (
	"fmt"
)

//go:generate  go run ./errsgen --pkg dnserr --out dns_error.errs.go

type DNSError struct {
	RCode  int
	Nested error
}

func NewDNSError(rcode int, nested error) *DNSError {
	return &DNSError{
		RCode:  rcode,
		Nested: nested,
	}
}

func (e DNSError) Error() string {
	if e.Nested == nil {
		return ""
	}
	return fmt.Sprintf("dns error[%d]: %v", e.RCode, e.Nested)
}

func (e *DNSError) Unwrap() error {
	return e.Nested
}

func (e *DNSError) Is(target error) bool {
	other, ok := target.(*DNSError)
	if !ok {
		return false
	}
	if e == nil && other == nil {
		return true
	}
	if e == nil || other == nil {
		return false
	}

	return e.RCode == other.RCode
}
