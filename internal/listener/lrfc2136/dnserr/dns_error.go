package dnserr

import (
	"fmt"

	"github.com/miekg/dns"
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

	rCodeStr, ok := dns.RcodeToString[e.RCode]
	if !ok {
		rCodeStr = fmt.Sprint(e.RCode)
	}

	return fmt.Sprintf("dns error[%s]: %v", rCodeStr, e.Nested)
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
