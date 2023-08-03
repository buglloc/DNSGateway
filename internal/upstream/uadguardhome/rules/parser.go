package rules

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"io"
	"strings"
)

type Parser struct {
	beginMarker string
	endMarker   string
}

func NewParser(beginMarker, endMarker string) *Parser {
	return &Parser{
		beginMarker: beginMarker,
		endMarker:   endMarker,
	}
}

func (p *Parser) Parse(in []string) (*Storage, error) {
	var beforeLen, afterRulesIdx int
	ourRules := make(map[StoreKay]Rule)
	inOurRules := false
	for i, r := range in {
		if !inOurRules {
			if r == p.beginMarker {
				inOurRules = true
				beforeLen = i
			}
			continue
		}

		if r == p.endMarker {
			afterRulesIdx = i
			break
		}

		rule, err := p.ParseRule([]byte(r))
		if err != nil {
			return nil, fmt.Errorf("invalid rule %q: %w", r, err)
		}

		ourRules[rule.Key()] = rule
	}

	return &Storage{
		before: in[:beforeLen],
		after:  in[afterRulesIdx:],
		rules:  ourRules,
	}, nil
}

// ParseRule parses AdBlock rule with dnsrewrite option
// AdBlock syntax: https://github.com/AdguardTeam/AdGuardHome/wiki/Hosts-Blocklists#adblock-style
// examples:
//
//	|4.3.2.1.in-addr.arpa^$dnsrewrite=NOERROR;PTR;example.net.
//	|2.0.0.0.0.0.0.0.4.f.7.0.0.0.0.0.0.0.4.3.0.0.0.0.8.b.6.0.2.0.a.2.ip6.arpa^$dnsrewrite=NOERROR;PTR;example.net.
//	|ya.ru^$dnsrewrite=NOERROR;A;1.2.3.3
//	|ya.ru^$dnsrewrite=NOERROR;AAAA;::1
//
// Limitation:
//   - only dnsrewrite
//   - only strict match
func (p *Parser) ParseRule(in []byte) (Rule, error) {
	in = bytes.TrimSpace(in)
	if len(in) == 0 {
		return Rule{}, io.EOF
	}

	if in[0] != '|' {
		return Rule{}, errors.New("must starts with '|'")
	}
	in = in[1:]

	idx := bytes.IndexByte(in, '^')
	if idx == -1 {
		return Rule{}, errors.New("expected '^' as end of hostname")
	}

	hostname := string(in[:idx])
	hostname = fqdn(hostname)
	if err := validateHostname(hostname); err != nil {
		return Rule{}, fmt.Errorf("invalid hostname %q: %w", hostname, err)
	}
	in = in[idx+1:]

	idx = bytes.IndexByte(in, ';')
	if idx == -1 {
		return Rule{}, errors.New("expected ';' as end of RRCode")
	}
	if !bytes.Equal(in[:idx], []byte("$dnsrewrite=NOERROR")) {
		return Rule{}, fmt.Errorf("invalid dnsrewrite option: %s", string(in[:idx]))
	}
	in = in[idx+1:]

	idx = bytes.IndexByte(in, ';')
	if idx == -1 {
		return Rule{}, errors.New("expected ';' as end of RRType")
	}
	rrType, err := strToRRType(string(in[:idx]))
	if err != nil {
		return Rule{}, fmt.Errorf("invalid RRType: %w", err)
	}
	in = in[idx+1:]

	if idx = indexComment(in); idx != -1 {
		in = in[:idx]
	}

	return newRule(hostname, rrType, string(in))
}

func strToRRType(s string) (rr uint16, err error) {
	// TypeNone and TypeReserved are special cases in package dns.
	if strings.EqualFold(s, "none") || strings.EqualFold(s, "reserved") {
		return 0, errors.New("dns rr type is none or reserved")
	}

	typ, ok := dns.StringToType[strings.ToUpper(s)]
	if !ok {
		return 0, fmt.Errorf("dns rr type %q is invalid", s)
	}

	return typ, nil
}

func indexComment(in []byte) int {
	for i, b := range in {
		switch b {
		case '!', '#':
			return i
		}
	}

	return -1
}

func unFqdn(s string) string {
	return strings.TrimSuffix(s, ".")
}

func fqdn(s string) string {
	if isFqdn(s) {
		return s
	}
	return s + "."
}

func isFqdn(s string) bool {
	return len(s) > 1 && s[len(s)-1] == '.'
}

func validateHostname(fqdn string) (err error) {
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
