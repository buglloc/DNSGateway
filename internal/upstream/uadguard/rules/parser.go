package rules

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/miekg/dns"

	"github.com/buglloc/DNSGateway/internal/fqdn"
	"github.com/buglloc/DNSGateway/internal/upstream"
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
	beforeLen := -1
	afterRulesIdx := -1
	ourRules := make([]Rule, 0)
	inOurRules := false
	for i, r := range in {
		if !inOurRules {
			if r == p.beginMarker {
				inOurRules = true
				beforeLen = i + 1
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

		ourRules = append(ourRules, rule)
	}

	if beforeLen == -1 {
		beforeLen = len(in)
	}

	if afterRulesIdx == -1 {
		afterRulesIdx = len(in)
	}

	before := make([]string, beforeLen)
	copy(before, in[:beforeLen])
	if len(before) == 0 || before[len(before)-1] != p.beginMarker {
		before = append(before, p.beginMarker)
	}

	after := make([]string, len(in)-afterRulesIdx)
	copy(after, in[afterRulesIdx:])
	if len(after) == 0 || after[0] != p.endMarker {
		after = append([]string{p.endMarker}, after...)
	}

	return &Storage{
		before: before,
		after:  after,
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
		return Rule{}, errors.New("expected '^' as end of name")
	}

	nameBytes := in[:idx]
	if nameBytes[0] == '|' {
		nameBytes = append([]byte{'*', '.'}, nameBytes[1:]...)
	}
	name := fqdn.FQDN(string(nameBytes))

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

	uRule, err := upstream.NewRule(name, rrType, UnescapeString(strings.TrimSpace(string(in))))
	if err != nil {
		return Rule{}, err
	}

	return Rule{
		Rule: &uRule,
	}, nil
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
