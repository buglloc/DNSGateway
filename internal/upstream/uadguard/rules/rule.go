package rules

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/miekg/dns"

	"github.com/buglloc/DNSGateway/internal/upstream"
)

type Rule struct {
	*upstream.Rule
}

func (r *Rule) Same(other Rule) bool {
	return r.SameUpstreamRule(other.Rule)
}

func (r *Rule) SameUpstreamRule(other *upstream.Rule) bool {
	if other.Type == dns.TypeAXFR {
		return r.matchAxfrRule(other)
	}

	return r.matchPlainRule(other)
}

func (r *Rule) Format() string {
	value := EscapeString(fmt.Sprint(r.Value))
	name := unFqdn(r.Name)
	if strictName := strings.TrimPrefix(name, "*."); strictName != name {
		name = "|" + strictName
	}

	return fmt.Sprintf(
		"|%s^$dnsrewrite=NOERROR;%s;%s",
		name, dns.TypeToString[r.Type], unFqdn(value),
	)
}

func (r *Rule) matchAxfrRule(other *upstream.Rule) bool {
	if strings.HasSuffix(r.Name, other.Name) {
		return true
	}

	if strings.HasSuffix(r.ValueStr, other.Name) {
		return true
	}

	return false
}

func (r *Rule) matchPlainRule(other *upstream.Rule) bool {
	if other.Type != 0 && other.Type != r.Type {
		return false
	}

	if other.Name != "" && other.Name != r.Name {
		return false
	}

	if other.ValueStr != "" && other.ValueStr != r.ValueStr {
		return false
	}

	return true
}

func newRule(name string, rrType uint16, valStr string) (Rule, error) {
	var uRule *upstream.Rule
	var err error
	switch rrType {
	case dns.TypeA:
		uRule, err = newRuleA(name, valStr)

	case dns.TypeAAAA:
		uRule, err = newRuleAAAA(name, valStr)

	case dns.TypeCNAME:
		uRule, err = newRuleCNAME(name, valStr)

	case dns.TypeMX:
		uRule, err = newRuleMX(name, valStr)

	case dns.TypePTR:
		uRule, err = newRulePTR(name, valStr)

	case dns.TypeTXT:
		uRule, err = newRuleTXT(name, valStr)

	case dns.TypeSRV:
		uRule, err = newRuleSRV(name, valStr)

	default:
		return Rule{}, fmt.Errorf("unsupported rrType %d: %s", rrType, dns.TypeToString[rrType])
	}

	if err != nil {
		return Rule{}, fmt.Errorf("invalid rule %d[%s]: %w", rrType, dns.TypeToString[rrType], err)
	}

	return Rule{
		Rule: uRule,
	}, nil
}

func newRuleA(name string, valStr string) (*upstream.Rule, error) {
	ip := parseIP(valStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid ipv4: %q", valStr)
	}

	if ip4 := ip.To4(); ip4 == nil {
		return nil, fmt.Errorf("invalid ipv4: %q", valStr)
	}

	return &upstream.Rule{
		Name:     name,
		Type:     dns.TypeA,
		Value:    ip,
		ValueStr: valStr,
	}, nil
}

func newRuleAAAA(name string, valStr string) (*upstream.Rule, error) {
	ip := parseIP(valStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid ipv6: %q", valStr)
	} else if ip4 := ip.To4(); ip4 != nil {
		return nil, fmt.Errorf("want ipv6, got ipv4: %q", valStr)
	}

	return &upstream.Rule{
		Name:     name,
		Type:     dns.TypeAAAA,
		Value:    ip,
		ValueStr: valStr,
	}, nil
}

func newRuleCNAME(name string, valStr string) (*upstream.Rule, error) {
	domain := fqdn(valStr)
	if err := validateHostname(domain); err != nil {
		return nil, fmt.Errorf("invalid new domain %q: %w", valStr, err)
	}

	return &upstream.Rule{
		Name:     name,
		Type:     dns.TypeCNAME,
		Value:    domain,
		ValueStr: domain,
	}, nil
}

func newRuleMX(name string, valStr string) (*upstream.Rule, error) {
	parts := strings.SplitN(valStr, " ", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid mx: %q", valStr)
	}

	pref64, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid mx preference: %w", err)
	}

	exch := parts[1]
	if err := validateHostname(exch); err != nil {
		return nil, fmt.Errorf("invalid mx exchange %q: %w", exch, err)
	}

	return &upstream.Rule{
		Name: name,
		Type: dns.TypeMX,
		Value: &dns.MX{
			Preference: uint16(pref64),
			Mx:         exch,
		},
		ValueStr: valStr,
	}, nil
}

func newRulePTR(name string, valStr string) (*upstream.Rule, error) {
	domain := fqdn(valStr)
	if err := validateHostname(domain); err != nil {
		return nil, fmt.Errorf("invalid ptr host %q: %w", valStr, err)
	}

	return &upstream.Rule{
		Name:     name,
		Type:     dns.TypePTR,
		Value:    domain,
		ValueStr: domain,
	}, nil
}

func newRuleTXT(name string, valStr string) (*upstream.Rule, error) {
	valStr = UnescapeString(strings.TrimSpace(valStr))
	return &upstream.Rule{
		Name:     name,
		Type:     dns.TypeTXT,
		Value:    valStr,
		ValueStr: valStr,
	}, nil
}

func newRuleSRV(name string, valStr string) (*upstream.Rule, error) {
	fields := strings.Split(valStr, " ")
	if len(fields) < 4 {
		return nil, fmt.Errorf("invalid srv %q: need four fields", valStr)
	}

	prio64, err := strconv.ParseUint(fields[0], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid srv priority: %w", err)
	}

	weight64, err := strconv.ParseUint(fields[1], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid srv weight: %w", err)
	}

	port64, err := strconv.ParseUint(fields[2], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid srv port: %w", err)
	}

	target := fields[3]

	// From RFC 2782:
	//
	//   A Target of "." means that the service is decidedly not available
	//   at this domain.
	//
	if target != "." {
		if err := validateHostname(target); err != nil {
			return nil, fmt.Errorf("invalid srv target %q: %w", target, err)
		}
	}

	return &upstream.Rule{
		Name: name,
		Type: dns.TypeSRV,
		Value: &dns.SRV{
			Priority: uint16(prio64),
			Weight:   uint16(weight64),
			Port:     uint16(port64),
			Target:   target,
		},
		ValueStr: valStr,
	}, nil
}

func parseIP(in string) net.IP {
	for _, c := range in {
		if c != '.' && c != ':' &&
			(c < '0' || c > '9') &&
			(c < 'A' || c > 'F') &&
			(c < 'a' || c > 'f') &&
			c != '[' && c != ']' {
			return nil
		}
	}

	return net.ParseIP(in)
}
