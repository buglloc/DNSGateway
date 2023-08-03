package rules

import (
	"fmt"
	"github.com/buglloc/DNSGateway/internal/upstream"
	"github.com/miekg/dns"
	"net"
	"strconv"
	"strings"
)

type Rule struct {
	UpstreamRule *upstream.Rule
}

func (r *Rule) Key() StoreKay {
	return StoreKay{
		Name: r.UpstreamRule.Name,
		Type: r.UpstreamRule.Type,
	}
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
		UpstreamRule: uRule,
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
		Name:  name,
		Type:  dns.TypeA,
		Value: ip,
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
		Name:  name,
		Type:  dns.TypeAAAA,
		Value: ip,
	}, nil
}

func newRuleCNAME(name string, valStr string) (*upstream.Rule, error) {
	domain := fqdn(valStr)
	if err := validateHostname(domain); err != nil {
		return nil, fmt.Errorf("invalid new domain %q: %w", valStr, err)
	}

	return &upstream.Rule{
		Name:  name,
		Type:  dns.TypeCNAME,
		Value: domain,
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
	}, nil
}

func newRulePTR(name string, valStr string) (*upstream.Rule, error) {
	fqdn := fqdn(valStr)
	if err := validateHostname(fqdn); err != nil {
		return nil, fmt.Errorf("invalid ptr host %q: %w", valStr, err)
	}

	return &upstream.Rule{
		Name:  name,
		Type:  dns.TypePTR,
		Value: fqdn,
	}, nil
}

func newRuleTXT(name string, valStr string) (*upstream.Rule, error) {
	return &upstream.Rule{
		Name:  name,
		Type:  dns.TypeTXT,
		Value: valStr,
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

var ReverseAddr = dns.ReverseAddr
