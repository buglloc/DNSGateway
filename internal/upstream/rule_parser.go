package upstream

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/miekg/dns"

	"github.com/buglloc/DNSGateway/internal/fqdn"
)

func newRule(name string, rrType uint16, valStr string) (Rule, error) {
	var out Rule
	var err error
	switch rrType {
	case dns.TypeA:
		out, err = newRuleA(name, valStr)

	case dns.TypeAAAA:
		out, err = newRuleAAAA(name, valStr)

	case dns.TypeCNAME:
		out, err = newRuleCNAME(name, valStr)

	case dns.TypeMX:
		out, err = newRuleMX(name, valStr)

	case dns.TypePTR:
		out, err = newRulePTR(name, valStr)

	case dns.TypeTXT:
		out, err = newRuleTXT(name, valStr)

	case dns.TypeSRV:
		out, err = newRuleSRV(name, valStr)

	default:
		return Rule{}, fmt.Errorf("unsupported rrType %d: %s", rrType, TypeString(rrType))
	}

	if err != nil {
		return Rule{}, fmt.Errorf("invalid rule %d[%s]: %w", rrType, TypeString(rrType), err)
	}

	return out, nil
}

func newRuleA(name string, valStr string) (Rule, error) {
	ip := parseIP(valStr)
	if ip == nil {
		return Rule{}, fmt.Errorf("invalid ipv4: %q", valStr)
	}

	if ip4 := ip.To4(); ip4 == nil {
		return Rule{}, fmt.Errorf("invalid ipv4: %q", valStr)
	}

	return Rule{
		Name:     name,
		Type:     dns.TypeA,
		Value:    ip,
		ValueStr: valStr,
	}, nil
}

func newRuleAAAA(name string, valStr string) (Rule, error) {
	ip := parseIP(valStr)
	if ip == nil {
		return Rule{}, fmt.Errorf("invalid ipv6: %q", valStr)
	} else if ip4 := ip.To4(); ip4 != nil {
		return Rule{}, fmt.Errorf("want ipv6, got ipv4: %q", valStr)
	}

	return Rule{
		Name:     name,
		Type:     dns.TypeAAAA,
		Value:    ip,
		ValueStr: valStr,
	}, nil
}

func newRuleCNAME(name string, valStr string) (Rule, error) {
	domain := fqdn.FQDN(valStr)
	if err := fqdn.ValidateHostname(domain); err != nil {
		return Rule{}, fmt.Errorf("invalid new domain %q: %w", valStr, err)
	}

	return Rule{
		Name:     name,
		Type:     dns.TypeCNAME,
		Value:    domain,
		ValueStr: domain,
	}, nil
}

func newRuleMX(name string, valStr string) (Rule, error) {
	parts := strings.SplitN(valStr, " ", 2)
	if len(parts) != 2 {
		return Rule{}, fmt.Errorf("invalid mx: %q", valStr)
	}

	pref64, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		return Rule{}, fmt.Errorf("invalid mx preference: %w", err)
	}

	exch := parts[1]
	if err := fqdn.ValidateHostname(exch); err != nil {
		return Rule{}, fmt.Errorf("invalid mx exchange %q: %w", exch, err)
	}

	return Rule{
		Name: name,
		Type: dns.TypeMX,
		Value: &dns.MX{
			Preference: uint16(pref64),
			Mx:         exch,
		},
		ValueStr: valStr,
	}, nil
}

func newRulePTR(name string, valStr string) (Rule, error) {
	domain := fqdn.FQDN(valStr)
	if err := fqdn.ValidateHostname(domain); err != nil {
		return Rule{}, fmt.Errorf("invalid ptr host %q: %w", valStr, err)
	}

	return Rule{
		Name:     name,
		Type:     dns.TypePTR,
		Value:    domain,
		ValueStr: domain,
	}, nil
}

func newRuleTXT(name string, valStr string) (Rule, error) {
	return Rule{
		Name:     name,
		Type:     dns.TypeTXT,
		Value:    valStr,
		ValueStr: valStr,
	}, nil
}

func newRuleSRV(name string, valStr string) (Rule, error) {
	fields := strings.Split(valStr, " ")
	if len(fields) < 4 {
		return Rule{}, fmt.Errorf("invalid srv %q: need four fields", valStr)
	}

	prio64, err := strconv.ParseUint(fields[0], 10, 16)
	if err != nil {
		return Rule{}, fmt.Errorf("invalid srv priority: %w", err)
	}

	weight64, err := strconv.ParseUint(fields[1], 10, 16)
	if err != nil {
		return Rule{}, fmt.Errorf("invalid srv weight: %w", err)
	}

	port64, err := strconv.ParseUint(fields[2], 10, 16)
	if err != nil {
		return Rule{}, fmt.Errorf("invalid srv port: %w", err)
	}

	target := fields[3]

	// From RFC 2782:
	//
	//   A Target of "." means that the service is decidedly not available
	//   at this domain.
	//
	if target != "." {
		if err := fqdn.ValidateHostname(target); err != nil {
			return Rule{}, fmt.Errorf("invalid srv target %q: %w", target, err)
		}
	}

	return Rule{
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
