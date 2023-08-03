package uadguardhome

import (
	"fmt"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/miekg/dns"
	"net"
)

type ruleKey struct {
	Name   string
	RRType uint16
}

type rulesHolder struct {
	beforeRules []string
	afterRules  []string
	rules       map[ruleKey]*rules.NetworkRule
}

func parseRules(in []string) (*rulesHolder, error) {
	var beforeLen, afterRulesIdx int
	ourRules := make(map[ruleKey]*rules.NetworkRule)
	inOurRules := false
	for i, r := range in {
		if !inOurRules {
			if r == rulesMarkerBegin {
				inOurRules = true
				beforeLen = i
			}
			continue
		}

		if r == rulesMarkerEnd {
			afterRulesIdx = i
			break
		}

		adRule, err := rules.NewNetworkRule(r, 0)
		if err != nil {
			return nil, fmt.Errorf("invalid rule %q: %w", r, err)
		}

		if adRule.DNSRewrite == nil {
			return nil, fmt.Errorf("invalid rule %q: dnsrewrite expected", r)
		}

		key := ruleKey{
			Name:   adRule.Shortcut,
			RRType: adRule.DNSRewrite.RRType,
		}
		ourRules[key] = adRule
	}

	return &rulesHolder{
		beforeRules: in[:beforeLen],
		afterRules:  in[afterRulesIdx:],
		rules:       ourRules,
	}, nil
}

func ruleToRR(r *rules.NetworkRule) (dns.RR, error) {
	hdr := dns.RR_Header{
		Name:   r.Shortcut,
		Rrtype: r.DNSRewrite.RRType,
		Ttl:    99,
	}
	switch r.DNSRewrite.RRType {
	case dns.TypeA:
		ip, _ := r.DNSRewrite.Value.(net.IP)
		return &dns.A{
			Hdr: hdr,
			A:   ip,
		}, nil
	case dns.TypeAAAA:
		ip, _ := r.DNSRewrite.Value.(net.IP)
		return &dns.AAAA{
			Hdr:  hdr,
			AAAA: ip,
		}, nil
	case dns.TypeCNAME:
		target, _ := r.DNSRewrite.Value.(string)
		return &dns.CNAME{
			Hdr:    hdr,
			Target: target,
		}, nil
	case dns.TypePTR:
		ptr, _ := r.DNSRewrite.Value.(string)
		return &dns.PTR{
			Hdr: hdr,
			Ptr: ptr,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported rrtype: %d", r.DNSRewrite.RRType)
	}
}
