package upstream

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

type RValue any

type RType = uint16

type Rule struct {
	Name     string
	Type     RType
	Value    RValue
	ValueStr string
}

func NewRule(name string, typ RType, content string) (Rule, error) {
	return newRule(name, typ, content)
}

func RuleFromRR(rr dns.RR) (Rule, error) {
	var value any
	var valueStr string
	switch v := rr.(type) {
	case *dns.A:
		value = v.A
		valueStr = v.A.String()

	case *dns.AAAA:
		value = v.AAAA
		valueStr = v.AAAA.String()

	case *dns.CNAME:
		value = v.Target
		valueStr = v.Target

	case *dns.MX:
		value = v
		valueStr = fmt.Sprintf("%d %s", v.Preference, v.Mx)

	case *dns.PTR:
		value = v.Ptr
		valueStr = v.Ptr

	case *dns.TXT:
		value = v.Txt
		if len(v.Txt) > 0 {
			valueStr = v.Txt[0]
		}

	case *dns.SRV:
		value = v
		valueStr = fmt.Sprintf("%d %d %d %s", v.Priority, v.Weight, v.Priority, v.Target)

	default:
		return Rule{}, fmt.Errorf("unsupported rr: %s", rr)
	}

	return Rule{
		Name:     dns.Fqdn(rr.Header().Name),
		Type:     rr.Header().Rrtype,
		Value:    value,
		ValueStr: valueStr,
	}, nil
}

func (r *Rule) RR() (dns.RR, error) {
	hdr := dns.RR_Header{
		Name:   r.Name,
		Rrtype: r.Type,
		Class:  dns.ClassINET,
	}

	switch r.Type {
	case dns.TypeA:
		return &dns.A{
			Hdr: hdr,
			A:   r.Value.(net.IP),
		}, nil

	case dns.TypeAAAA:
		return &dns.AAAA{
			Hdr:  hdr,
			AAAA: r.Value.(net.IP),
		}, nil

	case dns.TypeCNAME:
		return &dns.CNAME{
			Hdr:    hdr,
			Target: r.Value.(string),
		}, nil

	case dns.TypeMX:
		mx := r.Value.(*dns.MX)
		return &dns.MX{
			Hdr:        hdr,
			Preference: mx.Preference,
			Mx:         mx.Mx,
		}, nil

	case dns.TypePTR:
		return &dns.PTR{
			Hdr: hdr,
			Ptr: r.Value.(string),
		}, nil

	case dns.TypeTXT:
		return &dns.TXT{
			Hdr: hdr,
			Txt: []string{r.Value.(string)},
		}, nil

	case dns.TypeSRV:
		srv := r.Value.(*dns.SRV)
		return &dns.SRV{
			Hdr:      hdr,
			Priority: srv.Priority,
			Weight:   srv.Weight,
			Port:     srv.Port,
			Target:   srv.Target,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported rrType %d: %s", r.Type, TypeString(r.Type))
	}
}

func (r *Rule) Same(other *Rule) bool {
	if other.Type == dns.TypeAXFR {
		return r.matchAxfrRule(other)
	}

	return r.matchPlainRule(other)
}

func (r *Rule) matchAxfrRule(other *Rule) bool {
	if strings.HasSuffix(r.Name, other.Name) {
		return true
	}

	if strings.HasSuffix(r.ValueStr, other.Name) {
		return true
	}

	return false
}

func (r *Rule) matchPlainRule(other *Rule) bool {
	if other.Type != dns.TypeNone && other.Type != r.Type {
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

func TypeString(typ RType) string {
	out, ok := dns.TypeToString[typ]
	if !ok {
		return fmt.Sprintf("unknown_%d", typ)
	}

	return out
}
