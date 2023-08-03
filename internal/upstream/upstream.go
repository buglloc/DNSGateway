package upstream

import (
	"context"
	"fmt"
	"net"

	"github.com/miekg/dns"
)

type Upstream interface {
	Tx(ctx context.Context) (Tx, error)
	Query(ctx context.Context, name string, qType RType) (*Rule, error)
}

type Tx interface {
	Delete(r *Rule) error
	Update(r *Rule) error
	Commit(ctx context.Context) error
	Close()
}

type RValue any

type RType = uint16

type Rule struct {
	Name  string
	Type  RType
	Value RValue
}

func (r *Rule) RR() (dns.RR, error) {
	hdr := dns.RR_Header{
		Name:   r.Name,
		Rrtype: r.Type,
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
		return nil, fmt.Errorf("unsupported rrType %d: %s", r.Type, dns.TypeToString[r.Type])
	}
}
