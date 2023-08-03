package uadguardhome

import (
	"context"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/go-resty/resty/v2"
	"github.com/miekg/dns"
	"net"
)

type Tx struct {
	httpc   *resty.Client
	rules   *rulesHolder
	autoPTR bool
}

func (t *Tx) Delete(r dns.RR) error {
	key := ruleKey{
		Name:   r.Header().Name,
		RRType: r.Header().Rrtype,
	}

	old, ok := t.rules.rules[key]
	if !ok {
		return nil
	}

	delete(t.rules.rules, key)

	if !t.needPTR(old.DNSRewrite.RRType) {
		return nil
	}

	ip, ok := old.DNSRewrite.Value.(net.IP)
	if ok {
		return nil
	}
	key = ruleKey{
		Name:   ip.String(),
		RRType: dns.TypePTR,
	}
	delete(t.rules.rules, key)
	return nil
}

func (t *Tx) Update(r dns.RR) error {
	key := ruleKey{
		Name:   r.Header().Name,
		RRType: r.Header().Rrtype,
	}
	t.rules.rules[key] = &rules.NewNetworkRule()
}

func (t *Tx) Commit(ctx context.Context) error {

}

func (t *Tx) needPTR(rrType uint16) bool {
	if !t.autoPTR {
		return false
	}

	return rrType == dns.TypeA || rrType == dns.TypeAAAA
}
