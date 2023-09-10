package ucloudflare

import (
	"fmt"
	"strings"

	"github.com/cloudflare/cloudflare-go"
	"github.com/miekg/dns"

	"github.com/buglloc/DNSGateway/internal/upstream"
)

var noProxied = false

type Rule struct {
	cfRecord cloudflare.DNSRecord
	upRecord upstream.Rule
}

func RuleFromCF(r cloudflare.DNSRecord) (Rule, error) {
	rType, ok := dns.StringToType[r.Type]
	if !ok {
		return Rule{}, fmt.Errorf("unexpected record type: %s", r.Type)
	}

	uRule, err := upstream.NewRule(r.Name, rType, strings.TrimSpace(r.Content))
	if err != nil {
		return Rule{}, err
	}

	return Rule{
		cfRecord: r,
		upRecord: uRule,
	}, nil
}

func RuleFromUpstream(r upstream.Rule) (Rule, error) {
	return Rule{
		cfRecord: cloudflare.DNSRecord{
			Type:    upstream.TypeString(r.Type),
			Name:    r.Name,
			Content: r.ValueStr,
			TTL:     defaultTTL,
			Proxied: &noProxied,
		},
		upRecord: r,
	}, nil
}

func (r *Rule) Same(other Rule) bool {
	return r.upRecord.Same(&other.upRecord)
}

func (r *Rule) SameUpstream(other upstream.Rule) bool {
	return r.upRecord.Same(&other)
}
