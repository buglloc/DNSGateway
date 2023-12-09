package ucloudflare

import (
	"fmt"
	"strings"

	"github.com/cloudflare/cloudflare-go"
	"github.com/miekg/dns"

	"github.com/buglloc/DNSGateway/internal/fqdn"
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

	content := r.Content
	switch r.Type {
	case "MX":
		content = fmt.Sprintf("%d %s", *r.Priority, r.Content)
	case "SRV":
		dp := r.Data.(map[string]interface{})
		content = fmt.Sprintf("%.f %s", dp["priority"], r.Content)
		// Cloudflare's API, annoyingly, automatically prepends the weight
		// and port into content, separated by tabs.
		content = strings.Replace(content, "\t", " ", -1)
	}

	uRule, err := upstream.NewRule(fqdn.FQDN(r.Name), rType, strings.TrimSpace(content))
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
