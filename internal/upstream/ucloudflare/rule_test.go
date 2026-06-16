package ucloudflare

import (
	"net"
	"testing"

	"github.com/cloudflare/cloudflare-go"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"

	"github.com/buglloc/DNSGateway/internal/upstream"
)

func TestRuleFromCFPreservesTTL(t *testing.T) {
	rule, err := RuleFromCF(cloudflare.DNSRecord{
		Type:    "A",
		Name:    "example.com",
		Content: "192.0.2.1",
		TTL:     3600,
	})
	require.NoError(t, err)
	require.Equal(t, uint32(3600), rule.upRecord.TTL)

	rr, err := rule.upRecord.RR()
	require.NoError(t, err)
	require.Equal(t, uint32(3600), rr.Header().Ttl)
}

func TestRuleFromUpstreamUsesTTL(t *testing.T) {
	rule, err := RuleFromUpstream(upstream.Rule{
		Name:     "example.com.",
		Type:     dns.TypeA,
		TTL:      3600,
		Value:    net.ParseIP("192.0.2.1"),
		ValueStr: "192.0.2.1",
	})
	require.NoError(t, err)
	require.Equal(t, 3600, rule.cfRecord.TTL)
}

func TestRuleFromUpstreamUsesDefaultTTLWhenUnset(t *testing.T) {
	rule, err := RuleFromUpstream(upstream.Rule{
		Name:     "example.com.",
		Type:     dns.TypeA,
		Value:    net.ParseIP("192.0.2.1"),
		ValueStr: "192.0.2.1",
	})
	require.NoError(t, err)
	require.Equal(t, defaultTTL, rule.cfRecord.TTL)
}
