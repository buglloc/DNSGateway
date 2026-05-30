package upstream

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestRuleFromRRTXTChunksRoundTrip(t *testing.T) {
	rr := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   "txt.example.com.",
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
		},
		Txt: []string{"foo", "bar"},
	}

	rule, err := RuleFromRR(rr)
	require.NoError(t, err)
	require.Equal(t, []string{"foo", "bar"}, rule.Value)

	actual, err := rule.RR()
	require.NoError(t, err)
	require.Equal(t, []string{"foo", "bar"}, actual.(*dns.TXT).Txt)
}

func TestRuleSameTXTMatchesChunks(t *testing.T) {
	stored := Rule{
		Name:     "txt.example.com.",
		Type:     dns.TypeTXT,
		Value:    []string{"foo", "bar"},
		ValueStr: "foobar",
	}

	sameChunks := Rule{
		Name:     "txt.example.com.",
		Type:     dns.TypeTXT,
		Value:    []string{"foo", "bar"},
		ValueStr: "foobar",
	}
	differentChunks := Rule{
		Name:     "txt.example.com.",
		Type:     dns.TypeTXT,
		Value:    []string{"foobar"},
		ValueStr: "foobar",
	}

	require.True(t, stored.Same(&sameChunks))
	require.False(t, stored.Same(&differentChunks))
}
