package upstream

import (
	"strings"
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

func TestRuleRRPacksFQDNs(t *testing.T) {
	cases := []struct {
		name    string
		rrType  uint16
		content string
	}{
		{name: "example.com", rrType: dns.TypeA, content: "192.0.2.1"},
		{name: "alias.example.com", rrType: dns.TypeCNAME, content: "target.example.com"},
		{name: "example.com", rrType: dns.TypeMX, content: "10 mail.example.com"},
		{name: "_xmpp._tcp.example.com", rrType: dns.TypeSRV, content: "10 5 5223 server.example.com"},
		{name: "1.2.0.192.in-addr.arpa", rrType: dns.TypePTR, content: "ptr.example.com"},
	}

	for _, tc := range cases {
		t.Run(TypeString(tc.rrType), func(t *testing.T) {
			rule, err := NewRule(tc.name, tc.rrType, tc.content)
			require.NoError(t, err)

			rr, err := rule.RR()
			require.NoError(t, err)

			msg := new(dns.Msg)
			msg.SetReply(&dns.Msg{
				MsgHdr: dns.MsgHdr{Id: 1},
				Question: []dns.Question{{
					Name:   "example.com.",
					Qtype:  dns.TypeAXFR,
					Qclass: dns.ClassINET,
				}},
			})
			msg.Answer = []dns.RR{rr}

			_, err = msg.Pack()
			require.NoError(t, err)
		})
	}
}

func TestNewRuleTXTChunksValues(t *testing.T) {
	first := strings.Repeat("a", 200)
	second := strings.Repeat("b", 100)
	cases := []struct {
		name     string
		content  string
		value    []string
		valueStr string
	}{
		{
			name:     "quoted chunks",
			content:  `"` + first + `" "` + second + `"`,
			value:    []string{first, second},
			valueStr: first + second,
		},
		{
			name:     "long raw value",
			content:  strings.Repeat("a", 300),
			value:    []string{strings.Repeat("a", 255), strings.Repeat("a", 45)},
			valueStr: strings.Repeat("a", 300),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule, err := NewRule("txt.example.com", dns.TypeTXT, tc.content)
			require.NoError(t, err)
			require.Equal(t, tc.value, rule.Value)
			require.Equal(t, tc.valueStr, rule.ValueStr)

			rr, err := rule.RR()
			require.NoError(t, err)

			msg := new(dns.Msg)
			msg.SetReply(&dns.Msg{
				MsgHdr: dns.MsgHdr{Id: 1},
				Question: []dns.Question{{
					Name:   "example.com.",
					Qtype:  dns.TypeAXFR,
					Qclass: dns.ClassINET,
				}},
			})
			msg.Answer = []dns.RR{rr}

			_, err = msg.Pack()
			require.NoError(t, err)
		})
	}
}
