package rules

import (
	"github.com/buglloc/DNSGateway/internal/upstream"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"net"
	"testing"
)

func TestParseRule(t *testing.T) {
	cases := []struct {
		in  string
		out Rule
		err bool
	}{
		{
			in: "|4.3.2.1.in-addr.arpa^$dnsrewrite=NOERROR;PTR;example.net.",
			out: Rule{
				UpstreamRule: &upstream.Rule{
					Name:  "4.3.2.1.in-addr.arpa.",
					Type:  dns.TypePTR,
					Value: "example.net.",
				},
			},
		},
		{
			in: "|2.0.0.0.0.0.0.0.4.f.7.0.0.0.0.0.0.0.4.3.0.0.0.0.8.b.6.0.2.0.a.2.ip6.arpa^$dnsrewrite=NOERROR;PTR;example.net",
			out: Rule{
				UpstreamRule: &upstream.Rule{
					Name:  "2.0.0.0.0.0.0.0.4.f.7.0.0.0.0.0.0.0.4.3.0.0.0.0.8.b.6.0.2.0.a.2.ip6.arpa.",
					Type:  dns.TypePTR,
					Value: "example.net.",
				},
			},
		},
		{
			in: "|ya.ru^$dnsrewrite=NOERROR;A;1.2.3.3",
			out: Rule{
				UpstreamRule: &upstream.Rule{
					Name:  "ya.ru.",
					Type:  dns.TypeA,
					Value: net.ParseIP("1.2.3.3"),
				},
			},
		},
		{
			in: "|ya.ru^$dnsrewrite=NOERROR;AAAA;::1",
			out: Rule{
				UpstreamRule: &upstream.Rule{
					Name:  "ya.ru.",
					Type:  dns.TypeAAAA,
					Value: net.ParseIP("::1"),
				},
			},
		},
		{
			in: "|ya.ru^$dnsrewrite=NOERROR;CNAME;google.com",
			out: Rule{
				UpstreamRule: &upstream.Rule{
					Name:  "ya.ru.",
					Type:  dns.TypeCNAME,
					Value: "google.com.",
				},
			},
		},
		{
			in:  "||ya.ru^$dnsrewrite=NOERROR;CNAME;google.com",
			err: true,
		},
		{
			in:  "|ya.ru^$dnsrewrite=REFUSED;;",
			err: true,
		},
		{
			in:  "|canon.example.com^$dnstype=~CNAME",
			err: true,
		},
	}

	p := NewParser("b", "e")
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			actual, err := p.ParseRule([]byte(tc.in))
			if tc.err {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.EqualExportedValues(t, tc.out, actual)
		})
	}
}
