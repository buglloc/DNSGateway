package rules

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"

	"github.com/buglloc/DNSGateway/internal/upstream"
)

func TestParse(t *testing.T) {
	cases := []struct {
		in  []string
		out *Storage
	}{
		{
			in: []string{
				"lol",
				"kek",
			},
			out: &Storage{
				before: []string{
					"lol",
					"kek",
					"--b--",
				},
				rules: []Rule{},
				after: []string{
					"--e--",
				},
			},
		},
		{
			in: []string{
				"lol",
				"kek",
				"--b--",
			},
			out: &Storage{
				before: []string{
					"lol",
					"kek",
					"--b--",
				},
				rules: []Rule{},
				after: []string{
					"--e--",
				},
			},
		},
		{
			in: []string{
				"lol",
				"kek",
				"--b--",
				"--e--",
			},
			out: &Storage{
				before: []string{
					"lol",
					"kek",
					"--b--",
				},
				rules: []Rule{},
				after: []string{
					"--e--",
				},
			},
		},
		{
			in: []string{
				"lol",
				"kek",
				"|ya.ru^$dnsrewrite=NOERROR;A;1.2.3.3",
				"--b--",
				"|ya.ru^$dnsrewrite=NOERROR;A;1.2.3.3",
				"--e--",
				"|ya.ru^$dnsrewrite=NOERROR;A;1.2.3.3",
				"kek",
				"lol",
			},
			out: &Storage{
				before: []string{
					"lol",
					"kek",
					"|ya.ru^$dnsrewrite=NOERROR;A;1.2.3.3",
					"--b--",
				},
				rules: []Rule{
					{
						Rule: &upstream.Rule{
							Name:     "ya.ru.",
							Type:     dns.TypeA,
							Value:    net.ParseIP("1.2.3.3"),
							ValueStr: "1.2.3.3",
						},
					},
				},
				after: []string{
					"--e--",
					"|ya.ru^$dnsrewrite=NOERROR;A;1.2.3.3",
					"kek",
					"lol",
				},
			},
		},
	}

	p := NewParser("--b--", "--e--")
	for _, tc := range cases {
		t.Run(strings.Join(tc.in, "%%"), func(t *testing.T) {
			s, err := p.Parse(tc.in)
			require.NoError(t, err)

			require.EqualValues(t, tc.out, s)
		})
	}
}

func TestParseRule(t *testing.T) {
	cases := []struct {
		in  string
		out Rule
		err bool
	}{
		{
			in: "|4.3.2.1.in-addr.arpa^$dnsrewrite=NOERROR;PTR;example.net.",
			out: Rule{
				Rule: &upstream.Rule{
					Name:     "4.3.2.1.in-addr.arpa.",
					Type:     dns.TypePTR,
					Value:    "example.net.",
					ValueStr: "example.net.",
				},
			},
		},
		{
			in: "|2.0.0.0.0.0.0.0.4.f.7.0.0.0.0.0.0.0.4.3.0.0.0.0.8.b.6.0.2.0.a.2.ip6.arpa^$dnsrewrite=NOERROR;PTR;example.net",
			out: Rule{
				Rule: &upstream.Rule{
					Name:     "2.0.0.0.0.0.0.0.4.f.7.0.0.0.0.0.0.0.4.3.0.0.0.0.8.b.6.0.2.0.a.2.ip6.arpa.",
					Type:     dns.TypePTR,
					Value:    "example.net.",
					ValueStr: "example.net.",
				},
			},
		},
		{
			in: "|ya.ru^$dnsrewrite=NOERROR;A;1.2.3.3",
			out: Rule{
				Rule: &upstream.Rule{
					Name:     "ya.ru.",
					Type:     dns.TypeA,
					Value:    net.ParseIP("1.2.3.3"),
					ValueStr: "1.2.3.3",
				},
			},
		},
		{
			in: "|ya.ru^$dnsrewrite=NOERROR;AAAA;::1",
			out: Rule{
				Rule: &upstream.Rule{
					Name:     "ya.ru.",
					Type:     dns.TypeAAAA,
					Value:    net.ParseIP("::1"),
					ValueStr: "::1",
				},
			},
		},
		{
			in: "|ya.ru^$dnsrewrite=NOERROR;CNAME;google.com",
			out: Rule{
				Rule: &upstream.Rule{
					Name:     "ya.ru.",
					Type:     dns.TypeCNAME,
					Value:    "google.com.",
					ValueStr: "google.com.",
				},
			},
		},
		{
			in: "||ya.ru^$dnsrewrite=NOERROR;CNAME;google.com",
			out: Rule{
				Rule: &upstream.Rule{
					Name:     "*.ya.ru.",
					Type:     dns.TypeCNAME,
					Value:    "google.com.",
					ValueStr: "google.com.",
				},
			},
		},
		{
			in: `|k3s-lab-a-yawg.pve.buglloc.cc^$dnsrewrite=NOERROR;TXT;heritage=external-dns\,external-dns\/owner=thailab\,external-dns\/resource=service\/external-services\/pve-mahine-yawg`,
			out: Rule{
				Rule: &upstream.Rule{
					Name:     "k3s-lab-a-yawg.pve.buglloc.cc.",
					Type:     dns.TypeTXT,
					Value:    "heritage=external-dns,external-dns/owner=thailab,external-dns/resource=service/external-services/pve-mahine-yawg",
					ValueStr: "heritage=external-dns,external-dns/owner=thailab,external-dns/resource=service/external-services/pve-mahine-yawg",
				},
			},
		},
		{
			in: `|example.com^$dnsrewrite=NOERROR;MX;10 mail1.example.com`,
			out: Rule{
				Rule: &upstream.Rule{
					Name: "example.com.",
					Type: dns.TypeMX,
					Value: &dns.MX{
						Preference: 10,
						Mx:         "mail1.example.com",
					},
					ValueStr: "10 mail1.example.com",
				},
			},
		},
		{
			in: `|10.10.10.10.in-addr.arpa^$dnsrewrite=NOERROR;PTR;example.tsts`,
			out: Rule{
				Rule: &upstream.Rule{
					Name:     "10.10.10.10.in-addr.arpa.",
					Type:     dns.TypePTR,
					Value:    "example.tsts.",
					ValueStr: "example.tsts.",
				},
			},
		},
		{
			in: `|srv.tsts^$dnsrewrite=NOERROR;SRV;10 5 5223 server.tsts`,
			out: Rule{
				Rule: &upstream.Rule{
					Name: "srv.tsts.",
					Type: dns.TypeSRV,
					Value: &dns.SRV{
						Priority: 10,
						Weight:   5,
						Port:     5223,
						Target:   "server.tsts",
					},
					ValueStr: "10 5 5223 server.tsts",
				},
			},
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

			ruleStr := strings.TrimSuffix(tc.in, ".")
			require.Equal(t, ruleStr, actual.Format())
		})
	}
}

func TestFormat(t *testing.T) {
	cases := []struct {
		out string
		in  Rule
	}{
		{
			out: "|4.3.2.1.in-addr.arpa^$dnsrewrite=NOERROR;PTR;example.net",
			in: Rule{
				Rule: &upstream.Rule{
					Name:     "4.3.2.1.in-addr.arpa.",
					Type:     dns.TypePTR,
					Value:    "example.net.",
					ValueStr: "example.net.",
				},
			},
		},
		{
			out: "|2.0.0.0.0.0.0.0.4.f.7.0.0.0.0.0.0.0.4.3.0.0.0.0.8.b.6.0.2.0.a.2.ip6.arpa^$dnsrewrite=NOERROR;PTR;example.net",
			in: Rule{
				Rule: &upstream.Rule{
					Name:     "2.0.0.0.0.0.0.0.4.f.7.0.0.0.0.0.0.0.4.3.0.0.0.0.8.b.6.0.2.0.a.2.ip6.arpa.",
					Type:     dns.TypePTR,
					Value:    "example.net.",
					ValueStr: "example.net.",
				},
			},
		},
		{
			out: "|ya.ru^$dnsrewrite=NOERROR;A;1.2.3.3",
			in: Rule{
				Rule: &upstream.Rule{
					Name:     "ya.ru.",
					Type:     dns.TypeA,
					Value:    net.ParseIP("1.2.3.3"),
					ValueStr: "1.2.3.3",
				},
			},
		},
		{
			out: "|ya.ru^$dnsrewrite=NOERROR;AAAA;::1",
			in: Rule{
				Rule: &upstream.Rule{
					Name:     "ya.ru.",
					Type:     dns.TypeAAAA,
					Value:    net.ParseIP("::1"),
					ValueStr: "::1",
				},
			},
		},
		{
			out: "|ya.ru^$dnsrewrite=NOERROR;CNAME;google.com",
			in: Rule{
				Rule: &upstream.Rule{
					Name:     "ya.ru.",
					Type:     dns.TypeCNAME,
					Value:    "google.com.",
					ValueStr: "google.com.",
				},
			},
		},
		{
			out: "||ya.ru^$dnsrewrite=NOERROR;CNAME;google.com",
			in: Rule{
				Rule: &upstream.Rule{
					Name:     "*.ya.ru.",
					Type:     dns.TypeCNAME,
					Value:    "google.com.",
					ValueStr: "google.com.",
				},
			},
		},
		{
			out: `|k3s-lab-a-yawg.pve.buglloc.cc^$dnsrewrite=NOERROR;TXT;heritage=external-dns\,external-dns\/owner=thailab\,external-dns\/resource=service\/external-services\/pve-mahine-yawg`,
			in: Rule{
				Rule: &upstream.Rule{
					Name:     "k3s-lab-a-yawg.pve.buglloc.cc.",
					Type:     dns.TypeTXT,
					Value:    "heritage=external-dns,external-dns/owner=thailab,external-dns/resource=service/external-services/pve-mahine-yawg",
					ValueStr: "heritage=external-dns,external-dns/owner=thailab,external-dns/resource=service/external-services/pve-mahine-yawg",
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.out, func(t *testing.T) {
			require.Equal(t, tc.out, tc.in.Format())
		})
	}
}
