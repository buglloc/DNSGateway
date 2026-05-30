package rules

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"

	"github.com/buglloc/DNSGateway/internal/fqdn"
	"github.com/buglloc/DNSGateway/internal/upstream"
)

type Rule struct {
	*upstream.Rule
}

func (r *Rule) Same(other Rule) bool {
	return r.SameUpstreamRule(other.Rule)
}

func (r *Rule) SameUpstreamRule(other *upstream.Rule) bool {
	return r.Rule.Same(other)
}

func (r *Rule) Format() string {
	value := r.ValueStr
	if value == "" {
		value = fmt.Sprint(r.Value)
	}
	switch r.Type {
	case dns.TypeCNAME, dns.TypePTR:
		value = fqdn.UnFQDN(value)
	case dns.TypeMX:
		parts := strings.SplitN(value, " ", 2)
		if len(parts) == 2 && parts[1] != "." {
			value = parts[0] + " " + fqdn.UnFQDN(parts[1])
		}
	case dns.TypeSRV:
		parts := strings.Split(value, " ")
		if len(parts) >= 4 && parts[3] != "." {
			parts[3] = fqdn.UnFQDN(parts[3])
			value = strings.Join(parts, " ")
		}
	}

	name := fqdn.UnFQDN(r.Name)
	if strictName := strings.TrimPrefix(name, "*."); strictName != name {
		name = "|" + strictName
	}

	return fmt.Sprintf(
		"|%s^$dnsrewrite=NOERROR;%s;%s",
		name, upstream.TypeString(r.Type), EscapeString(value),
	)
}
