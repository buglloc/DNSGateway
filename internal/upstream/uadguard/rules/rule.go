package rules

import (
	"fmt"
	"strings"

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

	name := fqdn.UnFQDN(r.Name)
	if strictName := strings.TrimPrefix(name, "*."); strictName != name {
		name = "|" + strictName
	}

	return fmt.Sprintf(
		"|%s^$dnsrewrite=NOERROR;%s;%s",
		name, upstream.TypeString(r.Type), fqdn.UnFQDN(EscapeString(value)),
	)
}
