package ucloudflare

import (
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/cloudflare/cloudflare-go"
	"github.com/miekg/dns"

	"github.com/buglloc/DNSGateway/internal/fqdn"
	"github.com/buglloc/DNSGateway/internal/upstream"
)

var noProxied = false

var errUnsupportedRecordType = errors.New("unsupported cloudflare record type")

type Rule struct {
	cfRecord cloudflare.DNSRecord
	upRecord upstream.Rule
}

func RuleFromCF(r cloudflare.DNSRecord) (Rule, error) {
	recordType := strings.ToUpper(r.Type)
	rType, ok := dns.StringToType[recordType]
	if !ok || !isSupportedRecordType(rType) {
		return Rule{}, fmt.Errorf("%w: %s", errUnsupportedRecordType, r.Type)
	}

	content := r.Content
	switch recordType {
	case "MX":
		if r.Priority == nil {
			return Rule{}, errors.New("mx priority is empty")
		}
		content = fmt.Sprintf("%d %s", *r.Priority, r.Content)
	case "SRV":
		srv, err := srvContentFromCF(r)
		if err != nil {
			return Rule{}, err
		}
		content = srv
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
	record := cloudflare.DNSRecord{
		Type:    upstream.TypeString(r.Type),
		Name:    r.Name,
		Content: r.ValueStr,
		TTL:     defaultTTL,
		Proxied: &noProxied,
	}

	switch r.Type {
	case dns.TypeMX:
		mx, ok := r.Value.(*dns.MX)
		if !ok {
			return Rule{}, fmt.Errorf("unexpected MX value type: %T", r.Value)
		}
		priority := mx.Preference
		record.Priority = &priority
		record.Content = mx.Mx

	case dns.TypeSRV:
		srv, ok := r.Value.(*dns.SRV)
		if !ok {
			return Rule{}, fmt.Errorf("unexpected SRV value type: %T", r.Value)
		}

		data := map[string]any{
			"priority": srv.Priority,
			"weight":   srv.Weight,
			"port":     srv.Port,
			"target":   srv.Target,
		}
		service, proto, name, ok := splitSRVName(r.Name)
		if ok {
			data["service"] = service
			data["proto"] = proto
			data["name"] = name
		}

		record.Content = srv.Target
		record.Data = data
	}

	return Rule{
		cfRecord: record,
		upRecord: r,
	}, nil
}

func isSupportedRecordType(rType uint16) bool {
	switch rType {
	case dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeMX, dns.TypePTR, dns.TypeTXT, dns.TypeSRV:
		return true
	default:
		return false
	}
}

func srvContentFromCF(r cloudflare.DNSRecord) (string, error) {
	data, ok := r.Data.(map[string]any)
	if !ok {
		return "", fmt.Errorf("unexpected SRV data type: %T", r.Data)
	}

	priority, err := uint16Field(data, "priority")
	if err != nil {
		return "", fmt.Errorf("invalid SRV priority: %w", err)
	}
	weight, err := uint16Field(data, "weight")
	if err != nil {
		return "", fmt.Errorf("invalid SRV weight: %w", err)
	}
	port, err := uint16Field(data, "port")
	if err != nil {
		return "", fmt.Errorf("invalid SRV port: %w", err)
	}
	target, err := stringField(data, "target")
	if err != nil {
		return "", fmt.Errorf("invalid SRV target: %w", err)
	}

	return fmt.Sprintf("%d %d %d %s", priority, weight, port, target), nil
}

func uint16Field(data map[string]any, name string) (uint16, error) {
	v, ok := data[name]
	if !ok {
		return 0, errors.New("missing field")
	}

	switch n := v.(type) {
	case uint16:
		return n, nil
	case uint:
		if n > math.MaxUint16 {
			return 0, fmt.Errorf("out of range: %d", n)
		}
		return uint16(n), nil
	case uint64:
		if n > math.MaxUint16 {
			return 0, fmt.Errorf("out of range: %d", n)
		}
		return uint16(n), nil
	case int:
		if n < 0 || n > math.MaxUint16 {
			return 0, fmt.Errorf("out of range: %d", n)
		}
		return uint16(n), nil
	case int64:
		if n < 0 || n > math.MaxUint16 {
			return 0, fmt.Errorf("out of range: %d", n)
		}
		return uint16(n), nil
	case float64:
		if n < 0 || n > math.MaxUint16 || math.Trunc(n) != n {
			return 0, fmt.Errorf("out of range: %v", n)
		}
		return uint16(n), nil
	case float32:
		if n < 0 || n > math.MaxUint16 || float32(math.Trunc(float64(n))) != n {
			return 0, fmt.Errorf("out of range: %v", n)
		}
		return uint16(n), nil
	default:
		return 0, fmt.Errorf("unexpected type %T", v)
	}
}

func stringField(data map[string]any, name string) (string, error) {
	v, ok := data[name]
	if !ok {
		return "", errors.New("missing field")
	}

	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("unexpected type %T", v)
	}
	if s == "" {
		return "", errors.New("empty field")
	}

	return s, nil
}

func splitSRVName(name string) (string, string, string, bool) {
	parts := strings.SplitN(fqdn.UnFQDN(name), ".", 3)
	if len(parts) != 3 || !strings.HasPrefix(parts[0], "_") || !strings.HasPrefix(parts[1], "_") {
		return "", "", "", false
	}

	return parts[0], parts[1], parts[2], true
}

func (r *Rule) Same(other Rule) bool {
	return r.upRecord.Same(&other.upRecord)
}

func (r *Rule) SameUpstream(other upstream.Rule) bool {
	return r.upRecord.Same(&other)
}
