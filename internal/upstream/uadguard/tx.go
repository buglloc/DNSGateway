package uadguard

import (
	"context"
	"fmt"
	"net"

	"github.com/go-resty/resty/v2"
	"github.com/miekg/dns"

	"github.com/buglloc/DNSGateway/internal/upstream"
	"github.com/buglloc/DNSGateway/internal/upstream/uadguard/rules"
)

type Tx struct {
	httpc   *resty.Client
	rules   *rules.Storage
	autoPTR bool
}

func (t *Tx) Delete(r *upstream.Rule) error {
	rr, ok := t.rules.ByName(r.Name, r.Type)
	if !ok {
		return nil
	}

	t.rules.Delete(rr)
	if !t.needPTR(rr.Type) {
		return nil
	}

	ip, ok := rr.Value.(net.IP)
	if !ok {
		return nil
	}

	rr, ok = t.rules.ByName(ip.String(), dns.TypePTR)
	if ok {
		t.rules.Delete(rr)
	}

	return nil
}

func (t *Tx) Update(r *upstream.Rule) error {
	t.rules.Set(rules.Rule{Rule: r})
	if !t.needPTR(r.Type) {
		return nil
	}

	arpa, err := dns.ReverseAddr(r.Value.(net.IP).String())
	if err != nil {
		return fmt.Errorf("unable to generate arpa address: %w", err)
	}

	t.rules.Set(rules.Rule{
		Rule: &upstream.Rule{
			Name:  arpa,
			Type:  dns.TypePTR,
			Value: r.Name,
		},
	})
	return nil
}

func (t *Tx) Commit(ctx context.Context) error {
	httpRsp, err := t.httpc.R().
		SetContext(ctx).
		SetHeader("Content-Type", "application/json").
		SetBody(struct {
			Rules []string `json:"rules"`
		}{
			Rules: t.rules.Dump(),
		}).
		Get("/control/filtering/set_rules")
	if err != nil {
		return fmt.Errorf("make http request: %w", err)
	}

	if httpRsp.IsError() {
		return fmt.Errorf("non-200 response: %s", string(httpRsp.Body()))
	}

	return nil
}

func (t *Tx) Close() {}

func (t *Tx) needPTR(rrType uint16) bool {
	if !t.autoPTR {
		return false
	}

	return rrType == dns.TypeA || rrType == dns.TypeAAAA
}
