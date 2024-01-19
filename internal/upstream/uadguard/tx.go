package uadguard

import (
	"context"
	"fmt"

	"github.com/go-resty/resty/v2"
	"github.com/miekg/dns"

	"github.com/buglloc/DNSGateway/internal/upstream"
	"github.com/buglloc/DNSGateway/internal/upstream/uadguard/rules"
)

var _ upstream.Tx = (*Tx)(nil)

type Tx struct {
	httpc   *resty.Client
	rules   *rules.Storage
	autoPTR bool
	changed bool
}

func (t *Tx) Delete(r upstream.Rule) error {
	deleted := t.rules.Delete(r)
	if len(deleted) == 0 {
		return nil
	}

	t.changed = true
	if !t.needPTR(r.Type) {
		return nil
	}

	_ = t.rules.Delete(upstream.Rule{
		Name: r.ValueStr,
		Type: dns.TypePTR,
	})

	return nil
}

func (t *Tx) Append(r upstream.Rule) error {
	if r.ValueStr == "" {
		// TODO(buglloc): fix me
		r.ValueStr = fmt.Sprint(r.Value)
	}

	t.changed = true
	t.rules.Append(r)
	if !t.needPTR(r.Type) {
		return nil
	}

	arpa, err := dns.ReverseAddr(r.ValueStr)
	if err != nil {
		return fmt.Errorf("generate arpa address: %w", err)
	}

	_ = t.rules.Delete(upstream.Rule{
		Name: arpa,
		Type: dns.TypePTR,
	})

	t.rules.Append(upstream.Rule{
		Name:     arpa,
		Type:     dns.TypePTR,
		Value:    r.Name,
		ValueStr: r.Name,
	})
	return nil
}

func (t *Tx) Commit(ctx context.Context) error {
	if !t.changed {
		return nil
	}

	httpRsp, err := t.httpc.R().
		SetContext(ctx).
		SetHeader("Content-Type", "application/json").
		SetBody(struct {
			Rules []string `json:"rules"`
		}{
			Rules: t.rules.Dump(),
		}).
		Post("/control/filtering/set_rules")
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
