package uadguardhome

import (
	"context"
	"errors"
	"fmt"
	"github.com/buglloc/DNSGateway/internal/upstream"
	"github.com/go-resty/resty/v2"
	"github.com/miekg/dns"
	"net/http"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	DefaultRetries   = 3
	DefaultTimeout   = 1 * time.Minute
	rulesMarkerBegin = "# ---- DNSGateway rules begin ----"
	rulesMarkerEnd   = "# ---- DNSGateway rules end ----"
)

var _ upstream.Upstream = (*Upstream)(nil)

type Upstream struct {
	httpc   *resty.Client
	log     zerolog.Logger
	autoPTR bool
}

func NewUpstream(opts ...Option) (*Upstream, error) {
	return NewClientWithHTTP(http.DefaultClient, opts...)
}

func NewClientWithHTTP(httpc *http.Client, opts ...Option) (*Upstream, error) {
	client := &Upstream{
		log: log.With().
			Str("source", "agh-upstream").
			Logger(),
		httpc: resty.NewWithClient(httpc).
			SetHeader("User-Agent", "DNSGateway").
			SetHeader("Content-Type", "application/json").
			SetRetryCount(DefaultRetries).
			SetTimeout(DefaultTimeout),
	}

	for _, opt := range opts {
		opt(client)
	}

	if client.httpc.BaseURL == "" {
		return nil, errors.New("no upstream configured, use WithUpstream()")
	}
	return client, nil
}

func (c *Upstream) Query(ctx context.Context, q dns.Question) (dns.RR, error) {
	rh, err := c.fetchRules(ctx)
	if err != nil {
		return nil, err
	}

	key := ruleKey{
		Name:   q.Name,
		RRType: q.Qtype,
	}
	rr, ok := rh.rules[key]
	if !ok {
		return nil, errors.New("not found")
	}

	return ruleToRR(rr)
}

func (c *Upstream) Tx(ctx context.Context) (upstream.Tx, error) {
	rh, err := c.fetchRules(ctx)
	if err != nil {
		return nil, err
	}

	return &Tx{
		httpc:   c.httpc,
		rules:   rh,
		autoPTR: c.autoPTR,
	}, nil
}

func (c *Upstream) fetchRules(ctx context.Context) (*rulesHolder, error) {
	var rsp FilteringStatusRsp
	var errRsp ErrorRsp
	httpRsp, err := c.httpc.R().
		SetContext(ctx).
		SetResult(&rsp).
		SetError(&errRsp).
		Get("/control/filtering/status")
	if err != nil {
		return nil, fmt.Errorf("make http request: %w", err)
	}

	if httpRsp.IsError() {
		return nil, errors.New(errRsp.Message)
	}

	return parseRules(rsp.Rules)
}
