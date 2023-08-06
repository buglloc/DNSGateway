package uadguard

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/buglloc/DNSGateway/internal/upstream"
	"github.com/buglloc/DNSGateway/internal/upstream/uadguard/rules"
	"github.com/buglloc/DNSGateway/internal/xhttp"
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
	parser  *rules.Parser
	log     zerolog.Logger
	autoPTR bool
}

func NewUpstream(opts ...Option) (*Upstream, error) {
	return NewUpstreamWithHTTP(xhttp.NewHTTPClient(), opts...)
}

func NewUpstreamWithHTTP(httpc *http.Client, opts ...Option) (*Upstream, error) {
	client := &Upstream{
		httpc: resty.NewWithClient(httpc).
			SetHeader("User-Agent", "DNSGateway").
			SetHeader("Content-Type", "application/json").
			SetRetryCount(DefaultRetries).
			SetTimeout(DefaultTimeout),
		log: log.With().
			Str("source", "agh-upstream").
			Logger(),
		parser: rules.NewParser(rulesMarkerBegin, rulesMarkerEnd),
	}

	for _, opt := range opts {
		opt(client)
	}

	if client.httpc.BaseURL == "" {
		return nil, errors.New("no upstream configured, use WithUpstream()")
	}
	return client, nil
}

func (c *Upstream) Query(ctx context.Context, r upstream.Rule) ([]upstream.Rule, error) {
	rh, err := c.fetchRules(ctx)
	if err != nil {
		return nil, err
	}

	if r.Type == dns.TypeAXFR {
		return rh.Rules(), nil
	}

	return rh.Query(r), nil
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

func (c *Upstream) fetchRules(ctx context.Context) (*rules.Storage, error) {
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

	return c.parser.Parse(rsp.Rules)
}
