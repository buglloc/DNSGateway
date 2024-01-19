package ucloudflare

import (
	"context"
	"fmt"

	"github.com/cloudflare/cloudflare-go"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/buglloc/DNSGateway/internal/upstream"
	"github.com/buglloc/DNSGateway/internal/xhttp"
)

var _ upstream.Upstream = (*Upstream)(nil)

const defaultTTL = 900

type Upstream struct {
	cfc    *cloudflare.API
	zoneID string
	log    zerolog.Logger
}

func NewUpstream(token string, opts ...Option) (*Upstream, error) {
	httpc := xhttp.NewHTTPClient()
	cfc, err := cloudflare.NewWithAPIToken(token, cloudflare.HTTPClient(httpc))
	if err != nil {
		return nil, fmt.Errorf("create cloudflare client: %w", err)
	}

	return NewUpstreamWithCFC(cfc, opts...)
}

func NewUpstreamWithCFC(cfc *cloudflare.API, opts ...Option) (*Upstream, error) {
	client := &Upstream{
		cfc: cfc,
		log: log.With().
			Str("source", "cloudflare-upstream").
			Logger(),
	}

	for _, opt := range opts {
		opt(client)
	}

	return client, nil
}

func (c *Upstream) Query(ctx context.Context, r upstream.Rule) ([]upstream.Rule, error) {
	rh, err := c.fetchRules(ctx)
	if err != nil {
		return nil, err
	}

	return rh.Query(r), nil
}

func (c *Upstream) Tx(ctx context.Context) (upstream.Tx, error) {
	rh, err := c.fetchRules(ctx)
	if err != nil {
		return nil, err
	}

	return &Tx{
		cfc:    c.cfc,
		zoneID: c.zoneID,
		log:    c.log,
		store:  rh,
	}, nil
}

func (c *Upstream) fetchRules(ctx context.Context) (*Storage, error) {
	records, _, err := c.cfc.ListDNSRecords(
		ctx,
		cloudflare.ZoneIdentifier(c.zoneID),
		cloudflare.ListDNSRecordsParams{},
	)
	if err != nil {
		return nil, fmt.Errorf("fetch store: %w", err)
	}

	return NewCFStorage(records)
}
