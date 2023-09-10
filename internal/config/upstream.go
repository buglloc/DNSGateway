package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/buglloc/DNSGateway/internal/upstream"
	"github.com/buglloc/DNSGateway/internal/upstream/uadguard"
	"github.com/buglloc/DNSGateway/internal/upstream/ucloudflare"
)

type UpstreamKind string

const (
	UpstreamKindNone       UpstreamKind = ""
	UpstreamKindAdGuard    UpstreamKind = "adguard"
	UpstreamKindCloudflare UpstreamKind = "cloudflare"
)

func (k *UpstreamKind) UnmarshalText(data []byte) error {
	switch strings.ToLower(string(data)) {
	case "", "none":
		*k = UpstreamKindNone
	case "adguard":
		*k = UpstreamKindAdGuard
	case "cloudflare":
		*k = UpstreamKindCloudflare
	default:
		return fmt.Errorf("invalid upstream kind: %s", string(data))
	}
	return nil
}

func (k UpstreamKind) MarshalText() ([]byte, error) {
	return []byte(k), nil
}

type AdguardUpstream struct {
	APIServerURL string `koanf:"api_server_url"`
	Login        string `koanf:"login"`
	Password     string `koanf:"password"`
	AutoPTR      bool   `koanf:"auto_ptr"`
}

type CloudflareUpstream struct {
	ZoneID string `koanf:"zone_id"`
	Token  string `koanf:"token"`
}

type Upstream struct {
	Kind       UpstreamKind       `koanf:"kind"`
	Adguard    AdguardUpstream    `koanf:"adguard"`
	Cloudflare CloudflareUpstream `koanf:"cloudflare"`
}

func (u *AdguardUpstream) Validate() error {
	if u.APIServerURL == "" {
		return errors.New("addr is empty")
	}

	return nil
}

func (u *CloudflareUpstream) Validate() error {
	if u.ZoneID == "" {
		return errors.New("zone_id is empty")
	}

	if u.Token == "" {
		return errors.New("token is empty")
	}

	return nil
}

func (r *Runtime) NewUpstream() (upstream.Upstream, error) {
	switch r.cfg.Upstream.Kind {
	case UpstreamKindAdGuard:
		return r.newAdguardUpstream(r.cfg.Upstream.Adguard)
	case UpstreamKindCloudflare:
		return r.newCloudflareUpstream(r.cfg.Upstream.Cloudflare)
	default:
		return nil, fmt.Errorf("unsupported upstream kind: %s", r.cfg.Listener.Kind)
	}
}

func (r *Runtime) newAdguardUpstream(cfg AdguardUpstream) (*uadguard.Upstream, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid adguard config: %w", err)
	}

	gw, err := uadguard.NewUpstream(
		uadguard.WithUpstream(cfg.APIServerURL),
		uadguard.WithBasicAuth(cfg.Login, cfg.Password),
		uadguard.WithAutoPTR(cfg.AutoPTR),
	)
	if err != nil {
		return nil, fmt.Errorf("create adguard upstream: %w", err)
	}

	return gw, nil
}

func (r *Runtime) newCloudflareUpstream(cfg CloudflareUpstream) (*ucloudflare.Upstream, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid cloudflare config: %w", err)
	}

	gw, err := ucloudflare.NewUpstream(cfg.Token,
		ucloudflare.WithZoneID(cfg.ZoneID),
	)
	if err != nil {
		return nil, fmt.Errorf("create cloudflare upstream: %w", err)
	}

	return gw, nil
}
