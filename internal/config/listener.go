package config

import (
	"errors"
	"fmt"
	"strings"

	_ "github.com/knadh/koanf/v2"

	"github.com/buglloc/DNSGateway/internal/listener"
	"github.com/buglloc/DNSGateway/internal/listener/lrfc2136"
	"github.com/buglloc/DNSGateway/internal/upstream"
)

type ListenerKind string

const (
	ListenerKindNone    ListenerKind = ""
	ListenerKindRFC2136 ListenerKind = "rfc2136"
)

func (k *ListenerKind) UnmarshalText(data []byte) error {
	switch strings.ToLower(string(data)) {
	case "", "none":
		*k = ListenerKindNone
	case "rfc2136":
		*k = ListenerKindRFC2136
	default:
		return fmt.Errorf("invalid listener kind: %s", string(data))
	}
	return nil
}

func (k ListenerKind) MarshalText() ([]byte, error) {
	return []byte(k), nil
}

type Client struct {
	Name   string   `koanf:"name"`
	Secret string   `koanf:"secret"`
	Zones  []string `koanf:"zones"`
}

type RFC2136Listener struct {
	Addr    string   `koanf:"addr"`
	Nets    []string `koanf:"nets"`
	Clients []Client `koanf:"clients"`
}

type Listener struct {
	Kind    ListenerKind    `koanf:"kind"`
	RFC2136 RFC2136Listener `koanf:"rfc2136"`
}

func (l *RFC2136Listener) Validate() error {
	if l.Addr == "" {
		return errors.New("addr is empty")
	}

	names := make(map[string]struct{})
	for _, cl := range l.Clients {
		_, exists := names[cl.Name]
		if exists {
			return fmt.Errorf("duplicate client name: %s", cl.Name)
		}
		names[cl.Name] = struct{}{}

		if len(cl.Secret) < 32 {
			return fmt.Errorf("invalid client %q secret: too short: 32 chars min", cl.Name)
		}
	}
	return nil
}

func (r *Runtime) NewListener() (listener.Listener, error) {
	u, err := r.NewUpstream()
	if err != nil {
		return nil, fmt.Errorf("unable to create upstream for listener: %w", err)
	}

	switch r.cfg.Listener.Kind {
	case ListenerKindRFC2136:
		return r.newRFC2136Listener(u, r.cfg.Listener.RFC2136)
	default:
		return nil, fmt.Errorf("unsupported listener kind: %s", r.cfg.Listener.Kind)
	}
}

func (r *Runtime) newRFC2136Listener(u upstream.Upstream, cfg RFC2136Listener) (*lrfc2136.Listener, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid rfc2136 config: %w", err)
	}

	lCfg := lrfc2136.NewConfig().
		Addr(cfg.Addr).
		Upstream(u)

	for _, cl := range cfg.Clients {
		lCfg.AppendClient(lrfc2136.Client{
			Name:   cl.Name,
			Secret: cl.Secret,
			Zones:  cl.Zones,
		})
	}

	gw, err := lrfc2136.NewListener(lCfg)
	if err != nil {
		return nil, fmt.Errorf("create rfc2136 listener: %w", err)
	}

	return gw, nil
}
