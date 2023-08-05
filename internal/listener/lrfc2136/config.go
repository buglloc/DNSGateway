package lrfc2136

import (
	"errors"

	"github.com/buglloc/DNSGateway/internal/upstream"
)

type Config struct {
	addr     string
	nets     []string
	upstream upstream.Upstream
	clients  []Client
}

func NewConfig() *Config {
	return &Config{
		addr: ":53",
		nets: []string{
			"tcp",
			"udp",
		},
	}
}

func (c *Config) Addr(addr string) *Config {
	c.addr = addr
	return c
}

func (c *Config) Nets(nets ...string) *Config {
	c.nets = nets
	return c
}

func (c *Config) Upstream(upstream upstream.Upstream) *Config {
	c.upstream = upstream
	return c
}

func (c *Config) Clients(clients ...Client) *Config {
	c.clients = clients
	return c
}

func (c *Config) AppendClient(client Client) *Config {
	c.clients = append(c.clients, client)
	return c
}

func (c *Config) Validate() error {
	var errs []error
	if c.addr == "" {
		errs = append(errs, errors.New(".Addr is required"))
	}

	if len(c.nets) == 0 {
		errs = append(errs, errors.New(".Nets is required"))
	}

	if c.upstream == nil {
		errs = append(errs, errors.New(".Upstream is required"))
	}

	if len(c.clients) == 0 {
		errs = append(errs, errors.New(".Clients is required"))
	}

	return errors.Join(errs...)
}
