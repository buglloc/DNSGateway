package lrfc2136

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/buglloc/DNSGateway/internal/fqdn"
	"github.com/buglloc/DNSGateway/internal/listener/lrfc2136/dnserr"
)

type Client struct {
	Name       string
	Secret     string
	XFRAllowed bool
	AutoDelete bool
	Zones      []string
	Types      TypesSet
}

type TypesSet map[uint16]struct{}

type Clients struct {
	clients map[string]*Client
}

func (a *Clients) Client(r *dns.Msg) (*Client, error) {
	tsig := r.IsTsig()
	if tsig == nil {
		return nil, errors.New("no TSIG provided")
	}

	cl, ok := a.clients[tsig.Hdr.Name]
	if !ok {
		return nil, fmt.Errorf("unknown client: %s", tsig.Hdr.Name)
	}

	return cl, nil
}

func (c *Client) IsXFRAllowed() bool {
	return c.XFRAllowed
}

func (c *Client) ShouldAutoDelete() bool {
	return c.AutoDelete
}

func (c *Client) Zone(name string) string {
	name = "." + name
	for _, zone := range c.Zones {
		if strings.HasSuffix(name, zone) {
			return zone
		}
	}

	return ""
}

func (c *Client) IsNameAllowed(name string) bool {
	return c.Zone(name) != ""
}

func (c *Client) IsTypeAllowed(rrType uint16) bool {
	rrTypes := c.Types
	if len(rrTypes) == 0 {
		return true
	}

	_, ok := rrTypes[rrType]
	return ok
}

func (c *Client) SOA(name string) (*dns.SOA, error) {
	zone := c.Zone(name)
	if zone == "" {
		return nil, dnserr.NewDNSError(
			dns.RcodeNameError,
			fmt.Errorf("no zone for %q name was found", name),
		)
	}

	const ttl = 60
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   fqdn.FQDN(zone),
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		Ns:      "dns.cloudflare.com.",
		Mbox:    fqdn.FQDN("admin." + zone),
		Serial:  uint32(time.Now().Unix() % math.MaxUint32),
		Refresh: ttl,
		Retry:   ttl,
		Expire:  ttl,
	}, nil
}

func TsigSecrets(clients ...Client) (map[string]string, error) {
	out := make(map[string]string, len(clients))
	for _, c := range clients {
		if _, exists := out[c.Name]; exists {
			return nil, fmt.Errorf("duplicate client name: %s", c.Name)
		}

		out[c.Name] = c.Secret
	}

	return out, nil
}

func TsigClients(clients ...Client) (*Clients, error) {
	out := Clients{
		clients: make(map[string]*Client, len(clients)),
	}
	for _, c := range clients {
		if _, exists := out.clients[c.Name]; exists {
			return nil, fmt.Errorf("duplicate client name: %s", c.Name)
		}

		out.clients[c.Name] = &c
	}

	return &out, nil
}

func ParseTypesSet(in []string) (map[uint16]struct{}, error) {
	out := make(map[uint16]struct{}, len(in))
	for _, name := range in {
		rrType, ok := dns.StringToType[strings.ToUpper(name)]
		if !ok {
			return nil, fmt.Errorf("unknown record type: %s", name)
		}

		out[rrType] = struct{}{}
	}

	return out, nil
}
