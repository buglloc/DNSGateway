package lrfc2136

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

type Client struct {
	Name        string
	Secret      string
	AxfrAllowed bool
	AutoDelete  bool
	Zones       []string
}

type Clients struct {
	clients map[string]Client
}

func (a *Clients) ShouldAutoDelete(clientName string) bool {
	return a.clients[clientName].AutoDelete
}

func (a *Clients) IsQTypeAllowed(clientName string, qtype uint16) bool {
	switch qtype {
	case dns.TypeAXFR:
		return a.clients[clientName].AxfrAllowed
	}

	return true
}

func (a *Clients) IsNameAllowed(clientName, name string) bool {
	name = "." + name
	for _, zone := range a.clients[clientName].Zones {
		if strings.HasSuffix(name, zone) {
			return true
		}
	}

	return false
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
		clients: make(map[string]Client, len(clients)),
	}
	for _, c := range clients {
		if _, exists := out.clients[c.Name]; exists {
			return nil, fmt.Errorf("duplicate client name: %s", c.Name)
		}

		out.clients[c.Name] = c
	}

	return &out, nil
}
