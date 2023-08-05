package lrfc2136

import (
	"fmt"
	"strings"
)

type Client struct {
	Name   string
	Secret string
	Zones  []string
}

type ACL struct {
	clients map[string][]string
}

func (a *ACL) IsAllow(tsigName, fqdn string) bool {
	fqdn = "." + fqdn
	for _, zone := range a.clients[tsigName] {
		if strings.HasSuffix(fqdn, zone) {
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

func TsigACL(clients ...Client) (*ACL, error) {
	out := ACL{
		clients: make(map[string][]string, len(clients)),
	}
	for _, c := range clients {
		if _, exists := out.clients[c.Name]; exists {
			return nil, fmt.Errorf("duplicate client name: %s", c.Name)
		}

		out.clients[c.Name] = c.Zones
	}

	return &out, nil
}
