package rules

import "github.com/buglloc/DNSGateway/internal/upstream"

type StoreKay struct {
	Name string
	Type upstream.RType
}

type Storage struct {
	before []string
	after  []string
	rules  map[StoreKay]Rule
}
