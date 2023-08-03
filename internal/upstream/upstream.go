package upstream

import (
	"context"
	"github.com/miekg/dns"
)

type Upstream interface {
	Tx(ctx context.Context) (Tx, error)
	Query(ctx context.Context, q dns.Question) (dns.RR, error)
}

type Tx interface {
	Delete(r dns.RR) error
	Update(r dns.RR) error
	Commit(ctx context.Context) error
}

type RValue any

type RType = uint16

type Rule struct {
	Name  string
	Type  RType
	Value RValue
}
