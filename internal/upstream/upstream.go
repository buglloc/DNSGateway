package upstream

import (
	"context"
)

type Upstream interface {
	Tx(ctx context.Context) (Tx, error)
	Query(ctx context.Context, q Rule) ([]Rule, error)
}

type Tx interface {
	Delete(r Rule) error
	Append(r Rule) error
	Commit(ctx context.Context) error
	Close()
}
