package middlewares

import (
	"context"

	"github.com/miekg/dns"
)

type NextFn func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg)
