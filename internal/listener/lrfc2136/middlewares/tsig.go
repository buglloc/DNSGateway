package middlewares

import (
	"context"

	"github.com/miekg/dns"
)

func TSIGChecker(next NextFn) NextFn {
	return func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		tsig := r.IsTsig()
		if tsig == nil {
			WriteResponse(ctx, w, r, dns.RcodeRefused)
			return
		}

		if err := w.TsigStatus(); err != nil {
			WriteResponse(ctx, w, r, dns.RcodeRefused)
			return
		}

		next(ctx, w, r)
	}
}
