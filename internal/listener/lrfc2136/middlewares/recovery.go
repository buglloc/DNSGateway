package middlewares

import (
	"context"

	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

func Recoverer(next NextFn) NextFn {
	return func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		defer func() {
			if rvr := recover(); rvr != nil {
				log.Ctx(ctx).Panic().Any("error", rvr).Msg("panic occurred")

				WriteResponse(ctx, w, r, dns.RcodeServerFailure)
			}
		}()

		next(ctx, w, r)
	}
}
