package middlewares

import (
	"context"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

func Logger(next NextFn) NextFn {
	return func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		now := time.Now()
		next(ctx, w, r)
		log.Ctx(ctx).Info().Dur("elapsed", time.Since(now)).Msg("finished")
	}
}
