package middlewares

import (
	"context"

	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

func TSIGChecker(next NextFn) NextFn {
	return func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		writeRefuse := func() {
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeRefused)

			if err := w.WriteMsg(m); err != nil {
				log.Ctx(ctx).Error().Err(err).Msg("write failed")
			}
		}

		tsig := r.IsTsig()
		if tsig == nil {
			writeRefuse()
			return
		}

		if err := w.TsigStatus(); err != nil {
			writeRefuse()
			return
		}

		next(ctx, w, r)
	}
}
