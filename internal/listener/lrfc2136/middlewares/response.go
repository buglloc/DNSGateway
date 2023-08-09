package middlewares

import (
	"context"
	"errors"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"

	"github.com/buglloc/DNSGateway/internal/listener/lrfc2136/dnserr"
)

type HandleFn func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) error

func NopResponser(fn HandleFn) NextFn {
	return func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		err := fn(ctx, w, r)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("request failed")
		}
	}
}

func Responser(fn HandleFn) NextFn {
	return func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		err := fn(ctx, w, r)
		if err == nil {
			WriteResponse(ctx, w, r, dns.RcodeSuccess)
			return
		}

		log.Ctx(ctx).Error().Err(err).Msg("request failed")
		var dnsErr *dnserr.DNSError
		if errors.As(err, &dnsErr) {
			WriteResponse(ctx, w, r, dnsErr.RCode)
			return
		}

		WriteResponse(ctx, w, r, dns.RcodeServerFailure)
	}
}

func WriteResponse(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, rcode int) {
	m := new(dns.Msg)
	m.SetRcode(r, rcode)

	if tsig := r.IsTsig(); tsig != nil {
		m.SetTsig(tsig.Hdr.Name, dns.HmacSHA256, 300, time.Now().Unix())
	}

	if err := w.WriteMsg(m); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("write failed")
	}
}
