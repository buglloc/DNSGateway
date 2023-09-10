package middlewares

import (
	"context"
	"errors"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"

	"github.com/buglloc/DNSGateway/internal/listener/lrfc2136/dnserr"
)

type RawHandleFn func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) error

type MsgHandleFn func(ctx context.Context, m *dns.Msg, r *dns.Msg) error

func RawResponder(fn RawHandleFn) NextFn {
	return func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		err := fn(ctx, w, r)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("request failed")
		}
	}
}

func MsgResponder(fn MsgHandleFn) NextFn {
	return func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeSuccess)
		m.Authoritative = true

		if tsig := r.IsTsig(); tsig != nil {
			m.SetTsig(tsig.Hdr.Name, dns.HmacSHA256, 300, time.Now().Unix())
		}

		err := fn(ctx, m, r)
		if err == nil {
			if err := w.WriteMsg(m); err != nil {
				log.Ctx(ctx).Error().Err(err).Msg("write failed")
			}
			return
		}

		log.Ctx(ctx).Error().Err(err).Msg("request failed")
		var dnsErr *dnserr.DNSError
		if errors.As(err, &dnsErr) {
			WriteError(ctx, w, r, dnsErr.RCode)
			return
		}

		WriteError(ctx, w, r, dns.RcodeServerFailure)
	}
}

func WriteError(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, rcode int) {
	if rcode == 0 {
		rcode = dns.RcodeServerFailure
	}

	m := new(dns.Msg)
	m.SetRcode(r, rcode)
	if tsig := r.IsTsig(); tsig != nil {
		m.SetTsig(tsig.Hdr.Name, dns.HmacSHA256, 300, time.Now().Unix())
	}

	if err := w.WriteMsg(m); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("write failed")
	}
}
