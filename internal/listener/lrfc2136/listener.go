package lrfc2136

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"

	"github.com/buglloc/DNSGateway/internal/upstream"
)

type Listener struct {
	listeners []*dns.Server
	upsc      upstream.Upstream
	clients   *Clients
	mu        sync.Mutex
	log       zerolog.Logger
}

func NewListener(cfg *Config) (*Listener, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	tsigSecrets, err := TsigSecrets(cfg.clients...)
	if err != nil {
		return nil, fmt.Errorf("parse TSIG secrets: %w", err)
	}

	tsigClients, err := TsigClients(cfg.clients...)
	if err != nil {
		return nil, fmt.Errorf("parse TSIG ACLs: %w", err)
	}

	logger := log.With().
		Str("source", "rfc2136-listener").
		Logger()

	app := &Listener{
		listeners: make([]*dns.Server, len(cfg.nets)),
		upsc:      cfg.upstream,
		clients:   tsigClients,
		log:       logger,
	}

	for i, net := range cfg.nets {
		net := net
		app.listeners[i] = &dns.Server{
			Addr:       cfg.addr,
			Net:        net,
			TsigSecret: tsigSecrets,
			NotifyStartedFunc: func() {
				logger.Info().
					Str("net", net).
					Str("addr", cfg.addr).
					Msg("started")
			},
			MsgAcceptFunc: dnsMsgAcceptFunc,
			Handler:       app,
		}
	}

	return app, nil
}

func (a *Listener) ListenAndServe() error {
	var g errgroup.Group
	for _, l := range a.listeners {
		l := l
		g.Go(func() error {
			if err := l.ListenAndServe(); err != nil {
				return fmt.Errorf("listener for net %q failed: %w", l.Net, err)
			}

			return nil
		})
	}

	return g.Wait()
}

func (a *Listener) Shutdown(ctx context.Context) error {
	var errs []error
	for _, l := range a.listeners {
		if err := l.ShutdownContext(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (a *Listener) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	l := log.Logger.With().
		Stringer("client", w.RemoteAddr()).
		Logger()

	ctx := l.WithContext(context.Background())

	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.lockedServeDNS(ctx, w, r); err != nil {
		l.Error().Err(err).Msg("request failed")

		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	}
}

func (a *Listener) lockedServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) error {
	now := time.Now()
	tsig := r.IsTsig()
	if tsig == nil {
		return errors.New("missing TSIG")
	}

	if err := w.TsigStatus(); err != nil {
		return fmt.Errorf("invalid TSIG: %w", err)
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.SetTsig(tsig.Hdr.Name, dns.HmacSHA256, 300, time.Now().Unix())
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		a.handleQuery(ctx, m, r)

	case dns.OpcodeUpdate:
		a.handleUpdates(ctx, m, r)
	}

	if err := w.WriteMsg(m); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("write failed")
		return nil
	}

	log.Ctx(ctx).Info().Dur("elapsed", time.Since(now)).Msg("finished")
	return nil
}

func (a *Listener) handleQuery(ctx context.Context, m *dns.Msg, r *dns.Msg) {
	log.Ctx(ctx).Info().Msg("handle query")
	for _, q := range r.Question {
		if !a.clients.IsQTypeAllowed(m.IsTsig().Hdr.Name, q.Qtype) {
			log.Ctx(ctx).Warn().Str("qtype", dns.TypeToString[q.Qtype]).Msg("qtype is dissallowed")
			continue
		}

		rules, err := a.upsc.Query(ctx, upstream.Rule{
			Name: q.Name,
			Type: q.Qtype,
		})
		if err != nil {
			continue
		}

		for _, rule := range rules {
			rr, err := rule.RR()
			if err != nil {
				log.Ctx(ctx).Error().Err(err).Str("name", rule.Name).Msg("unable to generate rr")
				continue
			}

			m.Answer = append(m.Answer, rr)
		}
	}
}

func (a *Listener) handleUpdates(ctx context.Context, m *dns.Msg, r *dns.Msg) {
	log.Ctx(ctx).Info().Msg("handle updates")

	tx, err := a.upsc.Tx(ctx)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("create tx")
		return
	}

	shouldAutoDelete := a.clients.ShouldAutoDelete(m.IsTsig().Hdr.Name)
	handleUpdate := func(rr dns.RR) error {
		header := rr.Header()
		name := header.Name
		l := log.Ctx(ctx).With().Str("name", name).Logger()

		if _, ok := dns.IsDomainName(name); !ok {
			return errors.New("invalid domain name")
		}

		if !a.clients.IsNameAllowed(m.IsTsig().Hdr.Name, name) {
			return fmt.Errorf("%q is not allowed for client %q", name, m.IsTsig().Hdr.Name)
		}

		if header.Class == dns.ClassANY && header.Rdlength == 0 {
			err := tx.Delete(upstream.Rule{
				Name: name,
				Type: header.Rrtype,
			})
			if err != nil {
				return fmt.Errorf("delete: %w", err)
			}
			l.Info().Str("name", name).Msg("deleted")
			return nil
		}

		rule, err := upstream.RuleFromRR(rr)
		if err != nil {
			return fmt.Errorf("parse RR: %w", err)
		}

		if shouldAutoDelete {
			_ = tx.Delete(upstream.Rule{
				Name: rule.Name,
				Type: rule.Type,
			})
		}

		if err := tx.Append(rule); err != nil {
			return fmt.Errorf("update: %w", err)
		}

		l.Info().Any("rr", rr).Msg("updated")
		return nil
	}

	if len(r.Question) > 0 {
		a.handleQuery(ctx, m, r)
	}

	for _, rr := range r.Ns {
		if err := handleUpdate(rr); err != nil {
			log.Error().Err(err).Any("rr", rr).Msg("update failed")
		}
	}

	if err := tx.Commit(context.Background()); err != nil {
		log.Error().Err(err).Msg("commit failed")
	}
}

func dnsMsgAcceptFunc(dh dns.Header) dns.MsgAcceptAction {
	const qrBits = 1 << 15 // query/response (response=1)
	if isResponse := dh.Bits&qrBits != 0; isResponse {
		return dns.MsgIgnore
	}

	// Don't allow dynamic updates, because then the sections can contain a whole bunch of RRs.
	opcode := int(dh.Bits>>11) & 0xF
	switch opcode {
	case dns.OpcodeQuery:
	case dns.OpcodeNotify:
	case dns.OpcodeUpdate:
	default:
		return dns.MsgRejectNotImplemented
	}

	if dh.Qdcount != 1 {
		return dns.MsgReject
	}
	// NOTIFY requests can have a SOA in the ANSWER section. See RFC 1996 Section 3.7 and 3.11.
	if dh.Ancount > 1 {
		return dns.MsgReject
	}

	if dh.Arcount > 2 {
		return dns.MsgReject
	}
	return dns.MsgAccept
}
