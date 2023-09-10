package lrfc2136

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"

	"github.com/buglloc/DNSGateway/internal/listener/lrfc2136/dnserr"
	"github.com/buglloc/DNSGateway/internal/listener/lrfc2136/middlewares"
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
		m.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
	}
}

func (a *Listener) lockedServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) error {
	var handler middlewares.NextFn

	switch r.Opcode {
	case dns.OpcodeQuery:
		if isXRFRequest(r) {
			handler = middlewares.RawResponder(a.handleXFRTransfer)
			break
		}

		handler = middlewares.MsgResponder(a.handleQuery)

	case dns.OpcodeUpdate:
		handler = middlewares.MsgResponder(a.handleUpdates)

	default:
		handler = middlewares.MsgResponder(func(_ context.Context, _ *dns.Msg, _ *dns.Msg) error {
			return fmt.Errorf("unsupported opcode: %s", dns.OpcodeToString[r.Opcode])
		})
	}

	middlewares.Logger(
		middlewares.Recoverer(
			middlewares.TSIGChecker(
				handler,
			),
		),
	)(ctx, w, r)

	return nil
}

func (a *Listener) handleXFRTransfer(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) error {
	log.Ctx(ctx).Info().Msg("handle XFR transfer")
	client, err := a.clients.Client(r)
	if err != nil {
		return err
	}

	if client.IsXFRAllowed() {
		return fmt.Errorf("XFR is not allowed for client %q", r.IsTsig().Hdr.Name)
	}

	if !isXRFRequest(r) {
		return errors.New("invalid XFR request")
	}

	ch := make(chan *dns.Envelope)
	tr := new(dns.Transfer)
	done := make(chan struct{})
	go func() {
		defer close(done)

		if err := tr.Out(w, r, ch); err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("unable to write transfer")
		}
	}()

	a.handleXFRQuestion(ctx, client, r.Question[0], ch)
	close(ch)

	<-done
	_ = w.Close()
	return nil
}

func (a *Listener) handleXFRQuestion(ctx context.Context, client *Client, q dns.Question, out chan *dns.Envelope) {
	log.Ctx(ctx).Info().Str("name", q.Name).Msg("handle XFR request")

	rules, err := a.upsc.Query(ctx, upstream.Rule{
		Name: dns.Fqdn(q.Name),
		Type: q.Qtype,
	})
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("unable to get rules from upstream")
		out <- &dns.Envelope{
			Error: err,
		}
		return
	}

	soa, err := client.SOA(q.Name)
	if err != nil {
		log.Ctx(ctx).Error().Str("name", q.Name).Err(err).Msg("unable to get SOA")
		out <- &dns.Envelope{
			Error: err,
		}
		return
	}

	xfrMarker := &dns.Envelope{
		RR: []dns.RR{soa},
	}

	out <- xfrMarker
	defer func() { out <- xfrMarker }()

	const chunkSize = 64
	for i := 0; i < len(rules); i += chunkSize {
		end := i + chunkSize

		if end > len(rules) {
			end = len(rules)
		}

		rrs := make([]dns.RR, 0, chunkSize)
		for _, rule := range rules[i:end] {
			rr, err := rule.RR()
			if err != nil {
				log.Ctx(ctx).Error().Err(err).Str("name", rule.Name).Msg("unable to generate rr")
				continue
			}

			rrs = append(rrs, rr)
		}

		out <- &dns.Envelope{
			RR: rrs,
		}
	}
}

func (a *Listener) handleQuery(ctx context.Context, m *dns.Msg, r *dns.Msg) error {
	log.Ctx(ctx).Info().Msg("handle query")
	client, err := a.clients.Client(r)
	if err != nil {
		return err
	}

	for _, q := range r.Question {
		name := dns.Fqdn(q.Name)

		switch {
		case isXRFQuestion(q):
			log.Ctx(ctx).Warn().Msg("ignored unexpected XFR request")
			continue
		case isSOAQuestion(q):
			soa, err := client.SOA(q.Name)
			if err != nil {
				return err
			}

			if soa.Hdr.Name != q.Name {
				return dnserr.NewDNSError(
					dns.RcodeServerFailure,
					fmt.Errorf("%q is not a zone", q.Name),
				)
			}

			m.Answer = append(m.Answer, soa)
			continue
		}

		rules, err := a.upsc.Query(ctx, upstream.Rule{
			Name: name,
			Type: q.Qtype,
		})
		if err != nil {
			return dnserr.NewDNSError(
				dns.RcodeServerFailure,
				fmt.Errorf("unable to get rules from upstream for %q: %w", q.Name, err),
			)
		}

		if len(rules) == 0 {
			return dnserr.NewDNSError(
				dns.RcodeNameError,
				fmt.Errorf("no reqords for %q was found", q.Name),
			)
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
	return nil
}

func (a *Listener) handleUpdates(ctx context.Context, _ *dns.Msg, r *dns.Msg) error {
	log.Ctx(ctx).Info().Msg("handle updates")
	client, err := a.clients.Client(r)
	if err != nil {
		return err
	}

	tx, err := a.upsc.Tx(ctx)
	if err != nil {
		return dnserr.NewDNSError(
			dns.RcodeServerFailure,
			fmt.Errorf("create upstream tx: %w", err),
		)
	}

	handleUpdate := func(rr dns.RR) error {
		header := rr.Header()
		name := dns.Fqdn(header.Name)
		l := log.Ctx(ctx).With().Str("name", name).Logger()

		if _, ok := dns.IsDomainName(name); !ok {
			return errors.New("invalid domain name")
		}

		if !client.IsNameAllowed(name) {
			return fmt.Errorf(
				"%q is not allowed for client %q",
				name, client.Name,
			)
		}

		if header.Rrtype != dns.TypeNone && !client.IsTypeAllowed(header.Rrtype) {
			return fmt.Errorf(
				"%q record type is not allowed for client %q",
				dns.TypeToString[header.Rrtype], client.Name,
			)
		}

		switch {
		case header.Class == dns.ClassANY && header.Rdlength == 0:
			// "2.5.2 - Delete An RRset" or "Delete All RRsets From A Name"
			err := tx.Delete(upstream.Rule{
				Name: name,
				Type: header.Rrtype,
			})
			if err != nil {
				return fmt.Errorf("delete: %w", err)
			}
			l.Info().
				Str("type", upstream.TypeString(header.Rrtype)).
				Str("name", name).
				Msg("deleted")
			return nil
		case header.Class == dns.ClassNONE:
			// "2.5.4 - Delete An RR From An RRset"
			rule, err := upstream.RuleFromRR(rr)
			if err != nil {
				return fmt.Errorf("parse RR: %w", err)
			}

			if err := tx.Delete(rule); err != nil {
				return fmt.Errorf("delete: %w", err)
			}
			l.Info().
				Str("type", upstream.TypeString(header.Rrtype)).
				Str("name", name).
				Msg("deleted")
			return nil
		}

		rule, err := upstream.RuleFromRR(rr)
		if err != nil {
			return fmt.Errorf("parse RR: %w", err)
		}
		if client.ShouldAutoDelete() {
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

	for _, rr := range r.Ns {
		if err := handleUpdate(rr); err != nil {
			return dnserr.NewDNSError(dns.RcodeRefused, err)
		}
	}

	if err := tx.Commit(context.Background()); err != nil {
		return dnserr.NewDNSError(
			dns.RcodeServerFailure,
			fmt.Errorf("upstream tx commit: %w", err),
		)
	}

	return nil
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

func isXRFRequest(r *dns.Msg) bool {
	return len(r.Question) == 1 && isXRFQuestion(r.Question[0])
}

func isXRFQuestion(q dns.Question) bool {
	return q.Qtype == dns.TypeAXFR || q.Qtype == dns.TypeIXFR
}

func isSOAQuestion(q dns.Question) bool {
	return q.Qtype == dns.TypeSOA
}
