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

	"github.com/buglloc/DNSGateway/internal/upstream"
)

type Listener struct {
	dns  *dns.Server
	upsc upstream.Upstream
	acl  *ACL
	mu   sync.Mutex
	log  zerolog.Logger
}

func NewListener(addr string, upsc upstream.Upstream, clients ...Client) (*Listener, error) {
	tsigSecrets, err := TsigSecrets(clients...)
	if err != nil {
		return nil, fmt.Errorf("parse TSIG secrets: %w", err)
	}

	tsigACL, err := TsigACL(clients...)
	if err != nil {
		return nil, fmt.Errorf("parse TSIG ACLs: %w", err)
	}

	logger := log.With().
		Str("source", "rfc2136-listener").
		Logger()

	app := &Listener{
		dns: &dns.Server{
			Addr:       addr,
			Net:        "udp",
			TsigSecret: tsigSecrets,
			NotifyStartedFunc: func() {
				logger.Info().
					Str("addr", addr).
					Msg("started")
			},
			MsgAcceptFunc: dnsMsgAcceptFunc,
		},
		upsc: upsc,
		acl:  tsigACL,
		log:  logger,
	}

	app.dns.Handler = app
	return app, nil
}

func (a *Listener) ListenAndServe() error {
	return a.dns.ListenAndServe()
}

func (a *Listener) Shutdown(ctx context.Context) error {
	return a.dns.ShutdownContext(ctx)
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
		a.handleQuery(ctx, m)

	case dns.OpcodeUpdate:
		for _, rr := range r.Ns {
			a.handleUpdate(ctx, m, rr)
		}
	}

	if err := w.WriteMsg(m); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("write failed")
		return nil
	}

	log.Ctx(ctx).Info().Dur("elapsed", time.Since(now)).Msg("finished")
	return nil
}

func (a *Listener) handleQuery(ctx context.Context, m *dns.Msg) {
	log.Ctx(ctx).Info().Msg("handle query")
	for _, q := range m.Question {
		rule, err := a.upsc.Query(ctx, q.Name, q.Qtype)
		if err != nil {
			continue
		}

		rr, err := rule.RR()
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Str("name", rule.Name).Msg("unable to generate rr")
			continue
		}

		m.Answer = append(m.Answer, rr)
	}
}

func (a *Listener) handleUpdate(ctx context.Context, m *dns.Msg, r dns.RR) {
	header := r.Header()
	name := header.Name
	l := log.Ctx(ctx).With().Str("name", name).Logger()

	if _, ok := dns.IsDomainName(name); !ok {
		l.Warn().Msg("skip non-domain name")
		return
	}

	if !a.acl.IsAllow(m.IsTsig().Hdr.Name, name) {
		l.Warn().Str("client", m.IsTsig().Hdr.Name).Msg("skip not allowed domain name")
		return
	}

	if header.Class == dns.ClassANY && header.Rdlength == 0 {
		fmt.Println("delete", name, "!!!!!!!!!")
		//if err := deleteRecord(name, rtype); err != nil {
		//	l.Error().Err(err).Msg("unable to delete record")
		//} else {
		//	l.Info().Msg("deleted")
		//}
		return
	}

	switch rr := r.(type) {
	case *dns.A:
		fmt.Println("A", rr)
	case *dns.AAAA:
		fmt.Println("AAAA", rr)
	case *dns.CNAME:
		fmt.Println("CNAME", rr)
	case *dns.TXT:
		fmt.Println("TXT", rr)
	default:
		l.Warn().Type("type", r).Msg("ignore unsupported request")
	}
	//
	//if a, ok := r.(*dns.A); ok {
	//	rrr, err := getRecord(name, rtype)
	//	if err == nil {
	//		rr = rrr.(*dns.A)
	//	} else {
	//		rr = new(dns.A)
	//	}
	//
	//	ip = a.A
	//	rr.(*dns.A).Hdr = rheader
	//	rr.(*dns.A).A = ip
	//} else if a, ok := r.(*dns.AAAA); ok {
	//	rrr, err := getRecord(name, rtype)
	//	if err == nil {
	//		rr = rrr.(*dns.AAAA)
	//	} else {
	//		rr = new(dns.AAAA)
	//	}
	//
	//	ip = a.AAAA
	//	rr.(*dns.AAAA).Hdr = rheader
	//	rr.(*dns.AAAA).AAAA = ip
	//}
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
