package server

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/cache"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/dnssec"
	"github.com/powersvx/powersvx/internal/resolver"
)

// Server is the DNS request pipeline.
type Server struct {
	cfg      *config.Config
	cache    *cache.Tier
	res      *resolver.Resolver
	auth     *authoritative.Store
	dnssec   *dnssec.Validator
	tlsCfg   *tls.Config
	log      *slog.Logger
	udp      *dns.Server
	tcp      *dns.Server
	dot      *dns.Server
	dohHTTP  *http.Server
	queries  atomic.Uint64
	started  time.Time
	dotOn    bool
	dohOn    bool
}

func New(cfg *config.Config, tier *cache.Tier, res *resolver.Resolver, auth *authoritative.Store, sec *dnssec.Validator, tlsCfg *tls.Config, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		cfg:    cfg,
		cache:  tier,
		res:    res,
		auth:   auth,
		dnssec: sec,
		tlsCfg: tlsCfg,
		log:    log,
		started: time.Now(),
	}
}

func (s *Server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	start := time.Now()
	s.queries.Add(1)

	if len(req.Question) == 0 {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeFormatError)
		_ = w.WriteMsg(m)
		return
	}

	q := req.Question[0]
	qname := config.NormalizeName(q.Name)
	qtype := q.Qtype

	// L1/L2 cache hit — rewrite message ID and send pre-encoded wire.
	if entry, ok := s.cache.Get(qname, qtype); ok {
		wire := resolver.RewriteID(entry.Wire, req.Id)
		_, _ = w.Write(wire)
		s.log.Debug("cache hit", "name", qname, "type", dns.TypeToString[qtype], "ms", time.Since(start).Milliseconds())
		return
	}

	// Authoritative in-memory lookup
	if s.auth != nil {
		if rrs, inZone := s.auth.Lookup(qname, qtype); inZone {
			m := new(dns.Msg)
			m.SetReply(req)
			m.Authoritative = true
			m.RecursionAvailable = true
			if len(rrs) == 0 {
				m.Rcode = dns.RcodeNameError
			} else {
				m.Answer = rrs
			}
			s.storeAndWrite(w, req, m)
			return
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.res.Timeout)
	defer cancel()

	resp, err := s.res.Resolve(ctx, req)
	if err != nil {
		s.log.Warn("resolve failed", "name", qname, "err", err)
		m := new(dns.Msg)
		m.SetReply(req)
		m.RecursionAvailable = true
		m.Rcode = dns.RcodeServerFailure
		_ = w.WriteMsg(m)
		return
	}

	resp.Id = req.Id
	resp.RecursionAvailable = true
	resp.Compress = true

	if s.dnssec != nil && s.dnssec.Enabled() {
		if servfail, res := s.dnssec.Apply(resp); servfail {
			s.log.Warn("dnssec bogus", "name", qname, "reason", res.Reason)
			m := new(dns.Msg)
			m.SetReply(req)
			m.RecursionAvailable = true
			m.Rcode = dns.RcodeServerFailure
			_ = w.WriteMsg(m)
			return
		}
	}

	s.storeAndWrite(w, req, resp)
	s.log.Debug("resolved", "name", qname, "type", dns.TypeToString[qtype], "rcode", resp.Rcode, "ad", resp.AuthenticatedData, "ms", time.Since(start).Milliseconds())
}

func (s *Server) storeAndWrite(w dns.ResponseWriter, req, resp *dns.Msg) {
	wire, err := resolver.PackResponse(resp)
	if err != nil {
		_ = w.WriteMsg(resp)
		return
	}
	ttl := resolver.MinTTL(resp)
	s.cache.Set(config.NormalizeName(req.Question[0].Name), req.Question[0].Qtype, wire, resp.Rcode, ttl)
	_, _ = w.Write(wire)
}

func (s *Server) ListenAndServe() error {
	handler := dns.HandlerFunc(s.ServeDNS)
	udpAddr := s.cfg.ListenAddr(s.cfg.Server.UDPPort)
	tcpAddr := s.cfg.ListenAddr(s.cfg.Server.TCPPort)

	s.udp = &dns.Server{Addr: udpAddr, Net: "udp", Handler: handler, UDPSize: 1232}
	s.tcp = &dns.Server{Addr: tcpAddr, Net: "tcp", Handler: handler}

	errCh := make(chan error, 4)

	go func() {
		s.log.Info("UDP listener starting", "addr", udpAddr)
		errCh <- s.udp.ListenAndServe()
	}()
	go func() {
		s.log.Info("TCP listener starting", "addr", tcpAddr)
		errCh <- s.tcp.ListenAndServe()
	}()

	if s.tlsCfg != nil && s.cfg.Server.DoTPort > 0 {
		dotAddr := s.cfg.ListenAddr(s.cfg.Server.DoTPort)
		dotTLS := s.tlsCfg.Clone()
		dotTLS.NextProtos = []string{"dot"}
		s.dot = &dns.Server{
			Addr:      dotAddr,
			Net:       "tcp-tls",
			Handler:   handler,
			TLSConfig: dotTLS,
		}
		s.dotOn = true
		go func() {
			s.log.Info("DoT listener starting", "addr", dotAddr)
			errCh <- s.dot.ListenAndServe()
		}()
	}

	if s.tlsCfg != nil && s.cfg.Server.DoHPort > 0 {
		dohAddr := s.cfg.ListenAddr(s.cfg.Server.DoHPort)
		if err := s.startDoH(dohAddr); err != nil {
			return err
		}
		s.dohOn = true
		go func() {
			s.log.Info("DoH listener starting", "addr", dohAddr)
			errCh <- s.dohHTTP.ListenAndServeTLS("", "")
		}()
	}

	return <-errCh
}

func (s *Server) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var err error
	if s.udp != nil {
		err = s.udp.ShutdownContext(ctx)
	}
	if s.tcp != nil {
		if e := s.tcp.ShutdownContext(ctx); e != nil && err == nil {
			err = e
		}
	}
	if s.dot != nil {
		if e := s.dot.ShutdownContext(ctx); e != nil && err == nil {
			err = e
		}
	}
	if s.dohHTTP != nil {
		if e := s.dohHTTP.Shutdown(ctx); e != nil && err == nil {
			err = e
		}
	}
	return err
}

func (s *Server) Stats() (queries uint64, uptime time.Duration) {
	return s.queries.Load(), time.Since(s.started)
}

func (s *Server) UDPAddr() string {
	return s.cfg.ListenAddr(s.cfg.Server.UDPPort)
}

func (s *Server) DoTAddr() string {
	if !s.dotOn {
		return ""
	}
	return s.cfg.ListenAddr(s.cfg.Server.DoTPort)
}

func (s *Server) DoHAddr() string {
	if !s.dohOn {
		return ""
	}
	return s.cfg.ListenAddr(s.cfg.Server.DoHPort)
}

func (s *Server) DoTEnabled() bool { return s.dotOn }
func (s *Server) DoHEnabled() bool { return s.dohOn }

func (s *Server) DNSSECMode() string {
	if s.dnssec == nil {
		return string(dnssec.ModeOff)
	}
	return string(s.dnssec.Mode)
}

// ServeDNSMsg runs the pipeline and returns a packed response (for DoH).
func (s *Server) ServeDNSMsg(req *dns.Msg) (*dns.Msg, []byte, error) {
	rw := &memResponseWriter{}
	s.ServeDNS(rw, req)
	if rw.msg != nil {
		wire, err := rw.msg.Pack()
		return rw.msg, wire, err
	}
	if len(rw.wire) > 0 {
		msg := new(dns.Msg)
		if err := msg.Unpack(rw.wire); err != nil {
			return nil, rw.wire, nil
		}
		return msg, rw.wire, nil
	}
	return nil, nil, net.ErrClosed
}

type memResponseWriter struct {
	msg  *dns.Msg
	wire []byte
}

func (m *memResponseWriter) LocalAddr() net.Addr                { return &net.UDPAddr{IP: net.IPv4zero, Port: 0} }
func (m *memResponseWriter) RemoteAddr() net.Addr               { return &net.UDPAddr{IP: net.IPv4zero, Port: 0} }
func (m *memResponseWriter) WriteMsg(msg *dns.Msg) error        { m.msg = msg; return nil }
func (m *memResponseWriter) Write(b []byte) (int, error)        { m.wire = append([]byte(nil), b...); return len(b), nil }
func (m *memResponseWriter) Close() error                       { return nil }
func (m *memResponseWriter) TsigStatus() error                  { return nil }
func (m *memResponseWriter) TsigTimersOnly(bool)                {}
func (m *memResponseWriter) Hijack()                            {}
