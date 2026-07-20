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
	"github.com/powersvx/powersvx/internal/acme"
	"github.com/powersvx/powersvx/internal/analytics"
	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/cache"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/dnssec"
	"github.com/powersvx/powersvx/internal/ecs"
	"github.com/powersvx/powersvx/internal/eventlog"
	"github.com/powersvx/powersvx/internal/geo"
	"github.com/powersvx/powersvx/internal/metrics"
	"github.com/powersvx/powersvx/internal/ratelimit"
	"github.com/powersvx/powersvx/internal/resolver"
	"github.com/powersvx/powersvx/internal/rpz"
	"github.com/powersvx/powersvx/internal/tsig"
	"github.com/powersvx/powersvx/internal/view"
	"github.com/quic-go/quic-go"
)

// Server is the DNS request pipeline.
type Server struct {
	cfg     *config.Config
	cache   *cache.Tier
	res     *resolver.Resolver
	auth    *authoritative.Store
	dnssec  *dnssec.Validator
	limiter *ratelimit.Limiter
	rpz     *rpz.Engine
	tsig    *tsig.Store
	views   *view.Matcher
	geo     *geo.Resolver
	tlsCfg  *tls.Config
	events  *eventlog.Bus
	acme    *acme.ChallengeStore
	stats   *analytics.Collector
	log     *slog.Logger
	udp     *dns.Server
	tcp     *dns.Server
	dot     *dns.Server
	dohHTTP *http.Server
	doqLn   *quic.Listener
	doqCtx  context.Context
	doqCancel context.CancelFunc
	queries atomic.Uint64
	blocked atomic.Uint64
	started time.Time
	dotOn   bool
	dohOn   bool
	doqOn   bool
}

type Deps struct {
	Cache   *cache.Tier
	Res     *resolver.Resolver
	Auth    *authoritative.Store
	DNSSEC  *dnssec.Validator
	Limiter *ratelimit.Limiter
	RPZ     *rpz.Engine
	TSIG    *tsig.Store
	Views   *view.Matcher
	Geo     *geo.Resolver
	TLS     *tls.Config
	Events  *eventlog.Bus
	ACME    *acme.ChallengeStore
	Stats   *analytics.Collector
}

func New(cfg *config.Config, d Deps, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		cfg:     cfg,
		cache:   d.Cache,
		res:     d.Res,
		auth:    d.Auth,
		dnssec:  d.DNSSEC,
		limiter: d.Limiter,
		rpz:     d.RPZ,
		tsig:    d.TSIG,
		views:   d.Views,
		geo:     d.Geo,
		tlsCfg:  d.TLS,
		events:  d.Events,
		acme:    d.ACME,
		stats:   d.Stats,
		log:     log,
		started: time.Now(),
	}
}

func (s *Server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	start := time.Now()
	s.queries.Add(1)
	proto := protocolFromWriter(w)

	clientIP := ""
	if ra := w.RemoteAddr(); ra != nil {
		host, _, err := net.SplitHostPort(ra.String())
		if err == nil {
			clientIP = host
		} else {
			clientIP = ra.String()
		}
	}

	if s.limiter != nil && clientIP != "" && !s.limiter.Allow(clientIP) {
		s.blocked.Add(1)
		metrics.RateLimited.Inc()
		metrics.QueriesTotal.WithLabelValues(proto, "ratelimited").Inc()
		if s.events != nil {
			s.events.EmitSampled("rl:"+clientIP, 30*time.Second, "warn", "rate_limit",
				"client rate limited", map[string]string{"client": clientIP, "proto": proto})
		}
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeRefused)
		_ = w.WriteMsg(m)
		return
	}

	if len(req.Question) == 0 {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeFormatError)
		_ = w.WriteMsg(m)
		metrics.QueriesTotal.WithLabelValues(proto, "formerr").Inc()
		return
	}

	q := req.Question[0]
	qname := config.NormalizeName(q.Name)
	qtype := q.Qtype
	observe := func(code string) {
		if s.stats != nil {
			s.stats.Observe(qname, code)
		}
	}

	if s.acme != nil && qtype == dns.TypeTXT {
		if rr := s.acme.TXTAnswer(qname); rr != nil {
			m := new(dns.Msg)
			m.SetReply(req)
			m.Authoritative = true
			m.Answer = []dns.RR{rr}
			_ = w.WriteMsg(m)
			metrics.QueriesTotal.WithLabelValues(proto, "acme").Inc()
			observe("NOERROR")
			return
		}
	}

	// Split horizon + GeoDNS + ECS scope
	viewName := "default"
	if s.views != nil {
		viewName = s.views.Match(clientIP)
	}
	geoTag := "default"
	if s.geo != nil && s.geo.Enabled() {
		geoTag = s.geo.Lookup(clientIP).Tag
	}
	var sub *ecs.Subnet
	if s.res != nil && s.res.ECSEnabled {
		sub = ecs.Extract(req)
		if sub == nil && clientIP != "" {
			sub = ecs.FromIP(net.ParseIP(clientIP), s.res.ECSPrefixV4, s.res.ECSPrefixV6)
		}
	}
	ecsKey := ""
	if sub != nil {
		ecsKey = sub.String()
	}

	// RPZ before cache so blocks always apply
	if s.rpz != nil {
		if action, hit := s.rpz.Lookup(qname); hit {
			metrics.RPZBlocked.Inc()
			metrics.QueriesTotal.WithLabelValues(proto, "blocked").Inc()
			m := new(dns.Msg)
			m.SetReply(req)
			m.RecursionAvailable = true
			switch action {
			case rpz.ActionNODATA:
				m.Rcode = dns.RcodeSuccess
			default:
				m.Rcode = dns.RcodeNameError
			}
			_ = w.WriteMsg(m)
			metrics.QueryDuration.WithLabelValues(proto).Observe(time.Since(start).Seconds())
			if action == rpz.ActionNODATA {
				observe("NOERROR")
			} else {
				observe("NXDOMAIN")
			}
			return
		}
	}

	if entry, ok := s.cache.GetScoped(qname, qtype, ecsKey, viewName, geoTag); ok {
		metrics.CacheHits.Inc()
		wire := resolver.RewriteID(entry.Wire, req.Id)
		_, _ = w.Write(wire)
		metrics.QueriesTotal.WithLabelValues(proto, "cache").Inc()
		metrics.QueryDuration.WithLabelValues(proto).Observe(time.Since(start).Seconds())
		observe(dns.RcodeToString[entry.Rcode])
		return
	}
	metrics.CacheMisses.Inc()

	if s.auth != nil {
		if rrs, inZone := s.auth.LookupScoped(qname, qtype, viewName, geoTag); inZone {
			m := new(dns.Msg)
			m.SetReply(req)
			m.Authoritative = true
			m.RecursionAvailable = true
			if len(rrs) == 0 {
				m.Rcode = dns.RcodeNameError
			} else {
				m.Answer = rrs
			}
			s.storeAndWriteScoped(w, req, m, ecsKey, viewName, geoTag)
			metrics.QueriesTotal.WithLabelValues(proto, "auth").Inc()
			metrics.QueryDuration.WithLabelValues(proto).Observe(time.Since(start).Seconds())
			observe(dns.RcodeToString[m.Rcode])
			return
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.res.Timeout)
	defer cancel()

	resp, err := s.res.ResolveWithECS(ctx, req, sub)
	if err != nil {
		s.log.Warn("resolve failed", "kind", "resolve", "name", qname, "err", err)
		m := new(dns.Msg)
		m.SetReply(req)
		m.RecursionAvailable = true
		m.Rcode = dns.RcodeServerFailure
		_ = w.WriteMsg(m)
		metrics.QueriesTotal.WithLabelValues(proto, "servfail").Inc()
		observe("SERVFAIL")
		return
	}

	resp.Id = req.Id
	resp.RecursionAvailable = true
	resp.Compress = true

	if s.dnssec != nil && s.dnssec.Enabled() {
		if servfail, res := s.dnssec.Apply(resp); servfail {
			s.log.Warn("dnssec bogus", "kind", "dnssec", "name", qname, "reason", res.Reason)
			m := new(dns.Msg)
			m.SetReply(req)
			m.RecursionAvailable = true
			m.Rcode = dns.RcodeServerFailure
			_ = w.WriteMsg(m)
			metrics.QueriesTotal.WithLabelValues(proto, "dnssec_fail").Inc()
			observe("SERVFAIL")
			return
		}
	}

	s.storeAndWriteScoped(w, req, resp, ecsKey, viewName, geoTag)
	metrics.QueriesTotal.WithLabelValues(proto, "ok").Inc()
	metrics.QueryDuration.WithLabelValues(proto).Observe(time.Since(start).Seconds())
	observe(dns.RcodeToString[resp.Rcode])
}

func protocolFromWriter(w dns.ResponseWriter) string {
	if w == nil || w.LocalAddr() == nil {
		return "udp"
	}
	switch w.LocalAddr().Network() {
	case "tcp", "tcp4", "tcp6":
		return "tcp"
	default:
		return "udp"
	}
}

func (s *Server) storeAndWrite(w dns.ResponseWriter, req, resp *dns.Msg) {
	s.storeAndWriteScoped(w, req, resp, "", "", "")
}

func (s *Server) storeAndWriteScoped(w dns.ResponseWriter, req, resp *dns.Msg, ecsSubnet, viewName, geoTag string) {
	wire, err := resolver.PackResponse(resp)
	if err != nil {
		_ = w.WriteMsg(resp)
		return
	}
	ttl := resolver.MinTTL(resp)
	s.cache.SetScoped(config.NormalizeName(req.Question[0].Name), req.Question[0].Qtype, ecsSubnet, viewName, geoTag, wire, resp.Rcode, ttl)
	_, _ = w.Write(wire)
}

func (s *Server) ListenAndServe() error {
	handler := dns.HandlerFunc(s.ServeDNS)
	tsigMap := map[string]string(nil)
	if s.tsig != nil {
		tsigMap = s.tsig.Map()
	}

	udpAddr := s.cfg.ListenAddr(s.cfg.Server.UDPPort)
	tcpAddr := s.cfg.ListenAddr(s.cfg.Server.TCPPort)

	s.udp = &dns.Server{Addr: udpAddr, Net: "udp", Handler: handler, UDPSize: 1232, TsigSecret: tsigMap}
	s.tcp = &dns.Server{Addr: tcpAddr, Net: "tcp", Handler: handler, TsigSecret: tsigMap}

	errCh := make(chan error, 5)
	s.doqCtx, s.doqCancel = context.WithCancel(context.Background())

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
		s.dot = &dns.Server{Addr: dotAddr, Net: "tcp-tls", Handler: handler, TLSConfig: dotTLS, TsigSecret: tsigMap}
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

	if s.tlsCfg != nil && s.cfg.Server.DoQPort > 0 {
		doqAddr := s.cfg.ListenAddr(s.cfg.Server.DoQPort)
		if err := s.startDoQ(s.doqCtx, doqAddr); err != nil {
			s.log.Error("DoQ start failed", "err", err)
		} else {
			s.log.Info("DoQ listener starting", "addr", doqAddr)
		}
	}

	return <-errCh
}

func (s *Server) Shutdown() error {
	if s.doqCancel != nil {
		s.doqCancel()
	}
	if s.doqLn != nil {
		_ = s.doqLn.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var err error
	for _, srv := range []*dns.Server{s.udp, s.tcp, s.dot} {
		if srv == nil {
			continue
		}
		if e := srv.ShutdownContext(ctx); e != nil && err == nil {
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

func (s *Server) Blocked() uint64 { return s.blocked.Load() }

func (s *Server) UDPAddr() string { return s.cfg.ListenAddr(s.cfg.Server.UDPPort) }

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

func (s *Server) DoQAddr() string {
	if !s.doqOn {
		return ""
	}
	return s.cfg.ListenAddr(s.cfg.Server.DoQPort)
}

func (s *Server) DoTEnabled() bool { return s.dotOn }
func (s *Server) DoHEnabled() bool { return s.dohOn }
func (s *Server) DoQEnabled() bool { return s.doqOn }

func (s *Server) DNSSECMode() string {
	if s.dnssec == nil {
		return string(dnssec.ModeOff)
	}
	return string(s.dnssec.Mode)
}

func (s *Server) RPZCount() int64 {
	if s.rpz == nil {
		return 0
	}
	return s.rpz.Count()
}

// RuntimeFlags are feature toggles editable via the API/UI.
type RuntimeFlags struct {
	GeoDNS       bool `json:"geodns"`
	RPZ          bool `json:"rpz_enabled"`
	RateLimit    bool `json:"rate_limit"`
	ECS          bool `json:"ecs_enabled"`
	SplitHorizon bool `json:"split_horizon"`
}

func (s *Server) RuntimeFlags() RuntimeFlags {
	f := RuntimeFlags{}
	if s.geo != nil {
		f.GeoDNS = s.geo.Enabled()
	}
	if s.rpz != nil {
		f.RPZ = s.rpz.Enabled()
	}
	if s.limiter != nil {
		f.RateLimit = s.limiter.Enabled()
	}
	if s.res != nil {
		f.ECS = s.res.ECSEnabled
	}
	if s.views != nil {
		f.SplitHorizon = s.views.Enabled()
	}
	return f
}

func (s *Server) ApplyRuntimeFlags(f RuntimeFlags) {
	if s.geo != nil {
		s.geo.SetEnabled(f.GeoDNS)
	}
	if s.rpz != nil {
		s.rpz.SetEnabled(f.RPZ)
	}
	if s.limiter != nil {
		s.limiter.SetEnabled(f.RateLimit)
	}
	if s.res != nil {
		s.res.SetECSEnabled(f.ECS)
	}
	if s.views != nil {
		s.views.SetEnabled(f.SplitHorizon)
	}
	if s.cfg != nil {
		s.cfg.GeoDNS.Enabled = f.GeoDNS
		s.cfg.RPZ.Enabled = f.RPZ
		s.cfg.RateLimit.Enabled = f.RateLimit
		s.cfg.Resolver.ECSEnabled = f.ECS
		s.cfg.SplitHorizon.Enabled = f.SplitHorizon
	}
}

func (s *Server) Analytics() *analytics.Collector { return s.stats }

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

func (m *memResponseWriter) LocalAddr() net.Addr         { return &net.UDPAddr{IP: net.IPv4zero, Port: 0} }
func (m *memResponseWriter) RemoteAddr() net.Addr        { return &net.UDPAddr{IP: net.IPv4zero, Port: 0} }
func (m *memResponseWriter) WriteMsg(msg *dns.Msg) error { m.msg = msg; return nil }
func (m *memResponseWriter) Write(b []byte) (int, error) {
	m.wire = append([]byte(nil), b...)
	return len(b), nil
}
func (m *memResponseWriter) Close() error        { return nil }
func (m *memResponseWriter) TsigStatus() error   { return nil }
func (m *memResponseWriter) TsigTimersOnly(bool) {}
func (m *memResponseWriter) Hijack()             {}
