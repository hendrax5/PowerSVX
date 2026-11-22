package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/acl"
	"github.com/powersvx/powersvx/internal/aclban"
	"github.com/powersvx/powersvx/internal/acme"
	"github.com/powersvx/powersvx/internal/allowlist"
	"github.com/powersvx/powersvx/internal/analytics"
	"github.com/powersvx/powersvx/internal/anomaly"
	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/denylist"
	"github.com/powersvx/powersvx/internal/dnssec"
	"github.com/powersvx/powersvx/internal/eventlog"
	"github.com/powersvx/powersvx/internal/geo"
	"github.com/powersvx/powersvx/internal/kominfo"
	"github.com/powersvx/powersvx/internal/metrics"
	"github.com/powersvx/powersvx/internal/monitor"
	"github.com/powersvx/powersvx/internal/queryring"
	"github.com/powersvx/powersvx/internal/ratelimit"
	"github.com/powersvx/powersvx/internal/rpz"
	"github.com/powersvx/powersvx/internal/secondary"
	"github.com/powersvx/powersvx/internal/tsig"
	"github.com/powersvx/powersvx/internal/view"
)

// Server is the Auth Backend: the query handler of the Control Plane. It answers
// Authoritative Zones and Secondary Zones and refuses everything else. It does
// not recurse, cache, filter, rate limit or ban; those belong to the Dataplane
// (dnsdist in front of Unbound).
//
// The Server also holds the Control Plane's copy of the rules the console edits
// (rate limit, query ACL, bans, Filter lists, runtime flags) and the live
// statistics the Dataplane bridges feed. The API reads and writes them here and
// pushes them to the Dataplane; the query handler never consults them.
type Server struct {
	cfg          *config.Config
	auth         *authoritative.Store
	dnssec       *dnssec.Validator
	signer       *dnssec.Signer
	limiter      *ratelimit.Limiter
	rpz          *rpz.Engine
	allow        *allowlist.List
	deny         *denylist.List
	tsig         *tsig.Store
	views        *view.Matcher
	geo          *geo.Resolver
	events       *eventlog.Bus
	acme         *acme.ChallengeStore
	stats        *analytics.Collector
	anomaly      *anomaly.Detector
	mon          *monitor.Collector
	ring         *queryring.Ring
	secondaryMgr *secondary.Manager
	kominfo      *kominfo.Manager
	onRPZNotify  func(zone, clientIP string, tsigValid bool) bool
	log          *slog.Logger
	queryACLMu   sync.RWMutex
	queryACL     *acl.List
	aclBan       *aclban.Guard
	udp          *dns.Server
	udps         []*dns.Server // all UDP listeners (SO_REUSEPORT shard)
	tcp          *dns.Server
	queries      atomic.Uint64
	blocked      atomic.Uint64
	// invalidLogN samples the WARN for rejected wire messages (1/128).
	invalidLogN atomic.Uint64
	started     time.Time
}

type Deps struct {
	Auth    *authoritative.Store
	DNSSEC  *dnssec.Validator
	Signer  *dnssec.Signer
	Limiter *ratelimit.Limiter
	RPZ     *rpz.Engine
	Allow   *allowlist.List
	Deny    *denylist.List
	TSIG    *tsig.Store
	Views   *view.Matcher
	Geo     *geo.Resolver
	Events  *eventlog.Bus
	ACME    *acme.ChallengeStore
	Stats   *analytics.Collector
	Anomaly *anomaly.Detector
	Monitor *monitor.Collector
	Ring    *queryring.Ring
}

func New(cfg *config.Config, d Deps, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	var qacl *acl.List
	if cfg != nil {
		var err error
		qacl, err = acl.Parse(cfg.ACL.AllowQuery, cfg.ACL.DenyQuery)
		if err != nil {
			log.Warn("acl parse failed, allowing all", "err", err)
			qacl = acl.Open()
		}
	} else {
		qacl = acl.Open()
	}
	var banCfg aclban.Config
	if cfg != nil {
		banCfg = aclban.Config{
			Threshold: cfg.ACL.DenyAutobanThreshold,
			Window:    time.Duration(cfg.ACL.DenyAutobanWindowSec) * time.Second,
			TTL:       time.Duration(cfg.ACL.DenyAutobanTTLSec) * time.Second,
			NFT:       cfg.ACL.DenyAutobanNFT,
		}
	}
	ring := d.Ring
	if ring == nil {
		ring = queryring.New(0)
	}
	return &Server{
		cfg:      cfg,
		auth:     d.Auth,
		dnssec:   d.DNSSEC,
		signer:   d.Signer,
		limiter:  d.Limiter,
		rpz:      d.RPZ,
		allow:    d.Allow,
		deny:     d.Deny,
		tsig:     d.TSIG,
		views:    d.Views,
		geo:      d.Geo,
		events:   d.Events,
		acme:     d.ACME,
		stats:    d.Stats,
		anomaly:  d.Anomaly,
		mon:      d.Monitor,
		ring:     ring,
		log:      log,
		queryACL: qacl,
		aclBan:   aclban.New(banCfg, log),
		started:  time.Now(),
	}
}

// isLocalSource reports whether a query came from this host. The Dataplane
// forwards from loopback; nothing else may reach the Auth Backend.
func isLocalSource(addr net.Addr) bool {
	if addr == nil {
		return false
	}
	host := addr.String()
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// serveFromDataplane is the handler the listeners run. A query whose source is
// not loopback is refused before any processing: it was not sent by the local
// Dataplane.
func (s *Server) serveFromDataplane(w dns.ResponseWriter, req *dns.Msg) {
	if !isLocalSource(w.RemoteAddr()) {
		metrics.QueriesTotal.WithLabelValues(protocolFromWriter(w), "non_local").Inc()
		if req != nil {
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeRefused)
			_ = w.WriteMsg(m)
		}
		return
	}
	s.ServeDNS(w, req)
}

// ServeDNS answers a query from an Authoritative Zone or Secondary Zone, serves
// NOTIFY, dynamic update and zone transfer, and refuses any other name.
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

	if req != nil && req.Opcode == dns.OpcodeNotify {
		zone := ""
		if len(req.Question) > 0 {
			zone = config.NormalizeName(req.Question[0].Name)
		}
		tsigValid := req.IsTsig() != nil && w.TsigStatus() == nil
		m := new(dns.Msg)
		handled := false
		if zone != "" {
			if s.secondaryMgr != nil && s.secondaryMgr.HandleNotifyFrom(zone, clientIP, tsigValid) {
				handled = true
			}
			if s.onRPZNotify != nil && s.onRPZNotify(zone, clientIP, tsigValid) {
				handled = true
			}
		}
		if handled {
			m.SetReply(req)
			metrics.QueriesTotal.WithLabelValues(proto, "notify").Inc()
		} else {
			m.SetRcode(req, dns.RcodeRefused)
			metrics.QueriesTotal.WithLabelValues(proto, "notify_refused").Inc()
		}
		_ = w.WriteMsg(m)
		return
	}

	if req != nil && req.Opcode == dns.OpcodeUpdate {
		if s.handleUpdate(w, req, clientIP) {
			return
		}
	}

	if len(req.Question) == 0 {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeFormatError)
		_ = w.WriteMsg(m)
		metrics.QueriesTotal.WithLabelValues(proto, "formerr").Inc()
		if s.log != nil {
			s.log.Debug("dns FORMERR empty question", "client", clientIP, "proto", proto)
		}
		return
	}

	if s.handleTransfer(w, req, clientIP) {
		return
	}

	q := req.Question[0]
	qname := config.NormalizeName(q.Name)
	qtype := q.Qtype

	if s.acme != nil && qtype == dns.TypeTXT {
		if rr := s.acme.TXTAnswer(qname); rr != nil {
			m := new(dns.Msg)
			m.SetReply(req)
			m.Authoritative = true
			m.Answer = []dns.RR{rr}
			_ = w.WriteMsg(m)
			metrics.QueriesTotal.WithLabelValues(proto, "acme").Inc()
			return
		}
	}

	// Split horizon and GeoDNS pick which records of a zone answer.
	viewName := "default"
	if s.views != nil {
		viewName = s.views.Match(clientIP)
	}
	geoTag := "default"
	if s.geo != nil && s.geo.Enabled() {
		geoTag = s.geo.Lookup(clientIP).Tag
	}

	if s.auth != nil {
		if rrs, inZone := s.auth.LookupScoped(qname, qtype, viewName, geoTag); inZone {
			m := new(dns.Msg)
			m.SetReply(req)
			m.Authoritative = true
			zone := s.auth.FindZone(qname)
			if qtype == dns.TypeDNSKEY && s.signer != nil && s.signer.Enabled(zone) {
				m.Answer = s.signer.DNSKEYs(zone)
				m.Rcode = dns.RcodeSuccess
				s.signer.SignResponse(zone, req, m)
			} else if len(rrs) == 0 {
				if s.auth.NameExists(zone, qname) {
					m.Rcode = dns.RcodeSuccess // NODATA (name exists, qtype absent)
				} else {
					m.Rcode = dns.RcodeNameError // NXDOMAIN
				}
				if soaRRs, ok := s.auth.LookupScoped(zone, dns.TypeSOA, viewName, geoTag); ok && len(soaRRs) > 0 {
					m.Ns = append(m.Ns, soaRRs[0])
				}
				if s.signer != nil && s.signer.Enabled(zone) {
					s.signer.SignDenialForNames(zone, qname, s.auth.ZoneNames(zone), req, m)
				}
			} else {
				m.Answer = rrs
				if s.signer != nil && s.signer.Enabled(zone) {
					s.signer.SignResponse(zone, req, m)
				}
			}
			s.write(w, req, m)
			metrics.QueriesTotal.WithLabelValues(proto, "auth").Inc()
			metrics.QueryDuration.WithLabelValues(proto).Observe(time.Since(start).Seconds())
			return
		}
	}

	// Not a name of any hosted zone: this process does not resolve it.
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeRefused)
	_ = w.WriteMsg(m)
	metrics.QueriesTotal.WithLabelValues(proto, "refused").Inc()
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

// ListenAndServe starts the Auth Backend listeners: UDP and TCP on the
// configured address (loopback unless the operator widens it).
func (s *Server) ListenAndServe() error {
	handler := dns.HandlerFunc(s.serveFromDataplane)
	var tsigMap map[string]string
	if s.tsig != nil && s.tsig.Len() > 0 {
		tsigMap = s.tsig.Map()
	}

	udpAddr := s.cfg.ListenAddr(s.cfg.Server.UDPPort)
	tcpAddr := s.cfg.ListenAddr(s.cfg.Server.TCPPort)

	errCh := make(chan error, 48)

	accept := msgAcceptFunc
	invalid := func(m []byte, err error) {
		if s.log != nil {
			if n := s.invalidLogN.Add(1); n&0x7f == 1 {
				headn := len(m)
				if headn > 64 {
					headn = 64
				}
				s.log.Warn("dns message rejected", "err", err, "bytes", len(m), "head", fmt.Sprintf("%x", m[:headn]), "sampled", n)
			}
		}
		metrics.QueriesTotal.WithLabelValues("udp", "formerr").Inc()
	}
	decorate := decorateEDNSRepair

	nUDP := s.cfg.Server.Workers
	if nUDP <= 0 {
		nUDP = runtime.NumCPU()
	}
	if nUDP < 1 {
		nUDP = 1
	}
	if nUDP > 32 {
		nUDP = 32
	}
	reuse := nUDP > 1
	for i := 0; i < nUDP; i++ {
		srv := &dns.Server{
			Addr:           udpAddr,
			Net:            "udp",
			Handler:        handler,
			UDPSize:        int(s.udpBufSize()),
			ReusePort:      reuse,
			MsgAcceptFunc:  accept,
			MsgInvalidFunc: invalid,
			TsigSecret:     tsigMap,
			DecorateReader: decorate,
		}
		if i == 0 {
			s.udp = srv
		}
		s.udps = append(s.udps, srv)
		idx := i
		go func() {
			s.log.Info("UDP listener starting", "addr", udpAddr, "shard", idx, "shards", nUDP, "reuseport", reuse)
			errCh <- srv.ListenAndServe()
		}()
	}
	s.tcp = &dns.Server{Addr: tcpAddr, Net: "tcp", Handler: handler, MsgAcceptFunc: accept, MsgInvalidFunc: invalid, TsigSecret: tsigMap, DecorateReader: decorate}
	go func() {
		s.log.Info("TCP listener starting", "addr", tcpAddr)
		errCh <- s.tcp.ListenAndServe()
	}()


	return <-errCh
}

func (s *Server) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var err error
	shutdownDNS := append([]*dns.Server{}, s.udps...)
	shutdownDNS = append(shutdownDNS, s.tcp)
	if len(s.udps) == 0 && s.udp != nil {
		shutdownDNS = append([]*dns.Server{s.udp}, s.tcp)
	}
	for _, srv := range shutdownDNS {
		if srv == nil {
			continue
		}
		if e := srv.ShutdownContext(ctx); e != nil && err == nil {
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

func (s *Server) DoTAddr() string { return "" }

// DoT, DoH and DoQ are terminated by the Dataplane; the Go process no longer
// serves them.
func (s *Server) DoHAddr() string { return "" }
func (s *Server) DoQAddr() string { return "" }

func (s *Server) DoTEnabled() bool  { return false }
func (s *Server) DoHEnabled() bool  { return false }
func (s *Server) DoH3Enabled() bool { return false }
func (s *Server) DoQEnabled() bool  { return false }

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

// udpBufSize is the EDNS/UDP pack budget from config (clamped 1232–4096).
func (s *Server) udpBufSize() uint16 {
	if s == nil || s.cfg == nil {
		return config.EDNSBufferMin
	}
	return config.NormalizeEDNSBufferSize(s.cfg.Resolver.EDNSBufferSize)
}

func (s *Server) RPZ() *rpz.Engine { return s.rpz }

// ReloadRPZ replaces the in-memory blocklist from policy sources (file or HTTP).
func (s *Server) ReloadRPZ(policies []rpz.PolicyConfig, timeout time.Duration) (int, error) {
	if s.rpz == nil {
		return 0, nil
	}
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}
	return s.rpz.LoadPolicies(policies, timeout)
}

// RefreshRPZAXFR updates AXFR feeds via IXFR/SOA without re-downloading hosts feeds.
func (s *Server) RefreshRPZAXFR(policies []rpz.PolicyConfig, timeout time.Duration) (int, error) {
	if s.rpz == nil {
		return 0, nil
	}
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}
	return s.rpz.RefreshAXFR(policies, timeout)
}

// RuntimeFlags are feature toggles editable via the API/UI.
type RuntimeFlags struct {
	GeoDNS        bool                       `json:"geodns"`
	RPZ           bool                       `json:"rpz_enabled"`
	RateLimit     bool                       `json:"rate_limit"`
	ECS           bool                       `json:"ecs_enabled"`
	SplitHorizon  bool                       `json:"split_horizon"`
	ResolverMode  string                     `json:"resolver_mode"`
	ForwardOnFail bool                       `json:"forward_on_fail"`
	QueryLog      bool                       `json:"query_log_enabled"`
	Forwarders    []string                   `json:"forwarders,omitempty"`
	ForwardZones  []config.ForwardZoneConfig `json:"forward_zones,omitempty"`
	KominfoSync   bool                       `json:"kominfo_sync_enabled"`
}

func (s *Server) RuntimeFlags() RuntimeFlags {
	f := RuntimeFlags{
		ResolverMode:  "recursive",
		ForwardOnFail: true,
	}
	if s.cfg != nil {
		f.ResolverMode = config.NormalizeResolverMode(s.cfg.Resolver.Mode)
		f.ForwardOnFail = s.cfg.Resolver.ForwardOnFail
		f.QueryLog = s.cfg.Logging.QueryLogEnabled
		f.ECS = s.cfg.Resolver.ECSEnabled
		f.Forwarders = append([]string(nil), s.cfg.Resolver.Forwarders...)
		f.ForwardZones = append([]config.ForwardZoneConfig(nil), s.cfg.Resolver.ForwardZones...)
	}
	if s.geo != nil {
		f.GeoDNS = s.geo.Enabled()
	}
	if s.rpz != nil {
		f.RPZ = s.rpz.Enabled()
	}
	if s.limiter != nil {
		f.RateLimit = s.limiter.Enabled()
	}
	if s.views != nil {
		f.SplitHorizon = s.views.Enabled()
	}
	if s.kominfo != nil {
		f.KominfoSync = s.kominfo.Enabled()
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
	if s.views != nil {
		s.views.SetEnabled(f.SplitHorizon)
	}
	if s.cfg != nil {
		s.cfg.GeoDNS.Enabled = f.GeoDNS
		s.cfg.RPZ.Enabled = f.RPZ
		s.cfg.RateLimit.Enabled = f.RateLimit
		s.cfg.Resolver.ECSEnabled = f.ECS
		s.cfg.Resolver.Mode = config.NormalizeResolverMode(f.ResolverMode)
		s.cfg.Resolver.ForwardOnFail = f.ForwardOnFail
		if f.Forwarders != nil {
			s.cfg.Resolver.Forwarders = append([]string(nil), f.Forwarders...)
		}
		if f.ForwardZones != nil {
			s.cfg.Resolver.ForwardZones = append([]config.ForwardZoneConfig(nil), f.ForwardZones...)
		}
		s.cfg.SplitHorizon.Enabled = f.SplitHorizon
		s.cfg.Logging.QueryLogEnabled = f.QueryLog
		config.ApplyQueryLogGuard(s.cfg)
		s.cfg.KominfoSync.Enabled = f.KominfoSync
	}
	if s.kominfo != nil {
		s.kominfo.SetEnabled(f.KominfoSync)
	}
}

func (s *Server) SetSecondary(m *secondary.Manager) { s.secondaryMgr = m }

func (s *Server) Secondary() *secondary.Manager { return s.secondaryMgr }

func (s *Server) SetKominfo(m *kominfo.Manager) { s.kominfo = m }

func (s *Server) Kominfo() *kominfo.Manager { return s.kominfo }

func (s *Server) TSIG() *tsig.Store { return s.tsig }

// SetRPZNotifyHandler registers a callback for inbound NOTIFY that matches an axfr RPZ feed zone.
func (s *Server) SetRPZNotifyHandler(fn func(zone, clientIP string, tsigValid bool) bool) {
	s.onRPZNotify = fn
}

// SetQueryACL replaces the stored query ACL (allow/deny CIDRs). The API pushes
// it to the Dataplane; the handler does not enforce it.
func (s *Server) SetQueryACL(allow, deny []string) error {
	if s.aclBan != nil {
		s.aclBan.Reset() // clear bans so newly allowed clients are not nft-dropped
	}
	l, err := acl.Parse(allow, deny)
	if err != nil {
		return err
	}
	s.queryACLMu.Lock()
	s.queryACL = l
	s.queryACLMu.Unlock()
	if s.cfg != nil {
		s.cfg.ACL.AllowQuery = l.AllowCIDRs()
		s.cfg.ACL.DenyQuery = l.DenyCIDRs()
	}
	return nil
}

func (s *Server) QueryACL() (allow, deny []string) {
	s.queryACLMu.RLock()
	defer s.queryACLMu.RUnlock()
	if s.queryACL == nil {
		return nil, nil
	}
	return s.queryACL.AllowCIDRs(), s.queryACL.DenyCIDRs()
}

func (s *Server) Analytics() *analytics.Collector { return s.stats }
func (s *Server) Monitor() *monitor.Collector     { return s.mon }
func (s *Server) QueryRing() *queryring.Ring      { return s.ring }
func (s *Server) Allowlist() *allowlist.List      { return s.allow }
func (s *Server) Denylist() *denylist.List             { return s.deny }

func (s *Server) BanIP(ip string, ttl time.Duration) error {
	if s == nil || s.aclBan == nil {
		return fmt.Errorf("aclban guard unavailable")
	}
	return s.aclBan.Ban(ip, ttl)
}

func (s *Server) UnbanIP(ip string) bool {
	if s == nil || s.aclBan == nil {
		return false
	}
	return s.aclBan.Unban(ip)
}

func (s *Server) ACLBanList() []aclban.BanEntry {
	if s == nil || s.aclBan == nil {
		return nil
	}
	return s.aclBan.BanList()
}

func (s *Server) RateLimitConfig() ratelimit.Config {
	if s == nil || s.limiter == nil {
		if s != nil && s.cfg != nil {
			return ratelimit.Config{
				Enabled:       s.cfg.RateLimit.Enabled,
				QPS:           s.cfg.RateLimit.DefaultQPS,
				Burst:         s.cfg.RateLimit.DefaultBurst,
				BlockDuration: s.cfg.RateLimit.BlockDuration,
				Whitelist:     append([]string(nil), s.cfg.RateLimit.Whitelist...),
			}
		}
		return ratelimit.Config{}
	}
	return s.limiter.SnapshotConfig()
}

// ApplyRateLimitConfig stores the rate-limit parameters and the cfg snapshot.
// The API pushes them to the Dataplane.
func (s *Server) ApplyRateLimitConfig(qps, burst, blockSec int, whitelist []string) {
	if s == nil {
		return
	}
	if s.limiter != nil {
		s.limiter.Configure(qps, burst, blockSec, whitelist)
	}
	if s.cfg != nil {
		s.cfg.RateLimit.DefaultQPS = qps
		s.cfg.RateLimit.DefaultBurst = burst
		s.cfg.RateLimit.BlockDuration = blockSec
		s.cfg.RateLimit.Whitelist = append([]string(nil), whitelist...)
	}
}

func (s *Server) ClearRateLimitBlocks() {
	if s != nil && s.limiter != nil {
		s.limiter.ClearBlocked()
	}
}

// RateLimitBlocked returns currently blocked client IPs.
func (s *Server) RateLimitBlocked(limit int) []monitor.Count {
	if s == nil || s.limiter == nil {
		return nil
	}
	blocked := s.limiter.SnapshotBlocked(limit)
	out := make([]monitor.Count, 0, len(blocked))
	for _, b := range blocked {
		out = append(out, monitor.Count{Key: b.IP, Count: uint64(b.Remaining)})
	}
	return out
}
func (s *Server) Anomaly() *anomaly.Detector { return s.anomaly }
func (s *Server) Signer() *dnssec.Signer     { return s.signer }

func (s *Server) ServeDNSMsg(req *dns.Msg) (*dns.Msg, []byte, error) {
	return s.ServeDNSMsgFrom(req, "127.0.0.1")
}

// ServeDNSMsgFrom runs the handler in process as if the query came from clientIP.
func (s *Server) ServeDNSMsgFrom(req *dns.Msg, clientIP string) (*dns.Msg, []byte, error) {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		ip = net.IPv4(127, 0, 0, 1)
	}
	rw := &memResponseWriter{remote: &net.UDPAddr{IP: ip, Port: 0}}
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
	msg    *dns.Msg
	wire   []byte
	remote net.Addr
}

func (m *memResponseWriter) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4zero, Port: 0} }
func (m *memResponseWriter) RemoteAddr() net.Addr {
	if m.remote != nil {
		return m.remote
	}
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}
func (m *memResponseWriter) WriteMsg(msg *dns.Msg) error { m.msg = msg; return nil }
func (m *memResponseWriter) Write(b []byte) (int, error) {
	m.wire = append([]byte(nil), b...)
	return len(b), nil
}
func (m *memResponseWriter) Close() error        { return nil }
func (m *memResponseWriter) TsigStatus() error   { return nil }
func (m *memResponseWriter) TsigTimersOnly(bool) {}
func (m *memResponseWriter) Hijack()             {}

