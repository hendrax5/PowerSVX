package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"strings"
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
	"github.com/powersvx/powersvx/internal/cache"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/database"
	"github.com/powersvx/powersvx/internal/denylist"
	"github.com/powersvx/powersvx/internal/dnssec"
	"github.com/powersvx/powersvx/internal/ecs"
	"github.com/powersvx/powersvx/internal/eventlog"
	"github.com/powersvx/powersvx/internal/geo"
	"github.com/powersvx/powersvx/internal/kominfo"
	"github.com/powersvx/powersvx/internal/metrics"
	"github.com/powersvx/powersvx/internal/monitor"
	"github.com/powersvx/powersvx/internal/otelx"
	"github.com/powersvx/powersvx/internal/plugin"
	"github.com/powersvx/powersvx/internal/ratelimit"
	"github.com/powersvx/powersvx/internal/resolver"
	"github.com/powersvx/powersvx/internal/rpz"
	"github.com/powersvx/powersvx/internal/secondary"
	"github.com/powersvx/powersvx/internal/tproxy"
	"github.com/powersvx/powersvx/internal/tsig"
	"github.com/powersvx/powersvx/internal/view"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// Server is the DNS request pipeline.
type Server struct {
	cfg          *config.Config
	cache        *cache.Tier
	res          *resolver.Resolver
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
	tlsCfg       *tls.Config
	events       *eventlog.Bus
	acme         *acme.ChallengeStore
	stats        *analytics.Collector
	anomaly      *anomaly.Detector
	mon          *monitor.Collector
	plugins      *plugin.Registry
	qlog         *database.QueryLogger
	secondaryMgr *secondary.Manager
	kominfo      *kominfo.Manager
	onRPZNotify  func(zone string) bool
	log          *slog.Logger
	queryACLMu   sync.RWMutex
	queryACL     *acl.List
	aclBan       *aclban.Guard
	aclDenyN     atomic.Uint64
	nsec         *dnssec.NSECCache
	// refreshInflight dedupes background cache refresh/prefetch by cache key.
	refreshInflight sync.Map // uint64 -> struct{}
	udp             *dns.Server
	udps            []*dns.Server // all UDP listeners (SO_REUSEPORT shard)
	tcp             *dns.Server
	dot             *dns.Server
	dohHTTP         *http.Server
	dohHTTP3        *http3.Server
	doqLn           *quic.Listener
	doqCtx          context.Context
	doqCancel       context.CancelFunc
	queries         atomic.Uint64
	blocked         atomic.Uint64
	// resolveFailLogN samples WARN "resolve failed" under miss storms (1/128).
	resolveFailLogN atomic.Uint64
	started         time.Time
	dotOn           bool
	dohOn           bool
	doh3On          bool
	doqOn           bool
}

type Deps struct {
	Cache   *cache.Tier
	Res     *resolver.Resolver
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
	TLS     *tls.Config
	Events  *eventlog.Bus
	ACME    *acme.ChallengeStore
	Stats   *analytics.Collector
	Anomaly *anomaly.Detector
	Monitor *monitor.Collector
	Plugins *plugin.Registry
	QLog    *database.QueryLogger
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
	var ban *aclban.Guard
	if cfg != nil && cfg.ACL.DenyAutobanThreshold > 0 {
		ban = aclban.New(aclban.Config{
			Threshold: cfg.ACL.DenyAutobanThreshold,
			Window:    time.Duration(cfg.ACL.DenyAutobanWindowSec) * time.Second,
			TTL:       time.Duration(cfg.ACL.DenyAutobanTTLSec) * time.Second,
			NFT:       cfg.ACL.DenyAutobanNFT,
		}, log)
	}
	return &Server{
		cfg:      cfg,
		cache:    d.Cache,
		res:      d.Res,
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
		tlsCfg:   d.TLS,
		events:   d.Events,
		acme:     d.ACME,
		stats:    d.Stats,
		anomaly:  d.Anomaly,
		mon:      d.Monitor,
		plugins:  d.Plugins,
		qlog:     d.QLog,
		nsec:     dnssec.NewNSECCache(),
		log:      log,
		queryACL: qacl,
		aclBan:   ban,
		started:  time.Now(),
	}
}

func (s *Server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	_, span := otelx.Tracer().Start(context.Background(), "dns.query")
	defer span.End()

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
		m := new(dns.Msg)
		handled := false
		if zone != "" {
			if s.secondaryMgr != nil && s.secondaryMgr.HandleNotify(zone) {
				handled = true
			}
			if s.onRPZNotify != nil && s.onRPZNotify(zone) {
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

	logQuery := func(qname, qtype string, rcode int, cached bool) {
		if s.qlog == nil || s.cfg == nil || !s.cfg.Logging.QueryLogEnabled || qname == "" || clientIP == "" {
			return
		}
		rate := s.cfg.Logging.QueryLogSampleRate
		// 0 = keep all (when logging enabled). Under admit pressure, tighten further.
		if rate > 0 && rate < 1 {
			if s.res != nil {
				if capN := s.res.InflightCap(); capN > 0 && s.res.Inflight()*2 >= capN {
					rate *= 0.2
					if rate < 0.005 {
						rate = 0.005
					}
				}
			}
			// Sample: keep roughly rate fraction using cheap counter.
			if (s.queries.Load() % 1000) >= uint64(rate*1000) {
				return
			}
		}
		ip := clientIP
		if s.cfg.Logging.QueryLogMaskIP {
			ip = database.MaskClientIP(ip)
		}
		s.qlog.Log(database.QueryLogEntry{
			Timestamp:    time.Now(),
			ClientIP:     ip,
			QueryName:    qname,
			QueryType:    qtype,
			ResponseCode: rcode,
			ResponseMS:   int(time.Since(start).Milliseconds()),
			Cached:       cached,
			Protocol:     proto,
		})
	}
	note := func(path, rcode string, aclDenied, rateLimited, timeout bool) {
		if s.mon == nil {
			return
		}
		qn := ""
		if len(req.Question) > 0 {
			qn = config.NormalizeName(req.Question[0].Name)
		}
		s.mon.Observe(monitor.Sample{
			ClientIP:    clientIP,
			QName:       qn,
			Latency:     time.Since(start),
			Path:        path,
			RCode:       rcode,
			ACLDenied:   aclDenied,
			RateLimited: rateLimited,
			Timeout:     timeout,
		})
	}

	s.queryACLMu.RLock()
	qacl := s.queryACL
	s.queryACLMu.RUnlock()
	if qacl != nil && clientIP != "" && !qacl.Allows(clientIP) {
		metrics.QueriesTotal.WithLabelValues(proto, "acl_denied").Inc()
		// Autoban: after threshold, silent-drop (no REFUSED / no query-log) to cut CPU.
		if s.aclBan != nil {
			if silent, newBan := s.aclBan.Observe(clientIP); silent {
				metrics.ACLSilentDrop.Inc()
				if newBan {
					metrics.ACLAutoban.Inc()
				}
				return
			}
		}
		if s.events != nil {
			s.events.EmitSampled("acl:"+clientIP, 30*time.Second, "warn", "acl",
				"client denied by query ACL", map[string]string{"client": clientIP, "proto": proto})
		}
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeRefused)
		_ = w.WriteMsg(m)
		// Do not query-log ACL denies — spam fills Postgres and burns CPU.
		// Sample monitor sparsely (≈1%).
		if s.aclDenyN.Add(1)%100 == 1 {
			note("acl_denied", "REFUSED", true, false, false)
		}
		return
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
		if len(req.Question) > 0 {
			q := req.Question[0]
			logQuery(config.NormalizeName(q.Name), dns.TypeToString[q.Qtype], dns.RcodeRefused, false)
		}
		note("ratelimited", "REFUSED", false, true, false)
		return
	}

	if len(req.Question) == 0 {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeFormatError)
		_ = w.WriteMsg(m)
		metrics.QueriesTotal.WithLabelValues(proto, "formerr").Inc()
		if s.log != nil {
			s.log.Debug("dns FORMERR empty question", "client", clientIP, "proto", proto)
		}
		note("formerr", "FORMERR", false, false, false)
		return
	}

	if s.handleTransfer(w, req, clientIP) {
		return
	}

	q := req.Question[0]
	qname := config.NormalizeName(q.Name)
	qtype := q.Qtype
	qtypeStr := dns.TypeToString[qtype]
	observe := func(code string) {
		if s.stats != nil {
			s.stats.Observe(qname, code)
		}
		if s.anomaly != nil {
			s.anomaly.Observe(code)
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
			logQuery(qname, qtypeStr, dns.RcodeSuccess, false)
			note("acme", "NOERROR", false, false, false)
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
	if s.plugins != nil {
		if d, name := s.plugins.Decide(plugin.QueryCtx{Name: qname, Qtype: qtype, ClientIP: clientIP}); d != plugin.DecisionContinue {
			metrics.QueriesTotal.WithLabelValues(proto, "plugin").Inc()
			code := "NXDOMAIN"
			rcode := dns.RcodeNameError
			if d == plugin.DecisionNODATA {
				code = "NOERROR"
				rcode = dns.RcodeSuccess
			} else if d == plugin.DecisionRefused {
				code = "REFUSED"
				rcode = dns.RcodeRefused
			}
			observe(code)
			if s.events != nil {
				s.events.Emit("info", "plugin", "query blocked by plugin", map[string]string{"plugin": name, "qname": qname})
			}
			_ = plugin.ApplyDecision(w, req, d)
			logQuery(qname, qtypeStr, rcode, false)
			note("plugin", code, false, false, false)
			return
		}
	}

	if s.rpz != nil || s.deny != nil {
		whitelisted := s.allow != nil && s.allow.Allows(qname)
		if !whitelisted {
			if s.deny != nil && s.deny.Blocks(qname) {
				metrics.RPZBlocked.Inc()
				metrics.QueriesTotal.WithLabelValues(proto, "blocked").Inc()
				m := new(dns.Msg)
				m.SetReply(req)
				m.RecursionAvailable = true
				m.Rcode = dns.RcodeNameError
				_ = w.WriteMsg(m)
				metrics.QueryDuration.WithLabelValues(proto).Observe(time.Since(start).Seconds())
				observe("NXDOMAIN")
				logQuery(qname, qtypeStr, dns.RcodeNameError, false)
				note("blacklist", "NXDOMAIN", false, false, false)
				return
			}
			if s.rpz != nil {
				if hit, ok := s.rpz.Lookup(qname); ok {
					if hit.Action == rpz.ActionPass {
						// Explicit allow — continue to cache / auth / recursive.
					} else {
						metrics.RPZBlocked.Inc()
						metrics.QueriesTotal.WithLabelValues(proto, "blocked").Inc()
						m := new(dns.Msg)
						m.SetReply(req)
						m.RecursionAvailable = true
						rcode := dns.RcodeNameError
						code := "NXDOMAIN"
						switch hit.Action {
						case rpz.ActionNODATA:
							m.Rcode = dns.RcodeSuccess
							rcode = dns.RcodeSuccess
							code = "NOERROR"
						case rpz.ActionRedirect:
							m.Rcode = dns.RcodeSuccess
							rcode = dns.RcodeSuccess
							code = "NOERROR"
							if rr := rpzRedirectRR(qname, qtype, hit.Target); rr != nil {
								m.Answer = []dns.RR{rr}
							}
						case rpz.ActionCNAME:
							m.Rcode = dns.RcodeSuccess
							rcode = dns.RcodeSuccess
							code = "NOERROR"
							if rr := rpzCNAMERR(qname, hit.Target); rr != nil {
								m.Answer = []dns.RR{rr}
							}
						default:
							m.Rcode = dns.RcodeNameError
						}
						_ = w.WriteMsg(m)
						metrics.QueryDuration.WithLabelValues(proto).Observe(time.Since(start).Seconds())
						observe(code)
						logQuery(qname, qtypeStr, rcode, false)
						note("rpz", code, false, false, false)
						return
					}
				}
			}
		}
	}

	if entry, st := s.cache.GetScopedEx(qname, qtype, ecsKey, viewName, geoTag); st != cache.Miss {
		pathLabel := "cache"
		if st == cache.HitStale {
			metrics.CacheStaleHits.Inc()
			pathLabel = "cache_stale"
			s.scheduleRefresh(qname, qtype, ecsKey, viewName, geoTag, sub, req)
		} else {
			metrics.CacheHits.Inc()
			if entry.NeedsPrefetch(s.cache.PrefetchPct) {
				s.scheduleRefresh(qname, qtype, ecsKey, viewName, geoTag, sub, req)
			}
		}
		cached := new(dns.Msg)
		// Fast path: rewrite message ID in wire bytes (skip Unpack at multi‑10k QPS).
		// Fall back to Unpack only when client sent EDNS COOKIE (must echo).
		if opt := req.IsEdns0(); opt != nil && ednsHasCookie(opt) {
			if err := cached.Unpack(entry.Wire); err != nil {
				wire := resolver.RewriteID(entry.Wire, req.Id)
				_, _ = w.Write(wire)
			} else {
				cached.Id = req.Id
				resolver.PrepareClientResponse(req, cached, s.udpBufSize())
				_ = w.WriteMsg(cached)
			}
		} else {
			wire := resolver.RewriteID(entry.Wire, req.Id)
			_, _ = w.Write(wire)
		}
		metrics.QueriesTotal.WithLabelValues(proto, pathLabel).Inc()
		sec := time.Since(start).Seconds()
		metrics.QueryDuration.WithLabelValues(proto).Observe(sec)
		metrics.QueryDurationByPath.WithLabelValues(pathLabel).Observe(sec)
		observe(dns.RcodeToString[entry.Rcode])
		logQuery(qname, qtypeStr, entry.Rcode, true)
		note(pathLabel, dns.RcodeToString[entry.Rcode], false, false, false)
		return
	}
	metrics.CacheMisses.Inc()

	if s.auth != nil {
		if rrs, inZone := s.auth.LookupScoped(qname, qtype, viewName, geoTag); inZone {
			m := new(dns.Msg)
			m.SetReply(req)
			m.Authoritative = true
			m.RecursionAvailable = true
			zone := s.auth.FindZone(qname)
			if qtype == dns.TypeDNSKEY && s.signer != nil && s.signer.Enabled(zone) {
				m.Answer = s.signer.DNSKEYs(zone)
				m.Rcode = dns.RcodeSuccess
				s.signer.SignResponse(zone, req, m)
			} else if len(rrs) == 0 {
				m.Rcode = dns.RcodeNameError
				if s.signer != nil && s.signer.Enabled(zone) {
					s.signer.SignDenial(zone, qname, req, m)
				}
			} else {
				m.Answer = rrs
				if s.signer != nil && s.signer.Enabled(zone) {
					s.signer.SignResponse(zone, req, m)
				}
			}
			s.storeAndWriteScoped(w, req, m, ecsKey, viewName, geoTag)
			metrics.QueriesTotal.WithLabelValues(proto, "auth").Inc()
			metrics.QueryDuration.WithLabelValues(proto).Observe(time.Since(start).Seconds())
			observe(dns.RcodeToString[m.Rcode])
			logQuery(qname, qtypeStr, m.Rcode, false)
			note("auth", dns.RcodeToString[m.Rcode], false, false, false)
			return
		}
	}

	if viewName == "default" && geoTag == "default" {
		if m := s.aggressiveNSEC(req, qname); m != nil {
			metrics.AggressiveNSEC.Inc()
			s.storeAndWriteScoped(w, req, m, ecsKey, viewName, geoTag)
			metrics.QueriesTotal.WithLabelValues(proto, "aggressive_nsec").Inc()
			sec := time.Since(start).Seconds()
			metrics.QueryDuration.WithLabelValues(proto).Observe(sec)
			metrics.QueryDurationByPath.WithLabelValues("aggressive_nsec").Observe(sec)
			observe("NXDOMAIN")
			logQuery(qname, qtypeStr, dns.RcodeNameError, false)
			note("aggressive_nsec", "NXDOMAIN", false, false, false)
			return
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.res.Timeout)
	defer cancel()

	metrics.ResolveInflight.Set(float64(s.res.Inflight()))
	resp, via, err := s.res.ResolveWithECS(ctx, req, sub)
	metrics.ResolveInflight.Set(float64(s.res.Inflight()))
	if err != nil {
		if errors.Is(err, resolver.ErrAdmitRejected) {
			metrics.AdmitRejected.Inc()
			m := new(dns.Msg)
			m.SetReply(req)
			m.RecursionAvailable = true
			m.Rcode = dns.RcodeServerFailure
			s.cacheResolveFailure(qname, qtype, ecsKey, viewName, geoTag, m)
			_ = w.WriteMsg(m)
			metrics.QueriesTotal.WithLabelValues(proto, "admit_rejected").Inc()
			observe("SERVFAIL")
			logQuery(qname, qtypeStr, dns.RcodeServerFailure, false)
			note("admit_rejected", "SERVFAIL", false, false, false)
			return
		}
		// Sample logs — under multi-k QPS miss storms, WARN-per-fail burns CPU/disk.
		if n := s.resolveFailLogN.Add(1); n&0x7f == 1 {
			s.log.Warn("resolve failed", "kind", "resolve", "name", qname, "err", err, "sampled", n)
		}
		m := new(dns.Msg)
		m.SetReply(req)
		m.RecursionAvailable = true
		m.Rcode = dns.RcodeServerFailure
		// Negative-cache SERVFAIL so the same dead/slow name is not re-walked every query.
		s.cacheResolveFailure(qname, qtype, ecsKey, viewName, geoTag, m)
		_ = w.WriteMsg(m)
		metrics.QueriesTotal.WithLabelValues(proto, "servfail").Inc()
		observe("SERVFAIL")
		logQuery(qname, qtypeStr, dns.RcodeServerFailure, false)
		isTimeout := errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "deadline exceeded")
		if via == "" {
			via = "servfail"
		}
		metrics.QueryDurationByPath.WithLabelValues(via).Observe(time.Since(start).Seconds())
		note(via, "SERVFAIL", false, false, isTimeout)
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
			logQuery(qname, qtypeStr, dns.RcodeServerFailure, false)
			note("dnssec_fail", "SERVFAIL", false, false, false)
			return
		}
	}

	s.rememberNSEC(resp)
	s.storeAndWriteScoped(w, req, resp, ecsKey, viewName, geoTag)
	metrics.QueriesTotal.WithLabelValues(proto, "ok").Inc()
	sec := time.Since(start).Seconds()
	metrics.QueryDuration.WithLabelValues(proto).Observe(sec)
	if via == "" {
		via = "forward"
	}
	metrics.QueryDurationByPath.WithLabelValues(via).Observe(sec)
	observe(dns.RcodeToString[resp.Rcode])
	logQuery(qname, qtypeStr, resp.Rcode, false)
	note(via, dns.RcodeToString[resp.Rcode], false, false, false)
}

func (s *Server) aggressiveNSEC(req *dns.Msg, qname string) *dns.Msg {
	if s == nil || s.nsec == nil || req == nil || qname == "" {
		return nil
	}
	n := s.nsec.Cover(qname)
	if n == nil {
		return nil
	}
	m := new(dns.Msg)
	m.SetReply(req)
	m.RecursionAvailable = true
	m.AuthenticatedData = true
	m.Rcode = dns.RcodeNameError
	m.Ns = []dns.RR{n}
	return m
}

func (s *Server) rememberNSEC(resp *dns.Msg) {
	if s == nil || s.nsec == nil || resp == nil || !resp.AuthenticatedData {
		return
	}
	if resp.Rcode != dns.RcodeNameError && !(resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0) {
		return
	}
	s.nsec.AddFrom(resp.Ns)
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

// cacheResolveFailure stores SERVFAIL under NegativeTTL so repeated queries for
// the same dead/slow name do not re-enter expensive recursive iteration.
func (s *Server) cacheResolveFailure(qname string, qtype uint16, ecsKey, viewName, geoTag string, m *dns.Msg) {
	if s == nil || s.cache == nil || m == nil {
		return
	}
	wire, err := resolver.PackResponse(m)
	if err != nil || len(wire) == 0 {
		return
	}
	s.cache.SetScoped(config.NormalizeName(qname), qtype, ecsKey, viewName, geoTag, wire, dns.RcodeServerFailure, 0)
}

// scheduleRefresh runs at most one background resolve per cache key to refresh stale/prefetch entries.
func (s *Server) scheduleRefresh(qname string, qtype uint16, ecsKey, viewName, geoTag string, sub *ecs.Subnet, orig *dns.Msg) {
	if s == nil || s.res == nil || s.cache == nil || orig == nil || len(orig.Question) == 0 {
		return
	}
	key := cache.KeyScoped(qname, qtype, ecsKey, viewName, geoTag)
	if _, loaded := s.refreshInflight.LoadOrStore(key, struct{}{}); loaded {
		return
	}
	metrics.CachePrefetch.Inc()
	req := orig.Copy()
	go func() {
		defer s.refreshInflight.Delete(key)
		ctx, cancel := context.WithTimeout(context.Background(), s.res.Timeout)
		defer cancel()
		resp, _, err := s.res.ResolveWithECS(ctx, req, sub)
		if err != nil || resp == nil {
			return
		}
		wire, err := resolver.PackResponse(resp)
		if err != nil {
			return
		}
		ttl := resolver.MinTTL(resp)
		s.cache.SetScoped(qname, qtype, ecsKey, viewName, geoTag, wire, resp.Rcode, ttl)
	}()
}

func (s *Server) storeAndWriteScoped(w dns.ResponseWriter, req, resp *dns.Msg, ecsSubnet, viewName, geoTag string) {
	resolver.PrepareClientResponse(req, resp, s.udpBufSize())
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
	var tsigMap map[string]string
	if s.tsig != nil && s.tsig.Len() > 0 {
		tsigMap = s.tsig.Map()
	}

	udpAddr := s.cfg.ListenAddr(s.cfg.Server.UDPPort)
	tcpAddr := s.cfg.ListenAddr(s.cfg.Server.TCPPort)

	errCh := make(chan error, 48)
	s.doqCtx, s.doqCancel = context.WithCancel(context.Background())

	accept := msgAcceptFunc
	invalid := func(m []byte, err error) {
		if s.log != nil {
			n := len(m)
			if n > 64 {
				n = 64
			}
			s.log.Warn("dns message rejected", "err", err, "bytes", len(m), "head", fmt.Sprintf("%x", m[:n]))
		}
		metrics.QueriesTotal.WithLabelValues("udp", "formerr").Inc()
	}

	if s.cfg.Server.TProxy {
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
		for i := 0; i < nUDP; i++ {
			pc, err := tproxy.ListenUDP("udp", udpAddr)
			if err != nil {
				return fmt.Errorf("tproxy udp %s shard %d: %w", udpAddr, i, err)
			}
			srv := &dns.Server{PacketConn: pc, Net: "udp", Handler: handler, UDPSize: int(s.udpBufSize()), MsgAcceptFunc: accept, MsgInvalidFunc: invalid, TsigSecret: tsigMap}
			if i == 0 {
				s.udp = srv
			}
			s.udps = append(s.udps, srv)
			idx := i
			go func() {
				s.log.Info("UDP listener starting", "addr", udpAddr, "tproxy", true, "shard", idx, "shards", nUDP)
				errCh <- srv.ActivateAndServe()
			}()
		}
		ln, err := tproxy.ListenTCP("tcp", tcpAddr)
		if err != nil {
			return fmt.Errorf("tproxy tcp %s: %w", tcpAddr, err)
		}
		s.tcp = &dns.Server{Listener: ln, Net: "tcp", Handler: handler, MsgAcceptFunc: accept, MsgInvalidFunc: invalid, TsigSecret: tsigMap}
		go func() {
			s.log.Info("TCP listener starting", "addr", tcpAddr, "tproxy", true)
			errCh <- s.tcp.ActivateAndServe()
		}()
	} else {
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
		s.tcp = &dns.Server{Addr: tcpAddr, Net: "tcp", Handler: handler, MsgAcceptFunc: accept, MsgInvalidFunc: invalid, TsigSecret: tsigMap}
		go func() {
			s.log.Info("TCP listener starting", "addr", tcpAddr)
			errCh <- s.tcp.ListenAndServe()
		}()
	}

	if s.tlsCfg != nil && s.cfg.Server.DoTPort > 0 {
		dotAddr := s.cfg.ListenAddr(s.cfg.Server.DoTPort)
		dotTLS := s.tlsCfg.Clone()
		dotTLS.NextProtos = []string{"dot"}
		s.dot = &dns.Server{Addr: dotAddr, Net: "tcp-tls", Handler: handler, TLSConfig: dotTLS, MsgAcceptFunc: accept, MsgInvalidFunc: invalid, TsigSecret: tsigMap}
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
		if s.dohHTTP3 != nil {
			s.doh3On = true
			go func() {
				s.log.Info("DoH3 (HTTP/3) listener starting", "addr", dohAddr)
				if err := s.dohHTTP3.ListenAndServe(); err != nil {
					s.log.Error("DoH3 stopped", "err", err)
					errCh <- err
				}
			}()
		}
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
	shutdownDNS := append([]*dns.Server{}, s.udps...)
	shutdownDNS = append(shutdownDNS, s.tcp, s.dot)
	if len(s.udps) == 0 && s.udp != nil {
		shutdownDNS = append([]*dns.Server{s.udp}, s.tcp, s.dot)
	}
	for _, srv := range shutdownDNS {
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
	if s.dohHTTP3 != nil {
		if e := s.dohHTTP3.Close(); e != nil && err == nil {
			err = e
		}
	}
	return err
}

func (s *Server) Stats() (queries uint64, uptime time.Duration) {
	return s.queries.Load(), time.Since(s.started)
}

func ednsHasCookie(opt *dns.OPT) bool {
	if opt == nil {
		return false
	}
	for _, o := range opt.Option {
		if _, ok := o.(*dns.EDNS0_COOKIE); ok {
			return true
		}
	}
	return false
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

func (s *Server) DoTEnabled() bool  { return s.dotOn }
func (s *Server) DoHEnabled() bool  { return s.dohOn }
func (s *Server) DoH3Enabled() bool { return s.doh3On }
func (s *Server) DoQEnabled() bool  { return s.doqOn }

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

func rpzRedirectRR(qname string, qtype uint16, target string) dns.RR {
	ip := net.ParseIP(strings.TrimSpace(target))
	if ip == nil {
		return nil
	}
	name := config.NormalizeName(qname)
	const ttl = uint32(60)
	if ip4 := ip.To4(); ip4 != nil {
		if qtype != dns.TypeA && qtype != dns.TypeANY {
			return nil
		}
		return &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
			A:   ip4,
		}
	}
	if qtype != dns.TypeAAAA && qtype != dns.TypeANY {
		return nil
	}
	return &dns.AAAA{
		Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
		AAAA: ip.To16(),
	}
}

func rpzCNAMERR(qname, target string) dns.RR {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil
	}
	return &dns.CNAME{
		Hdr: dns.RR_Header{
			Name:   config.NormalizeName(qname),
			Rrtype: dns.TypeCNAME,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		Target: config.NormalizeName(target),
	}
}

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
		if f.Forwarders == nil {
			f.Forwarders = append([]string(nil), s.cfg.Resolver.Forwarders...)
		}
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
	if s.res != nil {
		f.ECS = s.res.ECSEnabled
		f.ResolverMode = config.NormalizeResolverMode(s.res.Mode)
		f.ForwardOnFail = s.res.ForwardOnFail
		f.Forwarders = append([]string(nil), s.res.Forwarders...)
		f.ForwardZones = append([]config.ForwardZoneConfig(nil), s.res.ForwardZones...)
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
	if s.cfg != nil {
		s.cfg.RateLimit.Enabled = f.RateLimit
	}
	if s.res != nil {
		s.res.SetECSEnabled(f.ECS)
		s.res.SetMode(f.ResolverMode)
		s.res.SetForwardOnFail(f.ForwardOnFail)
		if f.Forwarders != nil {
			s.res.SetForwarders(f.Forwarders)
		}
		if f.ForwardZones != nil {
			s.res.SetForwardZones(f.ForwardZones)
		}
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
		s.cfg.KominfoSync.Enabled = f.KominfoSync
	}
	if s.kominfo != nil {
		s.kominfo.SetEnabled(f.KominfoSync)
	}
}

func (s *Server) SetQueryLogger(q *database.QueryLogger) { s.qlog = q }

func (s *Server) SetSecondary(m *secondary.Manager) { s.secondaryMgr = m }

func (s *Server) Secondary() *secondary.Manager { return s.secondaryMgr }

func (s *Server) SetKominfo(m *kominfo.Manager) { s.kominfo = m }

func (s *Server) Kominfo() *kominfo.Manager { return s.kominfo }

// SetRPZNotifyHandler registers a callback for inbound NOTIFY that matches an axfr RPZ feed zone.
func (s *Server) SetRPZNotifyHandler(fn func(zone string) bool) { s.onRPZNotify = fn }

// SetQueryACL replaces the live DNS query ACL (allow/deny CIDRs).
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
func (s *Server) QueryLogger() *database.QueryLogger { return s.qlog }

func (s *Server) Analytics() *analytics.Collector { return s.stats }
func (s *Server) Monitor() *monitor.Collector     { return s.mon }
func (s *Server) Allowlist() *allowlist.List      { return s.allow }
func (s *Server) Denylist() *denylist.List        { return s.deny }

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

// ApplyRateLimitConfig updates live limiter parameters and cfg snapshot.
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

// ServeDNSMsgFrom runs the DNS pipeline as if the query came from clientIP (DoH/DoQ).
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
