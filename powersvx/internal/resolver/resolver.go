// Package resolver is the hot path: RPZ check -> cache -> singleflight -> resolve
// (forward via health-checked upstream pool, or built-in recursive). Logging and
// per-qname metrics are kept off this path except low-cost atomic counters and
// sampled async logs.
package resolver

import (
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"

	"powersvx/internal/cache"
	"powersvx/internal/logx"
	"powersvx/internal/metrics"
	"powersvx/internal/recursive"
	"powersvx/internal/rpz"
	"powersvx/internal/upstream"
)

type Resolver struct {
	cache  *cache.Cache
	rpz    *rpz.Matcher
	rpzOn  bool
	pool   *upstream.Pool
	rec    *recursive.Recursive
	group      singleflight.Group
	m          *metrics.Metrics
	log        *logx.Logger
	dnssec     bool
	serveStale bool
	ecsOn      bool
	ecsV4      uint8
	ecsV6      uint8
}

type Options struct {
	Cache      *cache.Cache
	RPZ        *rpz.Matcher
	RPZOn      bool
	Pool       *upstream.Pool       // forwarding mode
	Recursive  *recursive.Recursive // recursive mode (takes precedence if set)
	Metrics    *metrics.Metrics
	Logger     *logx.Logger
	DNSSEC     bool
	ServeStale bool
	ECSEnabled bool
	ECSV4      uint8
	ECSV6      uint8
}

func New(o Options) *Resolver {
	if o.ECSV4 == 0 {
		o.ECSV4 = 24
	}
	if o.ECSV6 == 0 {
		o.ECSV6 = 56
	}
	return &Resolver{
		cache:      o.Cache,
		rpz:        o.RPZ,
		rpzOn:      o.RPZOn,
		pool:       o.Pool,
		rec:        o.Recursive,
		m:          o.Metrics,
		log:        o.Logger,
		dnssec:     o.DNSSEC,
		serveStale: o.ServeStale,
		ecsOn:      o.ECSEnabled,
		ecsV4:      o.ECSV4,
		ecsV6:      o.ECSV6,
	}
}

// Handle processes a query and returns the reply. A nil reply means "drop".
func (r *Resolver) Handle(req *dns.Msg, clientIP net.IP) *dns.Msg {
	r.m.IncQueries()
	if len(req.Question) == 0 {
		return errReply(req, dns.RcodeFormatError)
	}
	q := req.Question[0]
	name := strings.ToLower(q.Name)

	if r.rpzOn {
		switch r.rpz.Lookup(name) {
		case rpz.ActionNXDOMAIN:
			r.m.IncRPZBlock()
			r.logSampled("rpz-block nxdomain", name)
			return errReply(req, dns.RcodeNameError)
		case rpz.ActionNODATA:
			r.m.IncRPZBlock()
			r.logSampled("rpz-block nodata", name)
			resp := new(dns.Msg)
			resp.SetReply(req)
			resp.RecursionAvailable = true
			return resp
		case rpz.ActionDrop:
			r.m.IncRPZBlock()
			r.logSampled("rpz-drop", name)
			return nil
		}
	}

	// EDNS Client Subnet: pass through a client-provided ECS, else synthesize
	// one from the client's IP so CDN upstreams return geo-correct answers.
	var ecs *dns.EDNS0_SUBNET
	ecsKey := ""
	if r.ecsOn {
		ecs = r.buildECS(req, clientIP)
		if ecs != nil {
			ecsKey = ecsNet(ecs)
		}
	}

	key := cacheKey(name, q.Qtype, q.Qclass, ecsKey)

	if resp := r.cache.Get(key, req); resp != nil {
		r.m.IncCacheHit()
		r.logSampled("cache-hit", name)
		return resp
	}
	r.m.IncCacheMiss()

	v, _, shared := r.group.Do(key, func() (interface{}, error) {
		resp, err := r.resolve(req, ecs)
		if err != nil {
			return nil, err
		}
		r.storeResult(key, resp)
		return resp, nil
	})
	if shared {
		r.m.IncCoalesced()
	}
	if v == nil {
		// Live resolution failed: try serving a stale answer (RFC 8767) before
		// giving up with SERVFAIL, so brief upstream blips don't break clients.
		if r.serveStale {
			if stale := r.cache.GetStale(key, req); stale != nil {
				r.m.IncServedStale()
				stale.RecursionAvailable = true
				r.logSampled("served-stale", name)
				return stale
			}
		}
		r.m.IncServFail()
		r.logSampled("servfail", name)
		return errReply(req, dns.RcodeServerFailure)
	}

	answer := v.(*dns.Msg)
	if answer.Rcode == dns.RcodeNameError {
		r.m.IncNXDomain()
	}
	out := answer.Copy()
	out.Id = req.Id
	out.Question = req.Question
	out.RecursionAvailable = true
	r.logSampled("cache-miss", name)
	return out
}

func (r *Resolver) storeResult(key string, resp *dns.Msg) {
	negative := resp.Rcode == dns.RcodeNameError || (resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0)
	r.cache.Store(key, resp, negative)
}

// resolve dispatches to the recursive engine or the forwarding pool.
func (r *Resolver) resolve(req *dns.Msg, ecs *dns.EDNS0_SUBNET) (*dns.Msg, error) {
	if r.rec != nil {
		return r.rec.Resolve(req.Question[0], ecs)
	}
	if r.pool == nil {
		return nil, errors.New("no resolver backend configured")
	}
	m := new(dns.Msg)
	m.SetQuestion(req.Question[0].Name, req.Question[0].Qtype)
	m.Question[0].Qclass = req.Question[0].Qclass
	m.Id = dns.Id()
	m.RecursionDesired = true
	setEDNS(m, r.dnssec, ecs)
	return r.pool.Exchange(m)
}

// buildECS returns the client's ECS option: pass through if the client sent one,
// otherwise synthesize from the client IP masked to the configured prefix.
func (r *Resolver) buildECS(req *dns.Msg, clientIP net.IP) *dns.EDNS0_SUBNET {
	if o := req.IsEdns0(); o != nil {
		for _, e := range o.Option {
			if s, ok := e.(*dns.EDNS0_SUBNET); ok {
				return s
			}
		}
	}
	if clientIP == nil || clientIP.IsLoopback() {
		return nil
	}
	e := &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, SourceScope: 0}
	if v4 := clientIP.To4(); v4 != nil {
		e.Family = 1
		e.SourceNetmask = r.ecsV4
		e.Address = v4.Mask(net.CIDRMask(int(r.ecsV4), 32))
	} else {
		e.Family = 2
		e.SourceNetmask = r.ecsV6
		e.Address = clientIP.Mask(net.CIDRMask(int(r.ecsV6), 128))
	}
	return e
}

// setEDNS installs a single OPT with the DO bit and (optionally) an ECS option.
func setEDNS(m *dns.Msg, do bool, ecs *dns.EDNS0_SUBNET) {
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	opt.SetUDPSize(4096)
	opt.SetDo(do)
	if ecs != nil {
		opt.Option = append(opt.Option, ecs)
	}
	m.Extra = append(m.Extra, opt)
}

func ecsNet(e *dns.EDNS0_SUBNET) string {
	return e.Address.String() + "/" + strconv.Itoa(int(e.SourceNetmask))
}

func (r *Resolver) logSampled(event, name string) {
	if r.log == nil {
		return
	}
	r.log.Log(event + " " + name)
}

// Prefetch re-resolves a cache key and re-stores the answer (used by cache
// prefetch workers). Shares the singleflight group with live misses.
func (r *Resolver) Prefetch(key string) {
	name, qtype, qclass, ok := parseKey(key)
	if !ok {
		return
	}
	req := new(dns.Msg)
	req.SetQuestion(name, qtype)
	req.Question[0].Qclass = qclass
	req.RecursionDesired = true

	_, _, _ = r.group.Do(key, func() (interface{}, error) {
		resp, err := r.resolve(req, nil)
		if err != nil {
			return nil, err
		}
		r.storeResult(key, resp)
		return resp, nil
	})
	if r.m != nil {
		r.m.IncPrefetch()
	}
}

func cacheKey(name string, qtype, qclass uint16, ecs string) string {
	var b strings.Builder
	b.Grow(len(name) + 12 + len(ecs))
	b.WriteString(name)
	b.WriteByte('|')
	b.WriteString(strconv.FormatUint(uint64(qtype), 10))
	b.WriteByte('|')
	b.WriteString(strconv.FormatUint(uint64(qclass), 10))
	if ecs != "" {
		b.WriteByte('|')
		b.WriteString(ecs)
	}
	return b.String()
}

func parseKey(key string) (string, uint16, uint16, bool) {
	i := strings.IndexByte(key, '|')
	if i < 0 {
		return "", 0, 0, false
	}
	rest := key[i+1:]
	j := strings.IndexByte(rest, '|')
	if j < 0 {
		return "", 0, 0, false
	}
	qcPart := rest[j+1:]
	if k := strings.IndexByte(qcPart, '|'); k >= 0 { // drop optional ECS suffix
		qcPart = qcPart[:k]
	}
	qt, err := strconv.ParseUint(rest[:j], 10, 16)
	if err != nil {
		return "", 0, 0, false
	}
	qc, err := strconv.ParseUint(qcPart, 10, 16)
	if err != nil {
		return "", 0, 0, false
	}
	return key[:i], uint16(qt), uint16(qc), true
}

func errReply(req *dns.Msg, rcode int) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetRcode(req, rcode)
	resp.RecursionAvailable = true
	return resp
}
