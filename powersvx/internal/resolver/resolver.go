// Package resolver is the hot path: RPZ check -> cache -> singleflight -> resolve
// (forward via health-checked upstream pool, or built-in recursive). Logging and
// per-qname metrics are kept off this path except low-cost atomic counters and
// sampled async logs.
package resolver

import (
	"errors"
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
}

func New(o Options) *Resolver {
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
	}
}

// Handle processes a query and returns the reply. A nil reply means "drop".
func (r *Resolver) Handle(req *dns.Msg) *dns.Msg {
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

	key := cacheKey(name, q.Qtype, q.Qclass)

	if resp := r.cache.Get(key, req); resp != nil {
		r.m.IncCacheHit()
		r.logSampled("cache-hit", name)
		return resp
	}
	r.m.IncCacheMiss()

	v, _, shared := r.group.Do(key, func() (interface{}, error) {
		resp, err := r.resolve(req)
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
func (r *Resolver) resolve(req *dns.Msg) (*dns.Msg, error) {
	if r.rec != nil {
		return r.rec.Resolve(req.Question[0])
	}
	if r.pool == nil {
		return nil, errors.New("no resolver backend configured")
	}
	m := req.Copy()
	m.Id = dns.Id()
	m.RecursionDesired = true
	if r.dnssec {
		m.SetEdns0(4096, true)
	}
	return r.pool.Exchange(m)
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
		resp, err := r.resolve(req)
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

func cacheKey(name string, qtype, qclass uint16) string {
	var b strings.Builder
	b.Grow(len(name) + 12)
	b.WriteString(name)
	b.WriteByte('|')
	b.WriteString(strconv.FormatUint(uint64(qtype), 10))
	b.WriteByte('|')
	b.WriteString(strconv.FormatUint(uint64(qclass), 10))
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
	qt, err := strconv.ParseUint(rest[:j], 10, 16)
	if err != nil {
		return "", 0, 0, false
	}
	qc, err := strconv.ParseUint(rest[j+1:], 10, 16)
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
