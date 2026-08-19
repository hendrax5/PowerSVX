// Package resolver is the hot path: RPZ check -> cache -> singleflight upstream
// forward -> cache store. Query logging and per-qname metrics are deliberately
// kept off this path except as low-cost atomic counters and sampled async logs.
package resolver

import (
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"

	"powersvx/internal/cache"
	"powersvx/internal/logx"
	"powersvx/internal/metrics"
	"powersvx/internal/rpz"
)

type Resolver struct {
	cache     *cache.Cache
	rpz       *rpz.Matcher
	upstreams []string
	udp       *dns.Client
	tcp       *dns.Client
	group     singleflight.Group
	m         *metrics.Metrics
	log       *logx.Logger
	dnssec    bool
	rpzOn     bool
}

type Options struct {
	Cache     *cache.Cache
	RPZ       *rpz.Matcher
	RPZOn     bool
	Upstreams []string
	Metrics   *metrics.Metrics
	Logger    *logx.Logger
	DNSSEC    bool
	Timeout   time.Duration
}

func New(o Options) *Resolver {
	if o.Timeout == 0 {
		o.Timeout = 2 * time.Second
	}
	return &Resolver{
		cache:     o.Cache,
		rpz:       o.RPZ,
		rpzOn:     o.RPZOn,
		upstreams: o.Upstreams,
		udp:       &dns.Client{Net: "udp", Timeout: o.Timeout},
		tcp:       &dns.Client{Net: "tcp", Timeout: o.Timeout},
		m:         o.Metrics,
		log:       o.Logger,
		dnssec:    o.DNSSEC,
	}
}

// Handle processes a query and returns the reply. A nil reply means "drop the
// packet" (RPZ drop action).
func (r *Resolver) Handle(req *dns.Msg) *dns.Msg {
	r.m.IncQueries()
	if len(req.Question) == 0 {
		return errReply(req, dns.RcodeFormatError)
	}
	q := req.Question[0]
	name := strings.ToLower(q.Name)

	// --- RPZ (Phase 3): immutable, lock-free, allocation-free lookup ---
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
			return resp
		case rpz.ActionDrop:
			r.m.IncRPZBlock()
			r.logSampled("rpz-drop", name)
			return nil
		}
	}

	key := cacheKey(name, q.Qtype, q.Qclass)

	// --- Cache (Phase 3): sharded lookup ---
	if resp := r.cache.Get(key, req); resp != nil {
		r.m.IncCacheHit()
		r.logSampled("cache-hit", name)
		return resp
	}
	r.m.IncCacheMiss()

	// --- Singleflight (Phase 3): coalesce identical concurrent misses ---
	v, _, shared := r.group.Do(key, func() (interface{}, error) {
		resp, err := r.forward(req)
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
		r.m.IncServFail()
		r.logSampled("servfail", name)
		return errReply(req, dns.RcodeServerFailure)
	}

	upstream := v.(*dns.Msg)
	if upstream.Rcode == dns.RcodeNameError {
		r.m.IncNXDomain()
	}
	// Clone for this requester and rewrite id/question.
	out := upstream.Copy()
	out.Id = req.Id
	out.Question = req.Question
	r.logSampled("cache-miss", name)
	return out
}

func (r *Resolver) storeResult(key string, resp *dns.Msg) {
	negative := resp.Rcode == dns.RcodeNameError || (resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0)
	r.cache.Store(key, resp, negative)
}

func (r *Resolver) forward(req *dns.Msg) (*dns.Msg, error) {
	m := req.Copy()
	m.Id = dns.Id()
	m.RecursionDesired = true
	if r.dnssec {
		m.SetEdns0(4096, true)
	}

	var lastErr error
	for _, up := range r.upstreams {
		resp, _, err := r.udp.Exchange(m, up)
		if err != nil {
			lastErr = err
			r.m.IncUpstreamErr()
			continue
		}
		if resp.Truncated {
			// TCP fallback on truncation (Phase edge case).
			r.m.IncTCP()
			resp2, _, err2 := r.tcp.Exchange(m, up)
			if err2 != nil {
				lastErr = err2
				r.m.IncUpstreamErr()
				continue
			}
			resp = resp2
		}
		return resp, nil
	}
	return nil, lastErr
}

func (r *Resolver) logSampled(event, name string) {
	if r.log == nil {
		return
	}
	r.log.Log(event + " " + name)
}

// cacheKey builds a compact key: name is already lowercased. Avoids fmt on the
// hot path.
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

func errReply(req *dns.Msg, rcode int) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetRcode(req, rcode)
	return resp
}

// Prefetch re-resolves a cache key and re-stores the answer. Invoked by the
// cache's background prefetch workers for popular, near-expiry entries. It
// shares the singleflight group with live misses so a concurrent real miss and
// a prefetch never double-hit the upstream.
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
		resp, err := r.forward(req)
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

// parseKey reverses cacheKey: "name|qtype|qclass".
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
