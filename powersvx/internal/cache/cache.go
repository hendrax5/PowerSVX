// Package cache implements a sharded DNS answer cache with separate positive
// and negative entries (Phase 3). Sharding reduces lock contention under high
// QPS; each shard has an independent mutex so unrelated qnames don't serialize.
package cache

import (
	"hash/fnv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

type entry struct {
	msg        *dns.Msg
	storedAt   int64 // unix seconds
	ttl        uint32
	negative   bool
	hits       uint32 // atomic; popularity for prefetch
	refreshing uint32 // atomic flag; 1 while a prefetch is queued/in-flight
}

type shard struct {
	mu  sync.RWMutex
	m   map[string]*entry
	cap int
}

type Cache struct {
	shards []*shard
	mask   uint32
	posMax uint32
	negMax uint32

	// Prefetch (refresh hot entries just before expiry).
	refresh    func(string) // set via EnablePrefetch
	prefetchCh chan string
	window     uint32 // seconds-before-expiry to trigger refresh
	minHits    uint32

	// Serve-stale (RFC 8767): keep expired entries for staleMax seconds and
	// hand them out with a short staleTTL when the upstream can't be reached.
	staleMax uint32
	staleTTL uint32
}

// EnableServeStale turns on RFC 8767 serve-stale. maxSec is how long past expiry
// an entry is retained; ttlSec is the short TTL applied to stale answers.
func (c *Cache) EnableServeStale(maxSec, ttlSec int) {
	c.staleMax = uint32(maxSec)
	c.staleTTL = uint32(ttlSec)
	if c.staleTTL == 0 {
		c.staleTTL = 30
	}
}

// New creates a cache with `shards` shards (rounded up to a power of two) and a
// per-shard entry cap. posMax/negMax clamp stored TTLs (seconds).
func New(shards, perShardCap, posMax, negMax int) *Cache {
	n := nextPow2(shards)
	c := &Cache{
		shards: make([]*shard, n),
		mask:   uint32(n - 1),
		posMax: uint32(posMax),
		negMax: uint32(negMax),
	}
	for i := range c.shards {
		c.shards[i] = &shard{m: make(map[string]*entry, perShardCap/4+1), cap: perShardCap}
	}
	return c
}

func (c *Cache) shardFor(key string) *shard {
	h := fnv.New32a()
	h.Write([]byte(key))
	return c.shards[h.Sum32()&c.mask]
}

// Get returns a cached reply cloned for `req` (id/question rewritten, TTLs aged)
// or nil on miss/expiry.
func (c *Cache) Get(key string, req *dns.Msg) *dns.Msg {
	s := c.shardFor(key)
	s.mu.RLock()
	e, ok := s.m[key]
	s.mu.RUnlock()
	if !ok {
		return nil
	}
	now := time.Now().Unix()
	elapsed := now - e.storedAt
	if elapsed >= int64(e.ttl) {
		// Fresh TTL expired. Keep the entry within the serve-stale window so
		// GetStale can hand it out on upstream failure; only drop beyond it.
		if c.staleMax == 0 || elapsed >= int64(e.ttl)+int64(c.staleMax) {
			s.mu.Lock()
			if cur, ok := s.m[key]; ok && cur == e {
				delete(s.m, key)
			}
			s.mu.Unlock()
		}
		return nil
	}
	remaining := e.ttl - uint32(elapsed)
	c.maybePrefetch(key, e, remaining)
	return buildReply(req, e.msg, remaining)
}

// GetStale returns an expired-but-within-window entry with a short TTL, used as
// a last resort when live resolution fails (RFC 8767). Returns nil if stale is
// disabled or nothing usable is cached.
func (c *Cache) GetStale(key string, req *dns.Msg) *dns.Msg {
	if c.staleMax == 0 {
		return nil
	}
	s := c.shardFor(key)
	s.mu.RLock()
	e, ok := s.m[key]
	s.mu.RUnlock()
	if !ok {
		return nil
	}
	now := time.Now().Unix()
	elapsed := now - e.storedAt
	if elapsed < int64(e.ttl) {
		return buildReply(req, e.msg, e.ttl-uint32(elapsed)) // still fresh
	}
	if elapsed >= int64(e.ttl)+int64(c.staleMax) {
		s.mu.Lock()
		if cur, ok := s.m[key]; ok && cur == e {
			delete(s.m, key)
		}
		s.mu.Unlock()
		return nil
	}
	return buildReply(req, e.msg, c.staleTTL)
}

// EnablePrefetch starts background workers that refresh popular entries shortly
// before they expire, so bursts of look-alike traffic (or a re-query of a hot
// name) hit warm cache instead of falling through to a cache-miss latency
// cliff. refresh(key) should re-resolve and Store the entry.
func (c *Cache) EnablePrefetch(window, minHits, workers int, refresh func(string)) {
	if refresh == nil || window <= 0 {
		return
	}
	c.window = uint32(window)
	c.minHits = uint32(minHits)
	c.refresh = refresh
	c.prefetchCh = make(chan string, 8192)
	if workers < 1 {
		workers = 1
	}
	for i := 0; i < workers; i++ {
		go c.prefetchLoop()
	}
}

func (c *Cache) prefetchLoop() {
	for key := range c.prefetchCh {
		c.refresh(key)
	}
}

// maybePrefetch enqueues a refresh at most once per entry lifetime, only for
// entries within the refresh window and above the popularity threshold. The
// enqueue is non-blocking; a full queue simply drops the hint (the entry still
// gets refreshed naturally by the next real miss).
func (c *Cache) maybePrefetch(key string, e *entry, remaining uint32) {
	if c.refresh == nil {
		return
	}
	h := atomic.AddUint32(&e.hits, 1)
	if remaining > c.window || h < c.minHits {
		return
	}
	if !atomic.CompareAndSwapUint32(&e.refreshing, 0, 1) {
		return
	}
	select {
	case c.prefetchCh <- key:
	default:
		atomic.StoreUint32(&e.refreshing, 0)
	}
}

// Store caches resp under key. positive vs negative is decided by the caller.
func (c *Cache) Store(key string, resp *dns.Msg, negative bool) {
	ttl := minTTL(resp)
	if negative {
		if ttl == 0 {
			ttl = 60
		}
		if ttl > c.negMax {
			ttl = c.negMax
		}
	} else {
		if ttl == 0 {
			return // uncacheable
		}
		if ttl > c.posMax {
			ttl = c.posMax
		}
	}

	e := &entry{
		msg:      resp.Copy(),
		storedAt: time.Now().Unix(),
		ttl:      ttl,
		negative: negative,
	}
	s := c.shardFor(key)
	s.mu.Lock()
	if len(s.m) >= s.cap {
		// Simple bounded eviction: drop one arbitrary entry. Cheap and avoids
		// pointer-heavy LRU bookkeeping on the hot path.
		for k := range s.m {
			delete(s.m, k)
			break
		}
	}
	s.m[key] = e
	s.mu.Unlock()
}

// Len returns approximate total entries (diagnostic only).
func (c *Cache) Len() int {
	n := 0
	for _, s := range c.shards {
		s.mu.RLock()
		n += len(s.m)
		s.mu.RUnlock()
	}
	return n
}

func buildReply(req, cached *dns.Msg, ttl uint32) *dns.Msg {
	out := cached.Copy()
	out.Id = req.Id
	out.Question = req.Question
	setTTL(out.Answer, ttl)
	setTTL(out.Ns, ttl)
	setTTL(out.Extra, ttl)
	return out
}

func setTTL(rrs []dns.RR, ttl uint32) {
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeOPT {
			continue
		}
		rr.Header().Ttl = ttl
	}
}

func minTTL(m *dns.Msg) uint32 {
	var min uint32
	first := true
	consider := func(rrs []dns.RR) {
		for _, rr := range rrs {
			if rr.Header().Rrtype == dns.TypeOPT {
				continue
			}
			t := rr.Header().Ttl
			if first || t < min {
				min = t
				first = false
			}
		}
	}
	consider(m.Answer)
	// For negative responses the authoritative TTL sits in the SOA (Ns).
	if len(m.Answer) == 0 {
		for _, rr := range m.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				if first || soa.Hdr.Ttl < min {
					min = soa.Hdr.Ttl
					first = false
				}
				if soa.Minttl < min || first {
					// negative TTL = min(SOA.TTL, SOA.MINIMUM) per RFC 2308
					if soa.Minttl < min {
						min = soa.Minttl
					}
					first = false
				}
			}
		}
	}
	if first {
		return 0
	}
	return min
}

func nextPow2(n int) int {
	if n < 1 {
		return 1
	}
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}
