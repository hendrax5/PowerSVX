// Package cache implements a sharded DNS answer cache with separate positive
// and negative entries (Phase 3). Sharding reduces lock contention under high
// QPS; each shard has an independent mutex so unrelated qnames don't serialize.
package cache

import (
	"hash/fnv"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type entry struct {
	msg      *dns.Msg
	storedAt int64 // unix seconds
	ttl      uint32
	negative bool
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
		// Lazily drop expired entry.
		s.mu.Lock()
		if cur, ok := s.m[key]; ok && cur == e {
			delete(s.m, key)
		}
		s.mu.Unlock()
		return nil
	}
	remaining := e.ttl - uint32(elapsed)
	return buildReply(req, e.msg, remaining)
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
