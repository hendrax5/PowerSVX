package recursive

import (
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// nsecCache stores DNSSEC-validated NSEC records so that RFC 8198 "aggressive
// use" can synthesize NXDOMAIN for any name that falls inside a proven gap,
// without hitting the network. Only NSEC (not NSEC3) is handled here.
type nsecEntry struct {
	rr     *dns.NSEC
	expiry int64
}

type nsecCache struct {
	mu sync.RWMutex
	m  map[string]nsecEntry // key: owner name
}

func newNSECCache() *nsecCache { return &nsecCache{m: make(map[string]nsecEntry)} }

func (c *nsecCache) addFrom(ns []dns.RR) {
	now := time.Now().Unix()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) > 50000 {
		c.m = make(map[string]nsecEntry)
	}
	for _, rr := range ns {
		if n, ok := rr.(*dns.NSEC); ok {
			c.m[strings.ToLower(n.Hdr.Name)] = nsecEntry{
				rr:     n,
				expiry: now + int64(n.Hdr.Ttl),
			}
		}
	}
}

// cover returns a still-valid NSEC entry proving qname does not exist, or nil.
func (c *nsecCache) cover(qname string) *nsecEntry {
	now := time.Now().Unix()
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, e := range c.m {
		if e.expiry <= now {
			continue
		}
		// A matching owner does not prove non-existence (the name exists); only
		// a covering gap does.
		if nsecCovers(e.rr.Hdr.Name, e.rr.NextDomain, qname) {
			cp := e
			return &cp
		}
	}
	return nil
}

// canonKey returns a comparable form for DNSSEC canonical name ordering
// (labels reversed, NUL-separated, lowercased).
func canonKey(name string) string {
	name = strings.ToLower(strings.TrimSuffix(dns.Fqdn(name), "."))
	if name == "" {
		return ""
	}
	labels := strings.Split(name, ".")
	var b strings.Builder
	for i := len(labels) - 1; i >= 0; i-- {
		b.WriteString(labels[i])
		b.WriteByte(0)
	}
	return b.String()
}

func nsecCovers(owner, next, qname string) bool {
	o, n, q := canonKey(owner), canonKey(next), canonKey(qname)
	if q == o { // exact owner: the name exists, not covered
		return false
	}
	if o < n {
		return o < q && q < n
	}
	// Wraparound at the zone apex (next sorts before owner).
	return q > o || q < n
}
