package dnssec

import (
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const nsecCacheCap = 50_000

type nsecEntry struct {
	rr     *dns.NSEC
	expiry int64
}

// NSECCache stores DNSSEC-validated NSEC records so RFC 8198 aggressive use
// can synthesize NXDOMAIN for any name inside a proven gap, without upstream
// traffic. NSEC3 is not cached (opt-out / closest-encloser is a later step).
type NSECCache struct {
	mu sync.RWMutex
	m  map[string]nsecEntry // key: owner name
}

func NewNSECCache() *NSECCache {
	return &NSECCache{m: make(map[string]nsecEntry)}
}

// AddFrom stores NSEC RRs from an authority section. Caller must only pass
// records from an authenticated (AD) denial.
func (c *NSECCache) AddFrom(ns []dns.RR) {
	if c == nil {
		return
	}
	now := time.Now().Unix()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) > nsecCacheCap {
		c.m = make(map[string]nsecEntry)
	}
	for _, rr := range ns {
		n, ok := rr.(*dns.NSEC)
		if !ok || n == nil {
			continue
		}
		cp, _ := dns.Copy(n).(*dns.NSEC)
		if cp == nil {
			continue
		}
		c.m[strings.ToLower(n.Hdr.Name)] = nsecEntry{
			rr:     cp,
			expiry: now + int64(n.Hdr.Ttl),
		}
	}
}

// Cover returns a still-valid NSEC proving qname does not exist, or nil.
// The returned RR is a copy; the caller may put it on the wire.
func (c *NSECCache) Cover(qname string) *dns.NSEC {
	if c == nil {
		return nil
	}
	now := time.Now().Unix()
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, e := range c.m {
		if e.expiry <= now || e.rr == nil {
			continue
		}
		if nsecGapCovers(e.rr.Hdr.Name, e.rr.NextDomain, qname) {
			cp, _ := dns.Copy(e.rr).(*dns.NSEC)
			return cp
		}
	}
	return nil
}

// canonKey is DNSSEC canonical order: labels reversed, NUL-separated, lowercased.
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

func nsecGapCovers(owner, next, qname string) bool {
	// RFC 8198 only proves gaps between owner names in one zone.
	// A TLD-apex NSEC (com. → commbank.) must not NXDOMAIN google.com.
	if parentName(owner) != parentName(qname) || parentName(next) != parentName(owner) {
		return false
	}
	o, n, q := canonKey(owner), canonKey(next), canonKey(qname)
	if q == o {
		return false
	}
	if o < n {
		return o < q && q < n
	}
	return q > o || q < n
}

func parentName(name string) string {
	name = strings.ToLower(dns.Fqdn(name))
	if name == "." {
		return "."
	}
	labels := dns.SplitDomainName(name)
	if len(labels) <= 1 {
		return "."
	}
	return strings.Join(labels[1:], ".") + "."
}
