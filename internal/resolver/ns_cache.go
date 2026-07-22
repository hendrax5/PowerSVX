package resolver

import (
	"sync"
	"time"
)

type nsCacheEntry struct {
	addrs  []string
	expiry time.Time
}

// nsAddrCache memoizes NS hostname → A addresses for glue-less referrals.
type nsAddrCache struct {
	mu      sync.RWMutex
	m       map[string]nsCacheEntry
	maxSize int
}

func newNSAddrCache(max int) *nsAddrCache {
	if max <= 0 {
		max = 4096
	}
	return &nsAddrCache{m: make(map[string]nsCacheEntry), maxSize: max}
}

func (c *nsAddrCache) get(name string) []string {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	e, ok := c.m[name]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.expiry) {
		return nil
	}
	out := make([]string, len(e.addrs))
	copy(out, e.addrs)
	return out
}

func (c *nsAddrCache) put(name string, addrs []string, ttl time.Duration) {
	if c == nil || name == "" || len(addrs) == 0 {
		return
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= c.maxSize {
		// Drop arbitrary ~10% on overflow.
		n := 0
		for k := range c.m {
			delete(c.m, k)
			n++
			if n >= c.maxSize/10+1 {
				break
			}
		}
	}
	stored := make([]string, len(addrs))
	copy(stored, addrs)
	c.m[name] = nsCacheEntry{addrs: stored, expiry: time.Now().Add(ttl)}
}
