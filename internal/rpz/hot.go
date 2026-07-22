package rpz

import (
	"sync"
	"sync/atomic"
	"time"
)

// hotCache keeps recent exact RPZ hits in RAM (cold-tier mode).
type hotCache struct {
	m   sync.Map // string -> Hit
	n   atomic.Int64
	max int64
}

func newHot(max int) *hotCache {
	if max <= 0 {
		max = 500_000
	}
	return &hotCache{max: int64(max)}
}

func (h *hotCache) Get(name string) (Hit, bool) {
	if h == nil {
		return Hit{}, false
	}
	v, ok := h.m.Load(name)
	if !ok {
		return Hit{}, false
	}
	return v.(Hit), true
}

func (h *hotCache) Set(name string, hit Hit) {
	if h == nil || name == "" {
		return
	}
	if _, loaded := h.m.Swap(name, hit); !loaded {
		n := h.n.Add(1)
		if n > h.max {
			h.evictApprox()
		}
	}
}

func (h *hotCache) evictApprox() {
	deleted := 0
	h.m.Range(func(k, _ any) bool {
		h.m.Delete(k)
		h.n.Add(-1)
		deleted++
		return deleted < 256
	})
}

// negCache remembers recent Bloom false-positives (Badger miss) to skip disk.
// Does not affect correctness: wildcards still checked; positives still verified.
type negCache struct {
	m   sync.Map // string -> time.Time expiry
	n   atomic.Int64
	max int64
	ttl time.Duration
}

func newNeg(max int, ttl time.Duration) *negCache {
	if max <= 0 {
		max = 500_000
	}
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &negCache{max: int64(max), ttl: ttl}
}

func (n *negCache) Has(name string) bool {
	if n == nil {
		return false
	}
	v, ok := n.m.Load(name)
	if !ok {
		return false
	}
	exp := v.(time.Time)
	if time.Now().After(exp) {
		n.m.Delete(name)
		n.n.Add(-1)
		return false
	}
	return true
}

func (n *negCache) Set(name string) {
	if n == nil || name == "" {
		return
	}
	_, loaded := n.m.Swap(name, time.Now().Add(n.ttl))
	if !loaded {
		c := n.n.Add(1)
		if c > n.max {
			deleted := 0
			n.m.Range(func(k, _ any) bool {
				n.m.Delete(k)
				n.n.Add(-1)
				deleted++
				return deleted < 256
			})
		}
	}
}
