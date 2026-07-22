package rpz

import (
	"sync"
	"sync/atomic"
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
