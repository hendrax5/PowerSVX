package cache

import (
	"encoding/binary"
	"hash/fnv"
	"sync"
	"sync/atomic"
	"time"
)

// HitState is the result of a scoped cache lookup.
type HitState int

const (
	Miss HitState = iota
	HitFresh
	HitStale
)

// Entry holds a pre-encoded DNS wire response ready to send.
type Entry struct {
	Wire       []byte
	Expiry     time.Time // fresh until
	StaleUntil time.Time // serve-stale until (may equal Expiry if stale disabled)
	Rcode      int
	// StoredTTL is the fresh lifetime used for prefetch thresholds.
	StoredTTL time.Duration
}

func (e *Entry) Expired() bool {
	return time.Now().After(e.Expiry)
}

func (e *Entry) StaleExpired() bool {
	until := e.StaleUntil
	if until.IsZero() {
		until = e.Expiry
	}
	return time.Now().After(until)
}

func (e *Entry) CloneWire() []byte {
	out := make([]byte, len(e.Wire))
	copy(out, e.Wire)
	return out
}

// RemainingFresh returns time until Expiry (0 if already expired).
func (e *Entry) RemainingFresh() time.Duration {
	d := time.Until(e.Expiry)
	if d < 0 {
		return 0
	}
	return d
}

// NeedsPrefetch is true when remaining fresh TTL is below pct of StoredTTL.
func (e *Entry) NeedsPrefetch(pct int) bool {
	if e == nil || pct <= 0 || e.StoredTTL <= 0 || e.Expired() {
		return false
	}
	thresh := e.StoredTTL * time.Duration(pct) / 100
	return e.RemainingFresh() <= thresh
}

// Key builds an FNV-64a cache key from qname + qtype.
func Key(name string, qtype uint16) uint64 {
	return KeyScoped(name, qtype, "", "", "")
}

// KeyScoped includes ECS subnet, split-horizon view, and geo tag for isolation.
func KeyScoped(name string, qtype uint16, ecsSubnet, viewName, geoTag string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], qtype)
	_, _ = h.Write(b[:])
	if ecsSubnet != "" {
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(ecsSubnet))
	}
	if viewName != "" {
		_, _ = h.Write([]byte{1})
		_, _ = h.Write([]byte(viewName))
	}
	if geoTag != "" {
		_, _ = h.Write([]byte{2})
		_, _ = h.Write([]byte(geoTag))
	}
	return h.Sum64()
}

// L1 is an in-process hot cache of pre-encoded responses.
type L1 struct {
	m       sync.Map // uint64 -> *Entry
	maxSize int64
	size    atomic.Int64
	hits    atomic.Uint64
	misses  atomic.Uint64
	stale   atomic.Uint64
}

func NewL1(maxEntries int) *L1 {
	if maxEntries <= 0 {
		maxEntries = 1_000_000
	}
	return &L1{maxSize: int64(maxEntries)}
}

func (c *L1) Get(key uint64) (*Entry, bool) {
	e, st := c.GetEx(key, false)
	return e, st == HitFresh
}

// GetEx returns fresh or optionally stale entries.
func (c *L1) GetEx(key uint64, allowStale bool) (*Entry, HitState) {
	v, ok := c.m.Load(key)
	if !ok {
		c.misses.Add(1)
		return nil, Miss
	}
	e := v.(*Entry)
	now := time.Now()
	if now.Before(e.Expiry) {
		c.hits.Add(1)
		return e, HitFresh
	}
	staleUntil := e.StaleUntil
	if staleUntil.IsZero() {
		staleUntil = e.Expiry
	}
	if allowStale && now.Before(staleUntil) {
		c.stale.Add(1)
		return e, HitStale
	}
	c.m.Delete(key)
	c.size.Add(-1)
	c.misses.Add(1)
	return nil, Miss
}

func (c *L1) Set(key uint64, wire []byte, ttl time.Duration, rcode int) {
	c.SetStale(key, wire, ttl, 0, rcode)
}

// SetStale stores wire with fresh ttl and optional extra stale window after expiry.
func (c *L1) SetStale(key uint64, wire []byte, ttl, staleTTL time.Duration, rcode int) {
	if ttl <= 0 {
		ttl = time.Second
	}
	stored := make([]byte, len(wire))
	copy(stored, wire)
	exp := time.Now().Add(ttl)
	staleUntil := exp
	if staleTTL > 0 {
		staleUntil = exp.Add(staleTTL)
	}
	e := &Entry{
		Wire:       stored,
		Expiry:     exp,
		StaleUntil: staleUntil,
		Rcode:      rcode,
		StoredTTL:  ttl,
	}
	if _, loaded := c.m.Swap(key, e); !loaded {
		n := c.size.Add(1)
		if n > c.maxSize {
			c.evictApprox()
		}
	}
}

func (c *L1) evictApprox() {
	deleted := 0
	c.m.Range(func(k, v any) bool {
		e := v.(*Entry)
		if e.StaleExpired() {
			c.m.Delete(k)
			c.size.Add(-1)
			deleted++
		}
		return deleted < 64
	})
	if deleted > 0 {
		return
	}
	c.m.Range(func(k, _ any) bool {
		c.m.Delete(k)
		c.size.Add(-1)
		deleted++
		return deleted < 64
	})
}

func (c *L1) Stats() (hits, misses, size uint64) {
	return c.hits.Load(), c.misses.Load(), uint64(c.size.Load())
}

func (c *L1) Close() error { return nil }

// WireBufferPool recycles byte slices for DNS packet I/O.
var WireBufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 1232)
		return &b
	},
}

func GetBuffer() *[]byte {
	return WireBufferPool.Get().(*[]byte)
}

func PutBuffer(b *[]byte) {
	*b = (*b)[:0]
	WireBufferPool.Put(b)
}
