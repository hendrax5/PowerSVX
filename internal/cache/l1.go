package cache

import (
	"encoding/binary"
	"hash/fnv"
	"sync"
	"sync/atomic"
	"time"
)

// Entry holds a pre-encoded DNS wire response ready to send.
type Entry struct {
	Wire   []byte
	Expiry time.Time
	Rcode  int
}

func (e *Entry) Expired() bool {
	return time.Now().After(e.Expiry)
}

func (e *Entry) CloneWire() []byte {
	out := make([]byte, len(e.Wire))
	copy(out, e.Wire)
	return out
}

// Key builds an FNV-64a cache key from qname + qtype.
func Key(name string, qtype uint16) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], qtype)
	_, _ = h.Write(b[:])
	return h.Sum64()
}

// L1 is an in-process hot cache of pre-encoded responses.
type L1 struct {
	m       sync.Map // uint64 -> *Entry
	maxSize int64
	size    atomic.Int64
	hits    atomic.Uint64
	misses  atomic.Uint64
}

func NewL1(maxEntries int) *L1 {
	if maxEntries <= 0 {
		maxEntries = 1_000_000
	}
	return &L1{maxSize: int64(maxEntries)}
}

func (c *L1) Get(key uint64) (*Entry, bool) {
	v, ok := c.m.Load(key)
	if !ok {
		c.misses.Add(1)
		return nil, false
	}
	e := v.(*Entry)
	if e.Expired() {
		c.m.Delete(key)
		c.size.Add(-1)
		c.misses.Add(1)
		return nil, false
	}
	c.hits.Add(1)
	return e, true
}

func (c *L1) Set(key uint64, wire []byte, ttl time.Duration, rcode int) {
	if ttl <= 0 {
		ttl = time.Second
	}
	stored := make([]byte, len(wire))
	copy(stored, wire)
	e := &Entry{
		Wire:   stored,
		Expiry: time.Now().Add(ttl),
		Rcode:  rcode,
	}
	if _, loaded := c.m.Swap(key, e); !loaded {
		n := c.size.Add(1)
		if n > c.maxSize {
			c.evictApprox()
		}
	}
}

func (c *L1) evictApprox() {
	// Approximate eviction: delete first expired or a few arbitrary keys.
	deleted := 0
	c.m.Range(func(k, v any) bool {
		e := v.(*Entry)
		if e.Expired() {
			c.m.Delete(k)
			c.size.Add(-1)
			deleted++
		}
		return deleted < 64
	})
	if deleted > 0 {
		return
	}
	// Force-delete a batch if still over capacity.
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
