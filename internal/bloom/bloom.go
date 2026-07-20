package bloom

import (
	"hash/fnv"
	"math"
	"sync"
)

// Filter is a simple concurrent Bloom filter for RPZ pre-checks.
type Filter struct {
	mu     sync.RWMutex
	bits   []uint64
	k      uint
	nbits  uint
	added  uint64
}

func New(nExpected int, fpRate float64) *Filter {
	if nExpected < 1 {
		nExpected = 1024
	}
	if fpRate <= 0 || fpRate >= 1 {
		fpRate = 0.01
	}
	m := -float64(nExpected) * math.Log(fpRate) / (math.Ln2 * math.Ln2)
	k := math.Ln2 * m / float64(nExpected)
	nbits := uint(m)
	if nbits < 64 {
		nbits = 64
	}
	kk := uint(k + 0.5)
	if kk < 1 {
		kk = 1
	}
	if kk > 16 {
		kk = 16
	}
	words := (nbits + 63) / 64
	return &Filter{bits: make([]uint64, words), k: kk, nbits: nbits}
}

func (f *Filter) Add(s string) {
	if f == nil {
		return
	}
	h1, h2 := hash2(s)
	f.mu.Lock()
	for i := uint(0); i < f.k; i++ {
		pos := (h1 + uint64(i)*h2) % uint64(f.nbits)
		f.bits[pos/64] |= 1 << (pos % 64)
	}
	f.added++
	f.mu.Unlock()
}

// MightContain returns false if definitely not present.
func (f *Filter) MightContain(s string) bool {
	if f == nil {
		return true
	}
	h1, h2 := hash2(s)
	f.mu.RLock()
	defer f.mu.RUnlock()
	for i := uint(0); i < f.k; i++ {
		pos := (h1 + uint64(i)*h2) % uint64(f.nbits)
		if f.bits[pos/64]&(1<<(pos%64)) == 0 {
			return false
		}
	}
	return true
}

func (f *Filter) Reset(nExpected int) {
	if f == nil {
		return
	}
	nf := New(nExpected, 0.01)
	f.mu.Lock()
	f.bits = nf.bits
	f.k = nf.k
	f.nbits = nf.nbits
	f.added = 0
	f.mu.Unlock()
}

func hash2(s string) (uint64, uint64) {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	a := h.Sum64()
	h.Reset()
	_, _ = h.Write([]byte(s + "#"))
	b := h.Sum64()
	if b == 0 {
		b = 0x9e3779b97f4a7c15
	}
	return a, b
}
