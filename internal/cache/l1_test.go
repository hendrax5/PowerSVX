package cache

import (
	"testing"
	"time"
)

func TestL1HitMiss(t *testing.T) {
	c := NewL1(100)
	wire := []byte{0xde, 0xad, 0xbe, 0xef}
	k := Key("example.com.", 1)
	if _, ok := c.Get(k); ok {
		t.Fatal("expected miss")
	}
	c.Set(k, wire, time.Minute, 0)
	e, ok := c.Get(k)
	if !ok {
		t.Fatal("expected hit")
	}
	if string(e.Wire) != string(wire) {
		t.Fatalf("wire mismatch")
	}
	// Callers must copy (CloneWire / RewriteID); Get returns shared Entry.
	cloned := e.CloneWire()
	cloned[0] = 0
	e2, _ := c.Get(k)
	if e2.Wire[0] != 0xde {
		t.Fatal("store was mutated via clone")
	}
}

func TestL1Expiry(t *testing.T) {
	c := NewL1(10)
	k := Key("x.", 1)
	c.Set(k, []byte{1}, time.Millisecond, 0)
	time.Sleep(5 * time.Millisecond)
	if _, ok := c.Get(k); ok {
		t.Fatal("expected expired miss")
	}
}

func BenchmarkL1Hit(b *testing.B) {
	c := NewL1(1000)
	wire := make([]byte, 128)
	for i := range wire {
		wire[i] = byte(i)
	}
	k := Key("bench.example.com.", 1)
	c.Set(k, wire, time.Hour, 0)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e, ok := c.Get(k)
		if !ok {
			b.Fatal("miss")
		}
		_ = e.CloneWire()
	}
}

func BenchmarkL1HitParallel(b *testing.B) {
	c := NewL1(1000)
	wire := make([]byte, 128)
	k := Key("bench.example.com.", 1)
	c.Set(k, wire, time.Hour, 0)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			e, ok := c.Get(k)
			if !ok {
				b.Fatal("miss")
			}
			out := make([]byte, len(e.Wire))
			copy(out, e.Wire)
			_ = out
		}
	})
}
