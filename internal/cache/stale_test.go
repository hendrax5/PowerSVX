package cache

import (
	"testing"
	"time"
)

func TestServeStaleHit(t *testing.T) {
	tier := NewTier(NewL1(100), nil, 5*time.Minute, time.Minute)
	tier.ServeStale = true
	tier.StaleTTL = 60 * time.Second
	tier.MinTTL = 0

	wire := []byte{1, 2, 3}
	// Store with 1ms fresh TTL + 2s stale window via SetStale path.
	k := KeyScoped("stale.example.", 1, "", "", "")
	tier.L1.SetStale(k, wire, time.Millisecond, 2*time.Second, 0)
	time.Sleep(5 * time.Millisecond)

	e, st := tier.GetScopedEx("stale.example.", 1, "", "", "")
	if st != HitStale {
		t.Fatalf("want HitStale, got %v", st)
	}
	if e == nil || string(e.Wire) != string(wire) {
		t.Fatal("stale wire missing")
	}
}

func TestPrefetchThreshold(t *testing.T) {
	e := &Entry{
		Expiry:    time.Now().Add(5 * time.Second),
		StoredTTL: 100 * time.Second,
	}
	if !e.NeedsPrefetch(10) { // 10% of 100s = 10s; remaining 5s < 10s
		t.Fatal("expected prefetch")
	}
	e.Expiry = time.Now().Add(20 * time.Second)
	if e.NeedsPrefetch(10) {
		t.Fatal("should not prefetch yet")
	}
}
