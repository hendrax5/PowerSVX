package ratelimit

import (
	"testing"
	"time"
)

func TestSnapshotBlocked(t *testing.T) {
	l := New(true, 1, 1, 60, nil)
	// Exhaust and block
	if !l.Allow("203.0.113.10") {
		t.Fatal("first should allow")
	}
	if l.Allow("203.0.113.10") {
		t.Fatal("second should block")
	}
	blocked := l.SnapshotBlocked(10)
	if len(blocked) != 1 || blocked[0].IP != "203.0.113.10" {
		t.Fatalf("%+v", blocked)
	}
	if blocked[0].Remaining < 1 {
		t.Fatalf("remaining=%d", blocked[0].Remaining)
	}
	// Expired entry cleaned
	l.mu.Lock()
	l.blocked["203.0.113.10"] = time.Now().Add(-time.Second)
	l.mu.Unlock()
	if n := l.SnapshotBlocked(10); len(n) != 0 {
		t.Fatalf("expected clean, got %+v", n)
	}
}
