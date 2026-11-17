package cache

import (
	"path/filepath"
	"testing"
	"time"
)

func TestL2RoundTripAndPromote(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "badger")
	l2, err := NewL2(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l2.Close() }()

	l1 := NewL1(100)
	tier := NewTier(l1, l2, time.Minute, time.Second)

	wire := []byte{1, 2, 3, 4, 5}
	tier.Set("promote.test.", 1, wire, 0, 60)

	// Clear L1 to force L2 hit + promote
	l1.m.Range(func(k, _ any) bool {
		l1.m.Delete(k)
		return true
	})

	e, ok := tier.Get("promote.test.", 1)
	if !ok {
		t.Fatal("expected L2 hit")
	}
	if string(e.Wire) != string(wire) {
		t.Fatalf("wire mismatch: %v", e.Wire)
	}
	// Second get should be L1
	if _, ok := l1.Get(Key("promote.test.", 1)); !ok {
		t.Fatal("expected promote to L1")
	}
}
