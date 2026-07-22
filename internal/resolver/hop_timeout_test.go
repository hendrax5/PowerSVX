package resolver

import (
	"context"
	"testing"
	"time"
)

func TestHopTimeoutCapsPerExchange(t *testing.T) {
	r := &Resolver{Timeout: 2 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 1600*time.Millisecond)
	defer cancel()
	hop := r.hopTimeout(ctx)
	if hop != defaultHopTimeout {
		t.Fatalf("want %v, got %v", defaultHopTimeout, hop)
	}
}

func TestHopTimeoutRespectsDeadline(t *testing.T) {
	r := &Resolver{Timeout: 2 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	hop := r.hopTimeout(ctx)
	if hop > 100*time.Millisecond || hop <= 0 {
		t.Fatalf("want <=100ms remaining, got %v", hop)
	}
}
