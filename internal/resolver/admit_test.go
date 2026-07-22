package resolver

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAcquireFailFastWhenFull(t *testing.T) {
	r := &Resolver{
		sem:    make(chan struct{}, 1),
		semCap: 1,
	}
	release, err := r.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	_, err = r.acquire(context.Background())
	if !errors.Is(err, ErrAdmitRejected) {
		t.Fatalf("want ErrAdmitRejected, got %v", err)
	}
}

func TestLoadShedAt75Percent(t *testing.T) {
	r := &Resolver{semCap: 100}
	r.inflight.Store(74)
	if r.loadShed() {
		t.Fatal("74/100 should not shed")
	}
	r.inflight.Store(75)
	if !r.loadShed() {
		t.Fatal("75/100 should shed")
	}
}

func TestHopTimeoutCapsPerExchange(t *testing.T) {
	r := &Resolver{Timeout: 2 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 1600*time.Millisecond)
	defer cancel()
	hop := r.hopTimeout(ctx)
	if hop != defaultHopTimeout {
		t.Fatalf("want %v, got %v", defaultHopTimeout, hop)
	}
}
