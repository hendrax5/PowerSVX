package cache

import (
	"testing"
	"time"
)

func TestSetScopedMinTTLFloor(t *testing.T) {
	tier := NewTier(NewL1(100), nil, 5*time.Minute, time.Minute)
	tier.MinTTL = 60 * time.Second

	wire := []byte{1, 2, 3, 4}
	tier.SetScoped("tiktok.com.", 1, "", "", "", wire, 0, 20) // upstream TTL 20s

	e, ok := tier.GetScoped("tiktok.com.", 1, "", "", "")
	if !ok {
		t.Fatal("expected cache hit")
	}
	remain := time.Until(e.Expiry)
	if remain < 50*time.Second {
		t.Fatalf("expected floor ~60s, remain=%v", remain)
	}
	if remain > 70*time.Second {
		t.Fatalf("expected ~60s not default 300s, remain=%v", remain)
	}
}

func TestSetScopedMinTTLRespectsMax(t *testing.T) {
	tier := NewTier(NewL1(100), nil, 30*time.Second, time.Minute)
	tier.MinTTL = 60 * time.Second // min > max → clamp to max

	tier.SetScoped("x.com.", 1, "", "", "", []byte{9}, 0, 10)
	e, ok := tier.GetScoped("x.com.", 1, "", "", "")
	if !ok {
		t.Fatal("expected hit")
	}
	remain := time.Until(e.Expiry)
	if remain > 35*time.Second || remain < 20*time.Second {
		t.Fatalf("expected clamp to max 30s, remain=%v", remain)
	}
}

func TestSetScopedNoMinTTL(t *testing.T) {
	tier := NewTier(NewL1(100), nil, 5*time.Minute, time.Minute)
	tier.SetScoped("y.com.", 1, "", "", "", []byte{1}, 0, 20)
	e, ok := tier.GetScoped("y.com.", 1, "", "", "")
	if !ok {
		t.Fatal("expected hit")
	}
	remain := time.Until(e.Expiry)
	if remain > 25*time.Second || remain < 10*time.Second {
		t.Fatalf("expected honor 20s TTL, remain=%v", remain)
	}
}
