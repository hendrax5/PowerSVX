package ratelimit

import "testing"

func TestAllowBurstThenBlock(t *testing.T) {
	l := New(true, 1, 2, 1, nil)
	if !l.Allow("10.0.0.1") || !l.Allow("10.0.0.1") {
		t.Fatal("burst should allow 2")
	}
	if l.Allow("10.0.0.1") {
		t.Fatal("third should be denied")
	}
}

func TestWhitelist(t *testing.T) {
	l := New(true, 1, 1, 1, []string{"10.0.0.0/8"})
	for i := 0; i < 20; i++ {
		if !l.Allow("10.1.2.3") {
			t.Fatal("whitelist should always allow")
		}
	}
}

func TestDisabled(t *testing.T) {
	l := New(false, 1, 1, 1, nil)
	for i := 0; i < 100; i++ {
		if !l.Allow("1.2.3.4") {
			t.Fatal("disabled limiter must allow")
		}
	}
}
