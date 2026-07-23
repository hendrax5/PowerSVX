package aclban

import (
	"log/slog"
	"testing"
	"time"
)

func TestObserveThresholdThenSilent(t *testing.T) {
	g := New(Config{Threshold: 3, Window: time.Minute, TTL: time.Minute, NFT: false}, slog.Default())
	if silent, _ := g.Observe("203.0.113.10"); silent {
		t.Fatal("first deny should reply")
	}
	if silent, _ := g.Observe("203.0.113.10"); silent {
		t.Fatal("second deny should reply")
	}
	if silent, newBan := g.Observe("203.0.113.10"); !silent || !newBan {
		t.Fatal("third deny should autoban silent")
	}
	if silent, newBan := g.Observe("203.0.113.10"); !silent || newBan {
		t.Fatal("still banned, not a new ban")
	}
	if silent, _ := g.Observe("203.0.113.11"); silent {
		t.Fatal("other IP should not be silent yet")
	}
}

func TestLoopbackNeverBanned(t *testing.T) {
	g := New(Config{Threshold: 1, Window: time.Minute, TTL: time.Minute, NFT: false}, slog.Default())
	for i := 0; i < 5; i++ {
		if silent, _ := g.Observe("127.0.0.1"); silent {
			t.Fatal("loopback must not silent-drop")
		}
	}
}

func TestResetClearsBan(t *testing.T) {
	g := New(Config{Threshold: 2, Window: time.Minute, TTL: time.Hour, NFT: false}, slog.Default())
	_, _ = g.Observe("198.51.100.1")
	if silent, _ := g.Observe("198.51.100.1"); !silent {
		t.Fatal("expected ban")
	}
	g.Reset()
	if silent, _ := g.Observe("198.51.100.1"); silent {
		t.Fatal("after reset should reply again")
	}
}
