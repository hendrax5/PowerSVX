package eventlog

import (
	"strconv"
	"testing"
	"time"
)

func TestRingAndSample(t *testing.T) {
	b := New(5)
	for i := 0; i < 7; i++ {
		b.Emit("warn", "test", "msg", map[string]string{"i": strconv.Itoa(i)})
	}
	got := b.Recent(10)
	if len(got) != 5 {
		t.Fatalf("want 5, got %d", len(got))
	}
	if got[0].Attrs["i"] != "2" || got[4].Attrs["i"] != "6" {
		t.Fatalf("order=%v", got)
	}

	b.EmitSampled("ip:1", time.Hour, "warn", "rate_limit", "blocked", nil)
	b.EmitSampled("ip:1", time.Hour, "warn", "rate_limit", "blocked again", nil)
	n := 0
	for _, e := range b.Recent(100) {
		if e.Kind == "rate_limit" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("sampled want 1 rate_limit, got %d", n)
	}
}
