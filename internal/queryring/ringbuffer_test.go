package queryring

import (
	"context"
	"testing"
	"time"
)

func TestRingWrapFilterAndSubscribe(t *testing.T) {
	r := New(5)
	for i := 0; i < 8; i++ {
		blocked := i%2 == 1
		r.Push(QueryEvent{
			ClientIP:  "10.0.0.1",
			QName:     "domain" + string(rune('a'+i)) + ".com",
			QType:     "A",
			RCode:     "NOERROR",
			Blocked:   blocked,
			LatencyMS: 1.5,
		})
	}
	if r.Len() != 5 {
		t.Fatalf("expected len 5, got %d", r.Len())
	}
	all := r.Recent(QueryFilter{Limit: 10})
	if len(all) != 5 || all[0].QName != "domainh.com" || all[4].QName != "domaind.com" {
		t.Fatalf("unexpected ring order: %+v", all)
	}
	blocked := r.Recent(QueryFilter{BlockedOnly: true, Limit: 10})
	if len(blocked) != 3 {
		t.Fatalf("expected 3 blocked, got %d", len(blocked))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := r.Subscribe(ctx, 4)
	r.Push(QueryEvent{QName: "live.test", RCode: "NOERROR"})
	select {
	case ev := <-ch:
		if ev.QName != "live.test" {
			t.Fatalf("unexpected sub event: %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for subscriber event")
	}
}
