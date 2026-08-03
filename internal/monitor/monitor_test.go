package monitor

import (
	"testing"
	"time"
)

func TestObserveQPSAndLatency(t *testing.T) {
	c := New()
	for i := 0; i < 100; i++ {
		c.Observe(Sample{
			ClientIP: "10.0.0.5",
			QName:    "ok.example",
			Latency:  time.Duration(i) * time.Millisecond,
			Path:     "cache",
			RCode:    "NOERROR",
		})
	}
	c.Observe(Sample{ClientIP: "10.0.0.6", Path: "acl_denied", RCode: "REFUSED", ACLDenied: true})
	c.Observe(Sample{ClientIP: "10.0.0.7", Path: "ratelimited", RCode: "REFUSED", RateLimited: true})
	c.Observe(Sample{Path: "servfail", RCode: "SERVFAIL", Timeout: true})
	c.Observe(Sample{ClientIP: "10.0.0.5", QName: "ads.tracker.com", Path: "rpz", RCode: "NXDOMAIN"})
	c.Observe(Sample{ClientIP: "10.0.0.5", QName: "ads.tracker.com", Path: "rpz", RCode: "NXDOMAIN"})

	snap := c.Snapshot([]string{"10.0.0.0/8"}, nil)
	if snap.QPSNow < 1 && len(snap.QPSSeries) == 0 {
		t.Fatal("expected qps data")
	}
	if snap.Latency.N != 105 {
		t.Fatalf("latency samples=%d", snap.Latency.N)
	}
	if snap.ACLDeny != 1 || snap.ACLAllow < 100 {
		t.Fatalf("acl allow=%d deny=%d", snap.ACLAllow, snap.ACLDeny)
	}
	if snap.RateLimitedTotal != 1 {
		t.Fatalf("rl=%d", snap.RateLimitedTotal)
	}
	if len(snap.TopClients) == 0 || snap.TopClients[0].Key != "10.0.0.5" {
		t.Fatalf("clients=%v", snap.TopClients)
	}
	if len(snap.TopSubnets) == 0 || snap.TopSubnets[0].Key != "10.0.0.0/24" {
		t.Fatalf("subnets=%v", snap.TopSubnets)
	}
	if snap.BlockedTotal != 2 || snap.BlockedPercent <= 0 {
		t.Fatalf("blocked=%d pct=%v", snap.BlockedTotal, snap.BlockedPercent)
	}
	if len(snap.TopBlocked) == 0 || snap.TopBlocked[0].Key != "ads.tracker.com" {
		t.Fatalf("top_blocked=%v", snap.TopBlocked)
	}
	if len(snap.BlockedCover) == 0 || snap.BlockedCover[0].Hits < 2 {
		t.Fatalf("blocked_cover=%v", snap.BlockedCover)
	}
	if len(snap.Recent) < 1 {
		t.Fatal("recent empty")
	}
	if snap.ACLOpenResolver {
		t.Fatal("should not be open with allow list")
	}
	open := c.Snapshot(nil, nil)
	if !open.ACLOpenResolver {
		t.Fatal("empty allow should warn open resolver")
	}
	foundTimeout := false
	for _, e := range snap.Errors {
		if e.Key == "timeout" {
			foundTimeout = true
		}
	}
	if !foundTimeout {
		t.Fatalf("errors=%v", snap.Errors)
	}
	if snap.Resources.Goroutines < 1 {
		t.Fatal("resources")
	}
	if snap.Resources.NumCPU < 1 {
		t.Fatal("num_cpu")
	}
	// RSS falls back to heap when OS RSS unavailable
	if snap.Resources.RSSMB <= 0 && snap.Resources.HeapMB <= 0 {
		t.Fatal("rss/heap")
	}
}

func TestRecordForwarder(t *testing.T) {
	c := New()
	c.RecordForwarder("1.1.1.1:53", true, 12, "")
	c.RecordForwarder("1.1.1.1:53", false, 0, "timeout")
	snap := c.Snapshot(nil, nil)
	if len(snap.Forwarders) != 1 {
		t.Fatalf("%v", snap.Forwarders)
	}
	f := snap.Forwarders[0]
	if f.OK != 1 || f.Fail != 1 || f.LastStatus != "timeout" {
		t.Fatalf("%+v", f)
	}
}
