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
			Latency:  time.Duration(i) * time.Millisecond,
			Path:     "cache",
			RCode:    "NOERROR",
		})
	}
	c.Observe(Sample{ClientIP: "10.0.0.6", Path: "acl_denied", RCode: "REFUSED", ACLDenied: true})
	c.Observe(Sample{ClientIP: "10.0.0.7", Path: "ratelimited", RCode: "REFUSED", RateLimited: true})
	c.Observe(Sample{Path: "servfail", RCode: "SERVFAIL", Timeout: true})

	snap := c.Snapshot([]string{"10.0.0.0/8"}, nil)
	if snap.QPSNow < 1 && len(snap.QPSSeries) == 0 {
		t.Fatal("expected qps data")
	}
	if snap.Latency.N != 103 {
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
