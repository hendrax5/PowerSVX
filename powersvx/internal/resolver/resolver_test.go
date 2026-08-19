package resolver

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestBuildECSAndCacheKey(t *testing.T) {
	r := &Resolver{ecsOn: true, ecsV4: 24, ecsV6: 56}
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	e := r.buildECS(req, net.ParseIP("203.0.113.55"))
	if e == nil {
		t.Fatal("expected an ECS option for a public client IP")
	}
	if e.SourceNetmask != 24 || e.Family != 1 {
		t.Errorf("unexpected ECS: netmask=%d family=%d", e.SourceNetmask, e.Family)
	}
	if e.Address.String() != "203.0.113.0" {
		t.Errorf("address should be masked to /24, got %s", e.Address)
	}
	scope := ecsNet(e)
	if scope != "203.0.113.0/24" {
		t.Errorf("ecsNet=%q", scope)
	}

	// Loopback => no ECS.
	if r.buildECS(req, net.ParseIP("127.0.0.1")) != nil {
		t.Error("loopback client should not get ECS")
	}

	// ECS scope is folded into the cache key and parseKey drops it cleanly.
	key := cacheKey("example.com.", dns.TypeA, dns.ClassINET, scope)
	if key != "example.com.|1|1|203.0.113.0/24" {
		t.Errorf("cacheKey=%q", key)
	}
	name, qt, qc, ok := parseKey(key)
	if !ok || name != "example.com." || qt != dns.TypeA || qc != dns.ClassINET {
		t.Errorf("parseKey mismatch: %q %d %d %v", name, qt, qc, ok)
	}
}

func TestBuildECSPassThrough(t *testing.T) {
	r := &Resolver{ecsOn: true, ecsV4: 24}
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	// Client already supplied ECS => pass it through unchanged.
	client := &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 20, Address: net.ParseIP("198.51.100.0").To4()}
	o := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	o.Option = append(o.Option, client)
	req.Extra = append(req.Extra, o)

	e := r.buildECS(req, net.ParseIP("203.0.113.55"))
	if e == nil || e.SourceNetmask != 20 {
		t.Fatalf("expected pass-through of client ECS /20, got %+v", e)
	}
}
