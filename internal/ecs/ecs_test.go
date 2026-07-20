package ecs

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestExtractApplyRoundTrip(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	sub := FromIP(net.ParseIP("203.0.113.50"), 24, 56)
	Apply(msg, sub, 1232)
	got := Extract(msg)
	if got == nil || got.String() != "203.0.113.0/24" {
		t.Fatalf("got %+v string=%s", got, got.String())
	}
}

func TestFromIPv6(t *testing.T) {
	sub := FromIP(net.ParseIP("2001:db8::1"), 24, 56)
	if sub.Family != 2 || sub.Source != 56 {
		t.Fatalf("%+v", sub)
	}
}
