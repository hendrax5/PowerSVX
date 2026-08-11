package resolver

import (
	"testing"

	"github.com/powersvx/powersvx/internal/config"
)

func TestMatchForwardZoneLongestSuffix(t *testing.T) {
	r := New(config.ResolverConfig{
		Mode: "recursive",
		ForwardZones: []config.ForwardZoneConfig{
			{Zone: "example.com", Forwarders: []string{"1.1.1.1:53"}},
			{Zone: "corp.example.com", Forwarders: []string{"10.0.0.1:53"}},
		},
	})
	got := r.matchForwardZone("a.corp.example.com.")
	if len(got) != 1 || got[0] != "10.0.0.1:53" {
		t.Fatalf("got %v", got)
	}
	got = r.matchForwardZone("www.example.com.")
	if len(got) != 1 || got[0] != "1.1.1.1:53" {
		t.Fatalf("got %v", got)
	}
	if r.matchForwardZone("other.org.") != nil {
		t.Fatal("expected no match")
	}
}

// Hybrid Unbound backend uses mode=forward + 127.0.0.1:5353; conditional zones
// must still match first (same matchForwardZone, independent of Mode).
func TestMatchForwardZoneWithUnboundBackendMode(t *testing.T) {
	r := New(config.ResolverConfig{
		Mode:       "forward",
		Forwarders: []string{"127.0.0.1:5353"},
		ForwardZones: []config.ForwardZoneConfig{
			{Zone: "corp.local", Forwarders: []string{"10.1.1.10:53"}},
		},
	})
	got := r.matchForwardZone("ad.corp.local.")
	if len(got) != 1 || got[0] != "10.1.1.10:53" {
		t.Fatalf("conditional must win over Unbound forwarder, got %v", got)
	}
	if r.matchForwardZone("example.com.") != nil {
		t.Fatal("public name must not match zone — ResolveWithECS then uses Unbound forwarders")
	}
}

