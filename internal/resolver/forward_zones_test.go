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
