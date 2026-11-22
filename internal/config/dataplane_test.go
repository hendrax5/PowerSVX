package config

import (
	"os"
	"testing"
)

func TestDNSDataplane(t *testing.T) {
	t.Setenv("POWERSVX_DNS_DATAPLANE", "")
	if DNSDataplane() != "powersvx" {
		t.Fatal(DNSDataplane())
	}
	t.Setenv("POWERSVX_DNS_DATAPLANE", "dnsdist")
	if !DNSDistDataplane() {
		t.Fatal("expected dnsdist")
	}
	// The removed Unbound mode never selects a Dataplane; CheckDataplane refuses it.
	for _, v := range []string{"unbound", "external"} {
		t.Setenv("POWERSVX_DNS_DATAPLANE", v)
		if DNSDistDataplane() || DNSDataplane() != "powersvx" {
			t.Fatalf("%s must not select a serving Dataplane, got %q", v, DNSDataplane())
		}
	}
	os.Unsetenv("POWERSVX_DNS_DATAPLANE")
}
