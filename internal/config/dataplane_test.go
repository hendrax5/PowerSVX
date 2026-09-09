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
	t.Setenv("POWERSVX_DNS_DATAPLANE", "unbound")
	if !UnboundDataplane() || DNSDistDataplane() {
		t.Fatal("expected unbound")
	}
	t.Setenv("POWERSVX_DNS_DATAPLANE", "dnsdist")
	if !DNSDistDataplane() || UnboundDataplane() {
		t.Fatal("expected dnsdist")
	}
	if !FilterDataplane() {
		t.Fatal("filter dataplane")
	}
	os.Unsetenv("POWERSVX_DNS_DATAPLANE")
}
