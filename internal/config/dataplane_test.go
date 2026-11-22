package config

import (
	"os"
	"testing"
)

// The Dataplane is dnsdist whatever the environment says; CheckDataplane is what
// refuses a node configured for anything else.
func TestDNSDataplaneIsAlwaysDnsdist(t *testing.T) {
	for _, v := range []string{"", "dnsdist", "cdb", "powersvx", "unbound", "external", "bogus"} {
		t.Setenv("POWERSVX_DNS_DATAPLANE", v)
		if DNSDataplane() != "dnsdist" || !DNSDistDataplane() {
			t.Fatalf("%q: got %q", v, DNSDataplane())
		}
	}
	os.Unsetenv("POWERSVX_DNS_DATAPLANE")
	if DNSDataplane() != "dnsdist" {
		t.Fatal("unset must mean dnsdist")
	}
}
