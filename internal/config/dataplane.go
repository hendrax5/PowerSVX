package config

import (
	"os"
	"strings"
)

// DNSDataplane returns who answers public DNS.
//
//	"powersvx" (default) — Go edge on :53 (lab / hybrid)
//	"unbound" — Unbound owns :53; PowerSVX is API/control-plane only
//	"dnsdist" — dnsdist :53 + CDB blocklist; Unbound recurse on 127.0.0.1:5353
func DNSDataplane() string {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("POWERSVX_DNS_DATAPLANE")))
	switch v {
	case "unbound", "external":
		return "unbound"
	case "dnsdist", "cdb":
		return "dnsdist"
	default:
		return "powersvx"
	}
}

// UnboundDataplane is true when public DNS is Unbound (RPZ in-process).
func UnboundDataplane() bool { return DNSDataplane() == "unbound" }

// DNSDistDataplane is true when dnsdist owns :53 with CDB filtering.
func DNSDistDataplane() bool { return DNSDataplane() == "dnsdist" }

// FilterDataplane is true when PowerSVX does not answer public :53.
func FilterDataplane() bool {
	switch DNSDataplane() {
	case "unbound", "dnsdist":
		return true
	default:
		return false
	}
}
