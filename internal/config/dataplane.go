package config

import (
	"fmt"
	"os"
	"strings"
)

// DNSDataplane returns who answers public DNS.
//
//	"powersvx" (default off host) — Go edge on :53 (lab / hybrid)
//	"unbound" — Unbound owns :53; PowerSVX is API/control-plane only
//	"dnsdist" — dnsdist :53 + CDB blocklist; Unbound recurse on 127.0.0.1:5353
func DNSDataplane() string {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("POWERSVX_DNS_DATAPLANE")))
	if v == "" && os.Getenv("POWERSVX_HOST_DEPLOYMENT") == "1" {
		v = "dnsdist" // an unset mode on a host deployment means dnsdist
	}
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

// CheckDataplane refuses a Dataplane mode other than dnsdist, which is being
// removed. POWERSVX_ALLOW_LEGACY_DATAPLANE=1 is the escape hatch for labs and
// local development. The message matches deploy/linux/dataplane-guard.sh.
func CheckDataplane() error {
	configured := strings.ToLower(strings.TrimSpace(os.Getenv("POWERSVX_DNS_DATAPLANE")))
	switch {
	case configured == "" && os.Getenv("POWERSVX_HOST_DEPLOYMENT") != "1":
		return nil // local development without dnsdist keeps its default
	case configured == "" || configured == "dnsdist" || configured == "cdb":
		return nil
	case os.Getenv("POWERSVX_ALLOW_LEGACY_DATAPLANE") == "1":
		return nil
	}
	return fmt.Errorf("POWERSVX_DNS_DATAPLANE=%s is configured, but this Dataplane mode is being removed in the next major version of PowerSVX, which supports only the dnsdist Dataplane. Move this node to the dnsdist Dataplane (POWERSVX_DNS_DATAPLANE=dnsdist) before updating; see docs/PRODUCTION.md.", configured)
}
