package config

import (
	"fmt"
	"os"
	"strings"
)

// DNSDataplane returns who answers public DNS.
//
//	"powersvx" (default off host) — Go edge on :53 (lab / hybrid)
//	"dnsdist" — dnsdist :53 + CDB blocklist; Unbound recurse on 127.0.0.1:5353
//
// The Unbound-on-the-public-port mode (POWERSVX_DNS_DATAPLANE=unbound|external)
// no longer exists; CheckDataplane refuses it before anything starts.
func DNSDataplane() string {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("POWERSVX_DNS_DATAPLANE")))
	if v == "" && os.Getenv("POWERSVX_HOST_DEPLOYMENT") == "1" {
		v = "dnsdist" // an unset mode on a host deployment means dnsdist
	}
	switch v {
	case "dnsdist", "cdb":
		return "dnsdist"
	default:
		return "powersvx"
	}
}

// DNSDistDataplane is true when dnsdist owns :53 with CDB filtering.
func DNSDistDataplane() bool { return DNSDataplane() == "dnsdist" }

// removedUnboundMode reports the retired Unbound-on-the-public-port values.
func removedUnboundMode(mode string) bool { return mode == "unbound" || mode == "external" }

// CheckDataplane refuses a Dataplane mode other than dnsdist.
//
// The Unbound-on-the-public-port mode (unbound, external) was removed: no code
// remains to run it, so nothing overrides the refusal. The Go resolver
// (powersvx and any other value) is being removed in the next major version;
// POWERSVX_ALLOW_LEGACY_DATAPLANE=1 is the escape hatch for labs and local
// development until then. The messages match deploy/linux/dataplane-guard.sh.
func CheckDataplane() error {
	configured := strings.ToLower(strings.TrimSpace(os.Getenv("POWERSVX_DNS_DATAPLANE")))
	switch {
	case removedUnboundMode(configured):
		return fmt.Errorf("POWERSVX_DNS_DATAPLANE=%s is configured, but the Unbound-on-the-public-port Dataplane mode has been removed, and POWERSVX_ALLOW_LEGACY_DATAPLANE does not bring it back. PowerSVX supports only the dnsdist Dataplane, with Unbound as its recursive backend behind dnsdist. Move this node to the dnsdist Dataplane (POWERSVX_DNS_DATAPLANE=dnsdist); see docs/PRODUCTION.md.", configured)
	case configured == "" && os.Getenv("POWERSVX_HOST_DEPLOYMENT") != "1":
		return nil // local development without dnsdist keeps its default
	case configured == "" || configured == "dnsdist" || configured == "cdb":
		return nil
	case os.Getenv("POWERSVX_ALLOW_LEGACY_DATAPLANE") == "1":
		return nil
	}
	return fmt.Errorf("POWERSVX_DNS_DATAPLANE=%s is configured, but this Dataplane mode is being removed in the next major version of PowerSVX, which supports only the dnsdist Dataplane. Move this node to the dnsdist Dataplane (POWERSVX_DNS_DATAPLANE=dnsdist) before updating; see docs/PRODUCTION.md.", configured)
}
