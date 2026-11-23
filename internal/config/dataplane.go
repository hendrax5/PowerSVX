package config

import (
	"fmt"
	"os"
	"strings"
)

// DNSDataplane returns who answers public DNS. There is exactly one Dataplane:
// dnsdist in front of Unbound, with the Control Plane's Auth Backend behind it.
// Whatever POWERSVX_DNS_DATAPLANE says, the answer is "dnsdist"; CheckDataplane
// stops the process before a node configured for anything else gets this far.
// Unset means dnsdist, on a host and in local development alike (where the
// process is then a Control Plane with no Dataplane to push to).
func DNSDataplane() string { return "dnsdist" }

// DNSDistDataplane is true when dnsdist owns :53 with CDB filtering. It always is.
func DNSDistDataplane() bool { return true }

// removedUnboundMode reports the retired Unbound-on-the-public-port values.
func removedUnboundMode(mode string) bool { return mode == "unbound" || mode == "external" }

// CheckDataplane refuses any Dataplane mode other than dnsdist. Unset is
// dnsdist. No environment variable brings a removed mode back. The messages
// match deploy/linux/dataplane-guard.sh.
func CheckDataplane() error {
	configured := strings.ToLower(strings.TrimSpace(os.Getenv("POWERSVX_DNS_DATAPLANE")))
	switch {
	case configured == "" || configured == "dnsdist" || configured == "cdb":
		return nil
	case removedUnboundMode(configured):
		return fmt.Errorf("POWERSVX_DNS_DATAPLANE=%s is configured, but the Unbound-on-the-public-port Dataplane mode has been removed. PowerSVX supports only the dnsdist Dataplane, with Unbound as its recursive backend behind dnsdist. Move this node to the dnsdist Dataplane (POWERSVX_DNS_DATAPLANE=dnsdist); see docs/PRODUCTION.md.", configured)
	}
	return fmt.Errorf("POWERSVX_DNS_DATAPLANE=%s is configured, but the Go resolver Dataplane mode has been removed. PowerSVX supports only the dnsdist Dataplane, with Unbound as its recursive backend behind dnsdist. Move this node to the dnsdist Dataplane (POWERSVX_DNS_DATAPLANE=dnsdist); see docs/PRODUCTION.md.", configured)
}
