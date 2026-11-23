package unboundrpz

import (
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

const (
	// DefaultBackendPort is the port Unbound listens on behind dnsdist.
	DefaultBackendPort = 5353
	// dnsdistPort is the public listener. Unbound forwarding there loops through
	// dnsdist, which sends every name it does not own straight back to Unbound.
	dnsdistPort = 53
)

// BackendPort is the port of Unbound's listener on loopback: POWERSVX_UNBOUND_BACKEND_PORT,
// the same variable the dnsdist and Unbound generators read, or 5353.
func BackendPort() int {
	if v := strings.TrimSpace(os.Getenv("POWERSVX_UNBOUND_BACKEND_PORT")); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 && p < 65536 {
			return p
		}
	}
	return DefaultBackendPort
}

// ForwarderLoop reports whether forwarding to addr would send Unbound's queries back
// into the Dataplane: a loopback address (127.0.0.0/8, ::1, localhost, or the
// unspecified address) on Unbound's own port or on port 53, where dnsdist listens.
// addr is written as Unbound or the console writes it: ip, ip:port, [ip]:port,
// ip@port, or localhost with any of those. An address with no port means port 53.
// reason says which listener the address points at, and is empty when it is not a loop.
func ForwarderLoop(addr string, backendPort int) (loop bool, reason string) {
	host, port, ok := splitForwarder(addr)
	if !ok || !isLoopbackHost(host) {
		return false, ""
	}
	switch port {
	case backendPort:
		return true, "Unbound's own listener"
	case dnsdistPort:
		return true, "the dnsdist listener, which sends the query back to Unbound"
	}
	return false, ""
}

func splitForwarder(addr string) (host string, port int, ok bool) {
	s := strings.TrimSpace(addr)
	if s == "" {
		return "", 0, false
	}
	port = dnsdistPort
	if i := strings.Index(s, "@"); i >= 0 {
		p, err := strconv.Atoi(strings.TrimSpace(s[i+1:]))
		if err != nil || p < 1 || p > 65535 {
			return "", 0, false
		}
		return strings.Trim(strings.TrimSpace(s[:i]), "[]"), p, true
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().String(), int(ap.Port()), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.String(), port, true
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		return strings.Trim(s, "[]"), port, true
	}
	if h, p, err := net.SplitHostPort(s); err == nil {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return "", 0, false
		}
		return h, n, true
	}
	return s, port, true
}

func isLoopbackHost(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "localhost" {
		return true
	}
	if i := strings.Index(h, "%"); i >= 0 {
		h = h[:i]
	}
	a, err := netip.ParseAddr(h)
	if err != nil {
		return false
	}
	a = a.Unmap()
	return a.IsLoopback() || a.IsUnspecified()
}

// SkippedForwarder is a forwarder the writer left out because it would loop.
type SkippedForwarder struct {
	Zone   string `json:"zone"` // "." for the default forwarders
	Addr   string `json:"addr"`
	Reason string `json:"reason"`
}

// dropLoops splits addrs into the ones safe to write and the ones that loop.
func dropLoops(zone string, addrs []string, backendPort int) (keep []string, skipped []SkippedForwarder) {
	for _, a := range addrs {
		if loop, why := ForwarderLoop(a, backendPort); loop {
			skipped = append(skipped, SkippedForwarder{Zone: zone, Addr: strings.TrimSpace(a), Reason: why})
			continue
		}
		keep = append(keep, a)
	}
	return keep, skipped
}
