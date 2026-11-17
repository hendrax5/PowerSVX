package tproxy

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Default public resolvers for safe intercept mode (ISP CPE hardcodes).
var DefaultPublicResolvers = []string{
	"8.8.8.8", "8.8.4.4",
	"1.1.1.1", "1.0.0.1",
	"9.9.9.9", "149.112.112.112",
	"208.67.222.222", "208.67.220.220",
	"94.140.14.14", "94.140.15.15",
}

// InterceptConfig is the live nftables/ip-rule intercept policy.
type InterceptConfig struct {
	Enabled   bool
	Iface     string   // e.g. ens18; empty = first non-loopback UP
	Mode      string   // public | all | custom
	Resolvers []string // used when mode=custom (or overrides public list)
	Mark      uint32   // fwmark, default 1
}

// Status is the live OS intercept state.
type Status struct {
	Supported     bool   `json:"supported"`
	Applied       bool   `json:"applied"`
	Iface         string `json:"iface,omitempty"`
	Mode          string `json:"mode,omitempty"`
	Mark          uint32 `json:"mark,omitempty"`
	UDPPackets    uint64 `json:"udp_packets"`
	TCPPackets    uint64 `json:"tcp_packets"`
	UDPBytes      uint64 `json:"udp_bytes"`
	TCPBytes      uint64 `json:"tcp_bytes"`
	RouteOK       bool   `json:"route_ok"`
	Warning       string `json:"warning,omitempty"`
	LastError     string `json:"last_error,omitempty"`
	LastApplyUnix int64  `json:"last_apply_unix,omitempty"`
}

// IfaceInfo is a host NIC suitable for intercept.
type IfaceInfo struct {
	Name  string   `json:"name"`
	Up    bool     `json:"up"`
	Addrs []string `json:"addrs,omitempty"`
}

var (
	mu            sync.Mutex
	lastApplyUnix int64
	lastErr       string
	lastCfg       InterceptConfig
)

var (
	reUDPCounter = regexp.MustCompile(`udp dport 53[^\{]*counter packets (\d+) bytes (\d+)`)
	reTCPCounter = regexp.MustCompile(`tcp dport 53[^\{]*counter packets (\d+) bytes (\d+)`)
)

// Supported reports whether OS intercept control is available on this build/OS.
func Supported() bool {
	return runtime.GOOS == "linux"
}

// ListIfaces returns non-loopback interfaces.
func ListIfaces() ([]IfaceInfo, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]IfaceInfo, 0, len(ifs))
	for _, iface := range ifs {
		name := iface.Name
		if name == "lo" || strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "br-") ||
			strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "virbr") {
			continue
		}
		info := IfaceInfo{Name: name, Up: iface.Flags&net.FlagUp != 0}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			info.Addrs = append(info.Addrs, a.String())
		}
		out = append(out, info)
	}
	return out, nil
}

// PickDefaultIface chooses a sensible NIC for intercept.
func PickDefaultIface() string {
	ifs, err := ListIfaces()
	if err != nil {
		return ""
	}
	for _, i := range ifs {
		if i.Up {
			return i.Name
		}
	}
	if len(ifs) > 0 {
		return ifs[0].Name
	}
	return ""
}

func normalizeMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "all":
		return "all"
	case "custom":
		return "custom"
	default:
		return "public"
	}
}

func resolversFor(cfg InterceptConfig) []string {
	switch normalizeMode(cfg.Mode) {
	case "custom":
		if len(cfg.Resolvers) > 0 {
			return uniqueIPs(cfg.Resolvers)
		}
		return append([]string(nil), DefaultPublicResolvers...)
	case "all":
		return nil
	default:
		if len(cfg.Resolvers) > 0 {
			return uniqueIPs(cfg.Resolvers)
		}
		return append([]string(nil), DefaultPublicResolvers...)
	}
}

func uniqueIPs(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if ip := net.ParseIP(s); ip == nil || ip.To4() == nil {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// Apply installs policy routing + nftables intercept (idempotent, no flush ruleset).
func Apply(cfg InterceptConfig) error {
	mu.Lock()
	defer mu.Unlock()
	if !Supported() {
		return fmt.Errorf("tproxy intercept only supported on linux")
	}
	if !cfg.Enabled {
		return DisableLocked()
	}
	iface := strings.TrimSpace(cfg.Iface)
	if iface == "" {
		iface = PickDefaultIface()
	}
	if iface == "" {
		return fmt.Errorf("no suitable network interface for tproxy intercept")
	}
	cfg.Iface = iface
	cfg.Mode = normalizeMode(cfg.Mode)
	if cfg.Mark == 0 {
		cfg.Mark = 1
	}
	if err := ensureRoutes(cfg.Mark); err != nil {
		lastErr = err.Error()
		return err
	}
	if err := applyNFT(cfg); err != nil {
		lastErr = err.Error()
		return err
	}
	lastCfg = cfg
	lastApplyUnix = time.Now().Unix()
	lastErr = ""
	return nil
}

// Disable removes powersvx_tproxy table and fwmark rules.
func Disable() error {
	mu.Lock()
	defer mu.Unlock()
	return DisableLocked()
}

// DisableLocked assumes mu held.
func DisableLocked() error {
	if !Supported() {
		return fmt.Errorf("tproxy intercept only supported on linux")
	}
	_ = exec.Command("nft", "delete", "table", "inet", "powersvx_tproxy").Run()
	mark := lastCfg.Mark
	if mark == 0 {
		mark = 1
	}
	_ = exec.Command("ip", "rule", "del", "fwmark", fmt.Sprintf("0x%x", mark), "lookup", "100", "priority", "100").Run()
	_ = exec.Command("ip", "-6", "rule", "del", "fwmark", fmt.Sprintf("0x%x", mark), "lookup", "100", "priority", "100").Run()
	lastCfg.Enabled = false
	lastApplyUnix = time.Now().Unix()
	lastErr = ""
	return nil
}

// GetStatus inspects live nft/ip state.
func GetStatus(desired InterceptConfig) Status {
	st := Status{Supported: Supported(), Mark: 1}
	if desired.Mark != 0 {
		st.Mark = desired.Mark
	}
	if !Supported() {
		st.LastError = "not linux"
		return st
	}
	mu.Lock()
	st.LastApplyUnix = lastApplyUnix
	st.LastError = lastErr
	if lastCfg.Iface != "" {
		st.Iface = lastCfg.Iface
	}
	if lastCfg.Mode != "" {
		st.Mode = lastCfg.Mode
	}
	mu.Unlock()

	out, err := exec.Command("nft", "list", "table", "inet", "powersvx_tproxy").CombinedOutput()
	if err == nil {
		st.Applied = true
		body := string(out)
		if m := reUDPCounter.FindStringSubmatch(body); len(m) == 3 {
			st.UDPPackets, _ = strconv.ParseUint(m[1], 10, 64)
			st.UDPBytes, _ = strconv.ParseUint(m[2], 10, 64)
		}
		if m := reTCPCounter.FindStringSubmatch(body); len(m) == 3 {
			st.TCPPackets, _ = strconv.ParseUint(m[1], 10, 64)
			st.TCPBytes, _ = strconv.ParseUint(m[2], 10, 64)
		}
		if strings.Contains(body, `iifname != "`) {
			// extract iface from rule
			if i := strings.Index(body, `iifname != "`); i >= 0 {
				rest := body[i+len(`iifname != "`):]
				if j := strings.Index(rest, `"`); j > 0 {
					st.Iface = rest[:j]
				}
			}
		}
		if strings.Contains(body, "@public_dns4") || strings.Contains(body, "public_dns4") {
			st.Mode = "public"
		} else if strings.Contains(body, "udp dport 53 tproxy") && !strings.Contains(body, "ip daddr") {
			st.Mode = "all"
		} else if strings.Contains(body, "ip daddr") {
			st.Mode = "custom"
		}
	}

	routeOut, _ := exec.Command("ip", "rule", "show").CombinedOutput()
	st.RouteOK = bytes.Contains(routeOut, []byte("lookup 100"))

	if desired.Enabled && normalizeMode(desired.Mode) == "all" {
		st.Warning = "Mode all intercepts every DNS on the interface — dangerous on BGP/transit hosts."
	}
	if desired.Enabled && !st.Applied {
		st.Warning = "Intercept enabled in settings but nft table not applied."
	}
	return st
}

func ensureRoutes(mark uint32) error {
	ms := fmt.Sprintf("0x%x", mark)
	_ = exec.Command("ip", "rule", "del", "fwmark", ms, "lookup", "100", "priority", "100").Run()
	_ = exec.Command("ip", "-6", "rule", "del", "fwmark", ms, "lookup", "100", "priority", "100").Run()
	if out, err := exec.Command("ip", "rule", "add", "fwmark", ms, "lookup", "100", "priority", "100").CombinedOutput(); err != nil {
		return fmt.Errorf("ip rule add: %w (%s)", err, bytes.TrimSpace(out))
	}
	_ = exec.Command("ip", "-6", "rule", "add", "fwmark", ms, "lookup", "100", "priority", "100").Run()
	if out, err := exec.Command("ip", "route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", "100").CombinedOutput(); err != nil {
		return fmt.Errorf("ip route replace: %w (%s)", err, bytes.TrimSpace(out))
	}
	_ = exec.Command("ip", "-6", "route", "replace", "local", "::/0", "dev", "lo", "table", "100").Run()
	return nil
}

var tproxyIfaceRe = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`)

func validateTProxyIface(iface string) error {
	if iface == "" || !tproxyIfaceRe.MatchString(iface) || strings.Contains(iface, "..") {
		return fmt.Errorf("invalid interface name: %q", iface)
	}
	if _, err := net.InterfaceByName(iface); err != nil {
		return fmt.Errorf("interface %q not found: %w", iface, err)
	}
	return nil
}

func applyNFT(cfg InterceptConfig) error {
	if err := validateTProxyIface(cfg.Iface); err != nil {
		return err
	}
	_ = exec.Command("nft", "delete", "table", "inet", "powersvx_tproxy").Run()

	var b strings.Builder
	b.WriteString("table inet powersvx_tproxy {\n")
	mode := normalizeMode(cfg.Mode)
	res := resolversFor(cfg)
	if mode != "all" {
		b.WriteString("  set public_dns4 {\n    type ipv4_addr\n    elements = { ")
		b.WriteString(strings.Join(res, ", "))
		b.WriteString(" }\n  }\n")
	}
	b.WriteString("  chain prerouting {\n")
	b.WriteString("    type filter hook prerouting priority mangle; policy accept;\n")
	fmt.Fprintf(&b, "    iifname != \"%s\" accept\n", cfg.Iface)
	b.WriteString("    fib daddr type local accept\n")
	mark := cfg.Mark
	if mark == 0 {
		mark = 1
	}
	if mode == "all" {
		fmt.Fprintf(&b, "    meta l4proto udp udp dport 53 tproxy ip to :53 meta mark set 0x%x counter accept\n", mark)
		fmt.Fprintf(&b, "    meta l4proto tcp tcp dport 53 tproxy ip to :53 meta mark set 0x%x counter accept\n", mark)
	} else {
		fmt.Fprintf(&b, "    ip daddr @public_dns4 udp dport 53 tproxy ip to :53 meta mark set 0x%x counter accept\n", mark)
		fmt.Fprintf(&b, "    ip daddr @public_dns4 tcp dport 53 tproxy ip to :53 meta mark set 0x%x counter accept\n", mark)
	}
	b.WriteString("  }\n}\n")

	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(b.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft apply: %w (%s)", err, bytes.TrimSpace(out))
	}
	return nil
}
