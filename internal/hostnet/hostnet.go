package hostnet

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// InterfaceInfo represents a physical or primary network interface on the host.
type InterfaceInfo struct {
	Name      string   `json:"name"`
	MAC       string   `json:"mac"`
	State     string   `json:"state"` // UP, DOWN, UNKNOWN
	MTU       int      `json:"mtu"`
	Speed     string   `json:"speed,omitempty"`
	IPv4      []string `json:"ipv4"` // e.g. ["103.162.17.246/28"]
	IPv6      []string `json:"ipv6"`
	Gateway   string   `json:"gateway,omitempty"`
	DNS       []string `json:"dns,omitempty"`
	RxBytes   uint64   `json:"rx_bytes"`
	TxBytes   uint64   `json:"tx_bytes"`
	RxPackets uint64   `json:"rx_packets"`
	TxPackets uint64   `json:"tx_packets"`
	IsDefault bool     `json:"is_default"`
}

// HostNetworkPayload is returned by the GET API endpoint.
type HostNetworkPayload struct {
	Interfaces     []InterfaceInfo `json:"interfaces"`
	DefaultGateway string          `json:"default_gateway"`
	DefaultIface   string          `json:"default_iface"`
	SystemDNS      []string        `json:"system_dns"`
	NetplanActive  bool            `json:"netplan_active"`
	NetplanPath    string          `json:"netplan_path,omitempty"`
	Note           string          `json:"note"`
}

// ApplyRequest contains desired interface network configuration.
type ApplyRequest struct {
	Iface     string   `json:"iface"`
	IP        string   `json:"ip"`                // e.g. "103.162.17.246/28"
	Gateway   string   `json:"gateway,omitempty"` // e.g. "103.162.17.241"
	DNS       []string `json:"dns,omitempty"`     // e.g. ["8.8.8.8", "1.1.1.1"]
	KeepOldIP bool     `json:"keep_old_ip"`       // keeps previous IP as alias to prevent instant drop
}

// RemoveIPRequest is used to prune an old alias IP after new IP is verified.
type RemoveIPRequest struct {
	Iface string `json:"iface"`
	IP    string `json:"ip"` // e.g. "103.162.17.246/28"
}

var (
	mu          sync.Mutex
	ifaceNameRe = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`)
)

func validateIfaceName(iface string) error {
	if iface == "" || !ifaceNameRe.MatchString(iface) || strings.Contains(iface, "..") {
		return fmt.Errorf("invalid interface name: %q", iface)
	}
	return nil
}

func sanitizeDNSList(dns []string) ([]string, error) {
	var clean []string
	seen := make(map[string]struct{}, len(dns))
	for _, raw := range dns {
		d := strings.TrimSpace(raw)
		if d == "" {
			continue
		}
		ip := net.ParseIP(d)
		if ip == nil {
			return nil, fmt.Errorf("invalid DNS IP address: %q", raw)
		}
		s := ip.String()
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			clean = append(clean, s)
		}
	}
	return clean, nil
}

// ListInterfaces inspects the host network stack and returns active interfaces.
func ListInterfaces() (*HostNetworkPayload, error) {
	mu.Lock()
	defer mu.Unlock()
	return listInterfacesLocked()
}

func listInterfacesLocked() (*HostNetworkPayload, error) {
	defaultGw, defaultIface := getDefaultRoute()
	dnsServers := getSystemDNS()

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate interfaces: %w", err)
	}

	var results []InterfaceInfo
	for _, iface := range ifaces {
		name := iface.Name
		// Ignore virtual loopback, docker bridges, and container veth pairs
		if name == "lo" || strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "br-") {
			continue
		}

		info := InterfaceInfo{
			Name:      name,
			MAC:       iface.HardwareAddr.String(),
			MTU:       iface.MTU,
			State:     "DOWN",
			IPv4:      []string{},
			IPv6:      []string{},
			DNS:       dnsServers,
			IsDefault: name == defaultIface,
		}

		if (iface.Flags & net.FlagUp) != 0 {
			info.State = "UP"
		}

		if info.IsDefault {
			info.Gateway = defaultGw
		}

		// Read addrs
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if ipNet.IP.To4() != nil {
				info.IPv4 = append(info.IPv4, ipNet.String())
			} else if !ipNet.IP.IsLinkLocalUnicast() {
				info.IPv6 = append(info.IPv6, ipNet.String())
			}
		}

		// Read sysfs stats if available
		info.Speed = readSysfsString(fmt.Sprintf("/sys/class/net/%s/speed", name))
		if info.Speed != "" && info.Speed != "-1" {
			info.Speed += " Mbps"
		}
		info.RxBytes = readSysfsUint64(fmt.Sprintf("/sys/class/net/%s/statistics/rx_bytes", name))
		info.TxBytes = readSysfsUint64(fmt.Sprintf("/sys/class/net/%s/statistics/tx_bytes", name))
		info.RxPackets = readSysfsUint64(fmt.Sprintf("/sys/class/net/%s/statistics/rx_packets", name))
		info.TxPackets = readSysfsUint64(fmt.Sprintf("/sys/class/net/%s/statistics/tx_packets", name))

		results = append(results, info)
	}

	netplanDir := getNetplanDir()
	netplanActive := dirExists(netplanDir)

	return &HostNetworkPayload{
		Interfaces:     results,
		DefaultGateway: defaultGw,
		DefaultIface:   defaultIface,
		SystemDNS:      dnsServers,
		NetplanActive:  netplanActive,
		NetplanPath:    netplanDir,
		Note:           "Host network changes apply live to the Linux kernel. To prevent connection drops, KeepOldIP retains your current address during transition.",
	}, nil
}

// ApplyConfig applies IP and route changes live via ip route / ip addr, and writes Netplan YAML.
func ApplyConfig(req ApplyRequest) (*HostNetworkPayload, error) {
	mu.Lock()
	defer mu.Unlock()

	req.Iface = strings.TrimSpace(req.Iface)
	req.IP = strings.TrimSpace(req.IP)
	req.Gateway = strings.TrimSpace(req.Gateway)

	if err := validateIfaceName(req.Iface); err != nil {
		return nil, err
	}

	cleanDNS, err := sanitizeDNSList(req.DNS)
	if err != nil {
		return nil, err
	}
	req.DNS = cleanDNS

	// Validate IP / CIDR format
	ip, ipNet, err := net.ParseCIDR(req.IP)
	if err != nil {
		// If user didn't append /prefix, check if valid IPv4 and default to /24
		parsedIP := net.ParseIP(req.IP)
		if parsedIP == nil || parsedIP.To4() == nil {
			return nil, fmt.Errorf("invalid IPv4 address or CIDR format: %s (example: 103.162.17.246/28)", req.IP)
		}
		req.IP = parsedIP.String() + "/24"
		ip, ipNet, _ = net.ParseCIDR(req.IP)
	} else {
		req.IP = ipNet.String()
		ones, _ := ipNet.Mask.Size()
		req.IP = fmt.Sprintf("%s/%d", ip.To4().String(), ones)
	}

	if ip.To4() == nil {
		return nil, fmt.Errorf("only IPv4 addresses are currently supported for host network config")
	}

	// Validate Gateway if provided
	if req.Gateway != "" {
		gwIP := net.ParseIP(req.Gateway)
		if gwIP == nil || gwIP.To4() == nil {
			return nil, fmt.Errorf("invalid IPv4 gateway format: %s", req.Gateway)
		}
		req.Gateway = gwIP.To4().String()
		if !ipNet.Contains(gwIP) {
			// Gateway is outside subnet; warn but continue if /32 or point-to-point
		}
	}

	// 1. Check current addresses on interface
	curIfaces, _ := net.Interfaces()
	var targetIface *net.Interface
	for i := range curIfaces {
		if curIfaces[i].Name == req.Iface {
			targetIface = &curIfaces[i]
			break
		}
	}
	if targetIface == nil {
		return nil, fmt.Errorf("interface %s not found on host", req.Iface)
	}

	curAddrs, _ := targetIface.Addrs()
	var oldIPv4 []string
	alreadyHasNewIP := false
	for _, a := range curAddrs {
		if ipN, ok := a.(*net.IPNet); ok && ipN.IP.To4() != nil {
			if ipN.String() == req.IP {
				alreadyHasNewIP = true
			} else {
				oldIPv4 = append(oldIPv4, ipN.String())
			}
		}
	}

	// 2. Add New IP via /usr/sbin/ip (live kernel apply)
	if !alreadyHasNewIP {
		out, err := execCommand("ip", "addr", "add", req.IP, "dev", req.Iface)
		if err != nil {
			// If already exists with different scope or duplicate error, ignore
			if !strings.Contains(strings.ToLower(out), "file exists") {
				return nil, fmt.Errorf("failed to add IP %s on %s: %s (%w)", req.IP, req.Iface, out, err)
			}
		}
	}

	// 3. Update Default Gateway if specified
	if req.Gateway != "" {
		out, err := execCommand("ip", "route", "replace", "default", "via", req.Gateway, "dev", req.Iface)
		if err != nil {
			return nil, fmt.Errorf("failed to update default gateway to %s: %s (%w)", req.Gateway, out, err)
		}
	}

	// 4. If KeepOldIP is FALSE, remove previous IP addresses
	if !req.KeepOldIP {
		for _, old := range oldIPv4 {
			_, _ = execCommand("ip", "addr", "del", old, "dev", req.Iface)
		}
	}

	// 5. Write Netplan YAML for persistent boot config
	addrsForBoot := []string{req.IP}
	if req.KeepOldIP {
		addrsForBoot = append(addrsForBoot, oldIPv4...)
	}
	if err := writeNetplanConfig(req, addrsForBoot); err != nil {
		return nil, fmt.Errorf("kernel updated but netplan persist failed: %w", err)
	}

	return listInterfacesLocked()
}

// RemoveIP removes a secondary or old IP address from the interface.
func RemoveIP(req RemoveIPRequest) (*HostNetworkPayload, error) {
	mu.Lock()
	defer mu.Unlock()

	req.Iface = strings.TrimSpace(req.Iface)
	req.IP = strings.TrimSpace(req.IP)

	if err := validateIfaceName(req.Iface); err != nil {
		return nil, err
	}
	if req.IP == "" {
		return nil, fmt.Errorf("IP is required")
	}
	if ip, ipNet, err := net.ParseCIDR(req.IP); err != nil || ip.To4() == nil {
		parsed := net.ParseIP(req.IP)
		if parsed == nil || parsed.To4() == nil {
			return nil, fmt.Errorf("invalid IPv4 address or CIDR format: %s", req.IP)
		}
	} else if ones, _ := ipNet.Mask.Size(); ones > 0 {
		req.IP = fmt.Sprintf("%s/%d", ip.To4().String(), ones)
	}

	out, err := execCommand("ip", "addr", "del", req.IP, "dev", req.Iface)
	if err != nil {
		return nil, fmt.Errorf("failed to remove IP %s from %s: %s (%w)", req.IP, req.Iface, out, err)
	}

	// Refresh persistent netplan config if managed by PowerSVX
	if netplanDir := getNetplanDir(); dirExists(netplanDir) {
		cfgFile := filepath.Join(netplanDir, "60-powersvx.yaml")
		if _, statErr := os.Stat(cfgFile); statErr == nil {
			if payload, listErr := listInterfacesLocked(); listErr == nil {
				for _, iface := range payload.Interfaces {
					if iface.Name == req.Iface && len(iface.IPv4) > 0 {
						syncReq := ApplyRequest{
							Iface:   iface.Name,
							IP:      iface.IPv4[0],
							Gateway: iface.Gateway,
							DNS:     iface.DNS,
						}
						if err := writeNetplanConfig(syncReq, iface.IPv4); err != nil {
							return nil, fmt.Errorf("IP removed from kernel, but failed updating netplan: %w", err)
						}
						break
					}
				}
			}
		}
	}

	return listInterfacesLocked()
}

func writeNetplanConfig(req ApplyRequest, addresses []string) error {
	if err := validateIfaceName(req.Iface); err != nil {
		return err
	}
	cleanDNS, err := sanitizeDNSList(req.DNS)
	if err != nil {
		return err
	}
	if req.Gateway != "" {
		gwIP := net.ParseIP(req.Gateway)
		if gwIP == nil || gwIP.To4() == nil {
			return fmt.Errorf("invalid gateway IP: %q", req.Gateway)
		}
	}

	var validAddrs []string
	for _, a := range addresses {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(a); err != nil {
			return fmt.Errorf("invalid CIDR address for netplan: %q", a)
		}
		validAddrs = append(validAddrs, fmt.Sprintf("      - %q", a))
	}
	if len(validAddrs) == 0 {
		return fmt.Errorf("at least one valid CIDR address is required for netplan")
	}

	netplanDir := getNetplanDir()
	if !dirExists(netplanDir) {
		return nil
	}

	// Write to 60-powersvx.yaml (Netplan merges in lexical order, overriding 50-cloud-init)
	filePath := filepath.Join(netplanDir, "60-powersvx.yaml")

	var dnsLines string
	if len(cleanDNS) > 0 {
		var list []string
		for _, d := range cleanDNS {
			list = append(list, fmt.Sprintf("        - %s", d))
		}
		dnsLines = "      nameservers:\n        addresses:\n" + strings.Join(list, "\n") + "\n"
	} else {
		dnsLines = "      nameservers:\n        addresses:\n        - 8.8.8.8\n        - 1.1.1.1\n"
	}

	var routeLines string
	if req.Gateway != "" {
		routeLines = fmt.Sprintf("      routes:\n      - to: default\n        via: %s\n", req.Gateway)
	}

	content := fmt.Sprintf(`# AUTO-GENERATED BY POWERSVX HOST NETWORK MANAGER
network:
  version: 2
  ethernets:
    %s:
      addresses:
%s
%s%s`, req.Iface, strings.Join(validAddrs, "\n"), dnsLines, routeLines)

	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		return err
	}

	// Try running netplan generate if netplan binary exists
	_, _ = execCommand("netplan", "generate")
	return nil
}

func getNetplanDir() string {
	if d := os.Getenv("POWERSVX_NETPLAN_DIR"); d != "" {
		return d
	}
	if dirExists("/etc/netplan") {
		return "/etc/netplan"
	}
	return ""
}

func getDefaultRoute() (gw string, iface string) {
	// 1. Try ip route show default
	out, err := execCommand("ip", "route", "show", "default")
	if err == nil && out != "" {
		// Example: "default via 103.162.17.241 dev eth0 proto static"
		re := regexp.MustCompile(`default via ([^\s]+) dev ([^\s]+)`)
		m := re.FindStringSubmatch(out)
		if len(m) >= 3 {
			return m[1], m[2]
		}
	}

	// 2. Fallback to /proc/net/route
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 && fields[1] == "00000000" { // Destination 0.0.0.0
			gwHex := fields[2]
			if len(gwHex) == 8 {
				b0, _ := strconv.ParseUint(gwHex[6:8], 16, 8)
				b1, _ := strconv.ParseUint(gwHex[4:6], 16, 8)
				b2, _ := strconv.ParseUint(gwHex[2:4], 16, 8)
				b3, _ := strconv.ParseUint(gwHex[0:2], 16, 8)
				return fmt.Sprintf("%d.%d.%d.%d", b0, b1, b2, b3), fields[0]
			}
		}
	}
	return "", ""
}

func getSystemDNS() []string {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return []string{"8.8.8.8", "1.1.1.1"}
	}
	defer f.Close()

	var servers []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "nameserver ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				servers = append(servers, parts[1])
			}
		}
	}
	if len(servers) == 0 {
		return []string{"8.8.8.8", "1.1.1.1"}
	}
	return servers
}

func execCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func readSysfsString(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func readSysfsUint64(path string) uint64 {
	s := readSysfsString(path)
	if s == "" {
		return 0
	}
	v, _ := strconv.ParseUint(s, 10, 64)
	return v
}

func dirExists(path string) bool {
	if path == "" {
		return false
	}
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}
