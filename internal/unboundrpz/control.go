package unboundrpz

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// ControlAddr is unbound-control host:port (plain, no TLS).
func ControlAddr() string {
	if v := strings.TrimSpace(os.Getenv("POWERSVX_UNBOUND_CONTROL")); v != "" {
		return v
	}
	return "127.0.0.1:8953"
}

// ReloadKeepCache asks Unbound to reload config/zones without flushing cache.
func ReloadKeepCache() error {
	out, err := ControlCommand("reload_keep_cache")
	if err != nil {
		return err
	}
	s := strings.TrimSpace(string(out))
	if s != "" && !strings.EqualFold(s, "ok") && !strings.HasPrefix(strings.ToLower(s), "ok") {
		// Some builds reply "ok\n"; treat non-empty non-ok as soft warning only if contains error.
		if strings.Contains(strings.ToLower(s), "error") {
			return fmt.Errorf("reload_keep_cache: %s", s)
		}
	}
	return nil
}

// DockerReload runs reload inside the unbound container (host-network deploy).
func DockerReload(container string) error {
	if container == "" {
		container = "powersvx-unbound-1"
	}
	cmd := exec.Command("docker", "exec", container, "unbound-control", "reload_keep_cache")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker exec unbound-control: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// TryReload attempts TCP control first, then docker exec.
func TryReload() error {
	if err := ReloadKeepCache(); err == nil {
		return nil
	} else if err2 := DockerReload(""); err2 == nil {
		return nil
	} else {
		return fmt.Errorf("reload failed: tcp=%v docker=%v", err, err2)
	}
}

// Stats fetches a subset of unbound-control stats_noreset.
func Stats() (map[string]float64, error) {
	out, err := ControlCommand("stats_noreset")
	if err != nil {
		return nil, err
	}
	m := map[string]float64{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		i := strings.IndexByte(line, '=')
		if i <= 0 {
			continue
		}
		k := line[:i]
		v, err := strconv.ParseFloat(line[i+1:], 64)
		if err != nil {
			continue
		}
		switch {
		case k == "total.num.queries" || k == "total.num.cachehits" || k == "total.num.cachemiss",
			k == "num.query.tcp" || k == "num.query.udp" || k == "mem.cache.rrset" || k == "mem.cache.message",
			k == "num.rrset.bogus" || k == "unwanted.queries",
			k == "total.num.recursivereplies" || k == "total.num.expired",
			k == "total.recursion.time.avg" || k == "total.recursion.time.median",
			k == "total.requestlist.avg" || k == "total.requestlist.max" || k == "total.requestlist.overwritten",
			k == "total.num.rx_udp" || k == "total.num.tx_udp",
			strings.HasPrefix(k, "num.rpz.action."),
			strings.HasPrefix(k, "num.query.type."):
			m[k] = v
		}
	}
	return m, nil
}

// ControlCommand talks to Unbound remote-control over plain TCP (control-use-cert: no).
// Prefers direct TCP so it works from the PowerSVX container on host networking
// without docker.sock or unbound-control binary.
func ControlCommand(cmd string) ([]byte, error) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return nil, fmt.Errorf("empty unbound control command")
	}
	addr := ControlAddr()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err == nil {
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := fmt.Fprintf(conn, "UBCT1 %s\n", cmd); err != nil {
			return nil, err
		}
		out, err := io.ReadAll(conn)
		if err != nil {
			return nil, err
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("empty reply from unbound-control %s", addr)
		}
		return out, nil
	}
	tcpErr := err

	container := os.Getenv("POWERSVX_UNBOUND_CONTAINER")
	if container == "" {
		container = "powersvx-unbound-1"
	}
	if _, e := exec.LookPath("docker"); e == nil {
		c := exec.Command("docker", "exec", container, "unbound-control", cmd)
		out, err := c.CombinedOutput()
		if err == nil && len(out) > 0 {
			return out, nil
		}
	}
	if p, e := exec.LookPath("unbound-control"); e == nil {
		host, port, _ := net.SplitHostPort(addr)
		if host == "" {
			host, port = "127.0.0.1", "8953"
		}
		c := exec.Command(p, "-s", host+"@"+port, cmd)
		out, err := c.CombinedOutput()
		if err == nil && len(out) > 0 {
			return out, nil
		}
	}
	return nil, fmt.Errorf("unbound control %q via %s: %w", cmd, addr, tcpErr)
}

// RPZActionTotal sums num.rpz.action.* counters (blocked / rewritten answers).
func RPZActionTotal(st map[string]float64) float64 {
	var sum float64
	for k, v := range st {
		if !strings.HasPrefix(k, "num.rpz.action.") {
			continue
		}
		// passthru is not a block
		if strings.HasSuffix(k, ".passthru") || strings.HasSuffix(k, ".disabled") {
			continue
		}
		sum += v
	}
	return sum
}

// CountZoneLines counts non-comment owner lines roughly (for health UI).
func CountZoneLines(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "$") || strings.HasPrefix(line, "@") {
			continue
		}
		n++
	}
	return n, sc.Err()
}

// WriteAccessControl generates Unbound ACL lines from CIDR list (included inside server:).
func WriteAccessControl(path string, cidrs []string) error {
	var b strings.Builder
	b.WriteString("# AUTO-GENERATED by PowerSVX - do not hand-edit\n")
	b.WriteString("access-control: 127.0.0.1/32 allow\n")
	b.WriteString("access-control: ::1/128 allow\n")
	if len(cidrs) == 0 {
		b.WriteString("access-control: 0.0.0.0/0 allow\n")
		b.WriteString("access-control: ::/0 allow\n")
	} else {
		for _, c := range cidrs {
			c = strings.TrimSpace(c)
			if c == "" {
				continue
			}
			if !strings.Contains(c, "/") {
				if strings.Contains(c, ":") {
					c += "/128"
				} else {
					c += "/32"
				}
			}
			fmt.Fprintf(&b, "access-control: %s allow\n", c)
		}
		b.WriteString("access-control: 0.0.0.0/0 refuse\n")
		b.WriteString("access-control: ::/0 refuse\n")
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// WaitControl polls until unbound-control responds or timeout.
func WaitControl(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		if _, err := Stats(); err == nil {
			return nil
		} else {
			last = err
		}
		time.Sleep(500 * time.Millisecond)
	}
	return last
}

// FlushDomain evicts a single domain from Unbound cache.
func FlushDomain(name string) (string, error) {
	clean := sanitizeUnboundDomain(name)
	if clean == "" {
		return "", fmt.Errorf("invalid domain name")
	}
	out, err := ControlCommand("flush " + clean + ".")
	return strings.TrimSpace(string(out)), err
}

// FlushZone evicts an entire zone subtree from Unbound cache.
func FlushZone(zone string) (string, error) {
	if strings.TrimSpace(zone) == "." {
		out, err := ControlCommand("flush_zone .")
		return strings.TrimSpace(string(out)), err
	}
	clean := sanitizeUnboundDomain(zone)
	if clean == "" {
		return "", fmt.Errorf("invalid zone name")
	}
	out, err := ControlCommand("flush_zone " + clean + ".")
	return strings.TrimSpace(string(out)), err
}

// FlushType evicts a specific RRset type for name from Unbound cache.
func FlushType(name, qtype string) (string, error) {
	clean := sanitizeUnboundDomain(name)
	qt := strings.ToUpper(strings.TrimSpace(qtype))
	if clean == "" || qt == "" {
		return "", fmt.Errorf("invalid domain or qtype")
	}
	for _, r := range qt {
		if !((r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return "", fmt.Errorf("invalid qtype")
		}
	}
	out, err := ControlCommand("flush_type " + clean + ". " + qt)
	return strings.TrimSpace(string(out)), err
}

// FlushNegative clears Unbound negative cache entries.
func FlushNegative() (string, error) {
	out, err := ControlCommand("flush_negative")
	return strings.TrimSpace(string(out)), err
}

// DumpCache returns filtered RRset cache lines from Unbound dump_cache, capped to limit lines.
func DumpCache(filter string, limit int) ([]string, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	filter = strings.ToLower(strings.TrimSpace(filter))
	out, err := ControlCommand("dump_cache")
	if err != nil {
		return nil, err
	}
	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "START_") || strings.HasPrefix(line, "END_") || strings.HasPrefix(line, ";") {
			continue
		}
		if filter != "" && !strings.Contains(strings.ToLower(line), filter) {
			continue
		}
		lines = append(lines, line)
		if len(lines) >= limit {
			break
		}
	}
	return lines, nil
}
