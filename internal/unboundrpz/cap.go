package unboundrpz

import (
	"bufio"
	"os"
	"strconv"
	"strings"

	"github.com/powersvx/powersvx/internal/allowlist"
)

const (
	prioHigh = 0
	prioMid  = 1
	prioLow  = 2
	prioN    = 3
)

// ConvertHostsOpts controls hosts→RPZ conversion.
// MaxEntries 0 means unlimited (full feed).
type ConvertHostsOpts struct {
	Action     string
	Target     string
	MaxEntries int
}

// MaxEntriesFromEnv reads POWERSVX_RPZ_MAX_ENTRIES.
//
//	unset / empty → auto from host MemTotal (safe partial on small VPS)
//	0 / unlimited / -1 → no cap
//	positive int → hard cap
//
// Auto defaults (MemTotal):
//
//	< 14 GiB → 1_500_000
//	< 24 GiB → 5_000_000
//	≥ 24 GiB → unlimited
func MaxEntriesFromEnv() int {
	v := strings.TrimSpace(os.Getenv("POWERSVX_RPZ_MAX_ENTRIES"))
	if v == "" {
		return autoMaxEntries(hostMemTotalMB())
	}
	switch strings.ToLower(v) {
	case "0", "unlimited", "-1", "full", "off":
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return autoMaxEntries(hostMemTotalMB())
	}
	return n
}

func autoMaxEntries(memMB int) int {
	switch {
	case memMB > 0 && memMB < 14*1024:
		return 1_500_000
	case memMB > 0 && memMB < 24*1024:
		return 5_000_000
	default:
		return 0
	}
}

func hostMemTotalMB() int {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}
		kb, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || kb < 65536 {
			return 0
		}
		return int(kb / 1024)
	}
	return 0
}

// namePriority ranks names for partial RPZ when MaxEntries is set.
// High: apex-like / .id phishing. Mid: shallow subdomains. Low: deep trees.
func namePriority(name string) int {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" {
		return prioLow
	}
	labels := strings.Count(name, ".") + 1
	if strings.HasSuffix(name, ".id") {
		if labels <= 4 {
			return prioHigh
		}
		return prioMid
	}
	switch {
	case labels <= 2:
		return prioHigh
	case labels <= 3:
		return prioMid
	default:
		return prioLow
	}
}

func parseHostsName(line string) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return ""
	}
	fields := strings.Fields(line)
	name := fields[0]
	if len(fields) >= 2 && (looksIP(fields[0]) || fields[0] == "0.0.0.0" || fields[0] == "127.0.0.1") {
		name = fields[1]
	}
	name = rpzOwner(name)
	if name == "" || name == "localhost" {
		return ""
	}
	if allowlist.OfficialBankName(name) {
		return ""
	}
	return name
}
