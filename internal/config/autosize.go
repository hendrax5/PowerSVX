package config

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// Autosize fills zero-valued capacity knobs from host RAM/CPU so upgrades
// take effect on the next process start without editing TOML.
//
// Rules (only when the field is <= 0):
//   - cache.max_size_mb  ≈ 12% of MemTotal (clamped), further capped to ~35% of GOMEMLIMIT
//   - resolver.max_inflight ≈ NumCPU * 512 (clamped 1024–16384)
//
// Explicit positive TOML/runtime values are left untouched.
func (c *Config) Autosize() (cacheMB, inflight, memMB, cpus int) {
	memMB = hostMemMB()
	cpus = runtime.NumCPU()
	if cpus < 1 {
		cpus = 1
	}

	if c.Cache.MaxSizeMB <= 0 {
		mb := memMB * 12 / 100
		if mb < 256 {
			mb = 256
		}
		if mb > 16384 {
			mb = 16384
		}
		if g := goMemLimitMB(); g > 0 {
			capMB := g * 35 / 100
			if capMB < 256 {
				capMB = 256
			}
			if mb > capMB {
				mb = capMB
			}
		}
		c.Cache.MaxSizeMB = mb
	}
	cacheMB = c.Cache.MaxSizeMB

	if c.Resolver.MaxInflight <= 0 {
		n := cpus * 512
		if n < 1024 {
			n = 1024
		}
		if n > 16384 {
			n = 16384
		}
		c.Resolver.MaxInflight = n
	}
	inflight = c.Resolver.MaxInflight
	return cacheMB, inflight, memMB, cpus
}

func hostMemMB() int {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 2048
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
			return 2048
		}
		kb, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil || kb < 65536 {
			return 2048
		}
		return int(kb / 1024)
	}
	return 2048
}

// goMemLimitMB parses GOMEMLIMIT (e.g. "6442450944B", "6GiB", "6144MiB").
func goMemLimitMB() int {
	s := strings.TrimSpace(os.Getenv("GOMEMLIMIT"))
	if s == "" {
		return 0
	}
	upper := strings.ToUpper(s)
	mult := int64(1)
	switch {
	case strings.HasSuffix(upper, "KIB"):
		mult = 1024
		s = s[:len(s)-3]
	case strings.HasSuffix(upper, "MIB"):
		mult = 1024 * 1024
		s = s[:len(s)-3]
	case strings.HasSuffix(upper, "GIB"):
		mult = 1024 * 1024 * 1024
		s = s[:len(s)-3]
	case strings.HasSuffix(upper, "KB"):
		mult = 1000
		s = s[:len(s)-2]
	case strings.HasSuffix(upper, "MB"):
		mult = 1000 * 1000
		s = s[:len(s)-2]
	case strings.HasSuffix(upper, "GB"):
		mult = 1000 * 1000 * 1000
		s = s[:len(s)-2]
	case strings.HasSuffix(upper, "B"):
		s = s[:len(s)-1]
	}
	s = strings.TrimSpace(s)
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return 0
	}
	bytes := n * mult
	return int(bytes / (1024 * 1024))
}
