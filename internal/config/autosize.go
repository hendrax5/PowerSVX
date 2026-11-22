package config

import (
	"os"
	"strconv"
	"strings"
)

// GoMemLimitMB parses GOMEMLIMIT (e.g. "6442450944B", "6GiB", "6144MiB").
// Returns 0 when unset / unparsable.
func GoMemLimitMB() int {
	return goMemLimitMB()
}

// RSSDegradeThresholdMB is the RSS level at which /health reports degraded.
// When GOMEMLIMIT is set, use 95% of that soft heap (floor 1024MB); otherwise 4096MB.
func RSSDegradeThresholdMB() float64 {
	if g := GoMemLimitMB(); g > 0 {
		v := float64(g) * 0.95
		if v < 1024 {
			return 1024
		}
		return v
	}
	return 4096
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
