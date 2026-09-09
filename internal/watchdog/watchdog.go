package watchdog

import (
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Start exits the process if live memory stays above GOMEMLIMIT.
// Docker then restarts the container (unless-stopped) instead of a silent DNS stall.
func Start(log *slog.Logger) {
	limit := parseGoMemLimit(os.Getenv("GOMEMLIMIT"))
	if limit == 0 {
		return
	}
	go func() {
		bad := 0
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for range t.C {
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			if ms.Sys > limit*115/100 {
				bad++
				if log != nil {
					log.Warn("watchdog memory pressure",
						"sys_mb", ms.Sys/1024/1024,
						"limit_mb", limit/1024/1024,
						"streak", bad)
				}
				if bad >= 8 {
					if log != nil {
						log.Error("watchdog: memory over GOMEMLIMIT; exiting for docker restart")
					}
					os.Exit(2)
				}
				continue
			}
			bad = 0
		}
	}()
}

func parseGoMemLimit(s string) uint64 {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" {
		return 0
	}
	mult := uint64(1)
	switch {
	case strings.HasSuffix(s, "GIB"):
		mult = 1 << 30
		s = strings.TrimSuffix(s, "GIB")
	case strings.HasSuffix(s, "GB"):
		mult = 1_000_000_000
		s = strings.TrimSuffix(s, "GB")
	case strings.HasSuffix(s, "MIB"):
		mult = 1 << 20
		s = strings.TrimSuffix(s, "MIB")
	case strings.HasSuffix(s, "MB"):
		mult = 1_000_000
		s = strings.TrimSuffix(s, "MB")
	case strings.HasSuffix(s, "B"):
		s = strings.TrimSuffix(s, "B")
	}
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	if err != nil || n == 0 {
		return 0
	}
	return n * mult
}
