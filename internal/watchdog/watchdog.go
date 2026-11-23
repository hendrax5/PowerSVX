package watchdog

import (
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	checkInterval = 15 * time.Second
	// A sample counts as over the limit above overPercent of GOMEMLIMIT; overStreak such samples
	// in a row (two minutes) make the process exit.
	overPercent = 115
	overStreak  = 8
)

// sample is what one check compares and logs. InUse is the memory the process is using right
// now: heap spans holding objects, stacks and runtime structures. It leaves out heap the
// runtime keeps for reuse (idle spans), which is free memory, not a leak: Go's Sys counts that
// memory even after it was handed back to the OS, so Sys never drops after a burst of work.
type sample struct {
	InUse     uint64
	HeapInuse uint64
	Sys       uint64
}

func readSample() sample {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return sample{InUse: ms.Sys - ms.HeapIdle, HeapInuse: ms.HeapInuse, Sys: ms.Sys}
}

type monitor struct {
	limit uint64
	read  func() sample
	exit  func(code int)
	log   *slog.Logger
	bad   int
}

// check takes one sample and exits the process after overStreak consecutive samples with
// in-use memory above overPercent of the limit.
func (m *monitor) check() {
	s := m.read()
	threshold := m.limit / 100 * overPercent
	if s.InUse <= threshold {
		m.bad = 0
		return
	}
	m.bad++
	attrs := []any{
		"compared", "in_use", "in_use_mb", s.InUse >> 20, "heap_inuse_mb", s.HeapInuse >> 20,
		"sys_mb", s.Sys >> 20, "threshold_mb", threshold >> 20, "limit_mb", m.limit >> 20, "streak", m.bad,
	}
	if m.log != nil {
		m.log.Warn("watchdog memory pressure", attrs...)
	}
	if m.bad >= overStreak {
		if m.log != nil {
			m.log.Error("watchdog: memory over GOMEMLIMIT; exiting for docker restart", attrs...)
		}
		m.exit(2)
	}
}

// Start exits the process if in-use memory stays above GOMEMLIMIT (plus 15%).
// Docker then restarts the container (unless-stopped) instead of a silent DNS stall.
func Start(log *slog.Logger) {
	limit := parseGoMemLimit(os.Getenv("GOMEMLIMIT"))
	if limit == 0 {
		return
	}
	m := &monitor{limit: limit, read: readSample, exit: os.Exit, log: log}
	go func() {
		t := time.NewTicker(checkInterval)
		defer t.Stop()
		for range t.C {
			m.check()
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
