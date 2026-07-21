package monitor

import (
	"runtime"
	"sync"
	"time"
)

// processSampler tracks CPU% between snapshots using process CPU time.
type processSampler struct {
	mu       sync.Mutex
	lastCPU  time.Duration
	lastWall time.Time
	cpuPct   float64
	rssMB    float64
}

var globalProc = &processSampler{}

func (p *processSampler) sample() (cpuPct, rssMB float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	cpu, rss, ok := readProcessUsage()
	if !ok {
		return p.cpuPct, p.rssMB
	}
	p.rssMB = float64(rss) / (1024 * 1024)
	now := time.Now()
	if !p.lastWall.IsZero() && p.lastCPU > 0 {
		wall := now.Sub(p.lastWall).Seconds()
		if wall > 0.05 {
			delta := (cpu - p.lastCPU).Seconds()
			if delta < 0 {
				delta = 0
			}
			// Percent of a single core (can exceed 100 on multi-threaded bursts).
			p.cpuPct = (delta / wall) * 100
			if p.cpuPct > 100*float64(runtime.NumCPU()) {
				p.cpuPct = 100 * float64(runtime.NumCPU())
			}
		}
	}
	p.lastCPU = cpu
	p.lastWall = now
	return p.cpuPct, p.rssMB
}

func resourceSnapshot() Resources {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	cpuPct, rssMB := globalProc.sample()
	r := Resources{
		Goroutines: runtime.NumGoroutine(),
		AllocMB:    float64(ms.Alloc) / (1024 * 1024),
		SysMB:      float64(ms.Sys) / (1024 * 1024),
		HeapMB:     float64(ms.HeapAlloc) / (1024 * 1024),
		NumGC:      ms.NumGC,
		CPUPercent: cpuPct,
		RSSMB:      rssMB,
		NumCPU:     runtime.NumCPU(),
	}
	if r.RSSMB <= 0 {
		// Fallback when OS RSS unavailable (e.g. some Windows builds).
		r.RSSMB = r.HeapMB
	}
	return r
}

// readProcessUsage is implemented per-OS.
// cpu is cumulative process CPU time; rss is resident set size in bytes.
func readProcessUsage() (cpu time.Duration, rss uint64, ok bool) {
	return readProcessUsageOS()
}
