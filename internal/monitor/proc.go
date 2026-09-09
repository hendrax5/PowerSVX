package monitor

import (
	"runtime"
	"sync"
	"time"

	"github.com/powersvx/powersvx/internal/metrics"
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
			// Percent of total host capacity (0–100), not "one core".
			cores := float64(runtime.NumCPU())
			if cores < 1 {
				cores = 1
			}
			p.cpuPct = (delta / wall) * 100 / cores
			if p.cpuPct > 100 {
				p.cpuPct = 100
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
	enrichHostResources(&r)
	metrics.Goroutines.Set(float64(r.Goroutines))
	metrics.RSSBytes.Set(r.RSSMB * 1024 * 1024)
	if r.HostMemAvailableMB > 0 {
		metrics.HostMemAvailableBytes.Set(r.HostMemAvailableMB * 1024 * 1024)
		metrics.HostMemTotalBytes.Set(r.HostMemTotalMB * 1024 * 1024)
	}
	if r.DiskUsedPct > 0 {
		metrics.HostDiskUsedPercent.Set(r.DiskUsedPct)
	}
	if r.Load1 > 0 {
		metrics.HostLoad1.Set(r.Load1)
	}
	return r
}

// readProcessUsage is implemented per-OS.
// cpu is cumulative process CPU time; rss is resident set size in bytes.
func readProcessUsage() (cpu time.Duration, rss uint64, ok bool) {
	return readProcessUsageOS()
}
