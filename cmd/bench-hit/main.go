package main

import (
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/powersvx/powersvx/internal/cache"
)

// Micro-benchmark for L1 cache hit path (pre-encoded wire + copy).
func main() {
	c := cache.NewL1(1000)
	wire := make([]byte, 256)
	for i := range wire {
		wire[i] = byte(i)
	}
	k := cache.Key("bench.example.com.", 1)
	c.Set(k, wire, time.Hour, 0)

	const n = 100_000
	samples := make([]time.Duration, n)
	for i := 0; i < n; i++ {
		start := time.Now()
		e, ok := c.Get(k)
		if !ok {
			fmt.Fprintln(os.Stderr, "unexpected miss")
			os.Exit(1)
		}
		_ = e.CloneWire()
		samples[i] = time.Since(start)
	}

	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	p50 := samples[n*50/100]
	p99 := samples[n*99/100]
	p999 := samples[n*999/1000]
	fmt.Printf("L1 hit samples=%d p50=%v p99=%v p999=%v\n", n, p50, p99, p999)
	if p99 > time.Millisecond {
		fmt.Fprintf(os.Stderr, "FAIL: p99 %v exceeds 1ms target\n", p99)
		os.Exit(1)
	}
	fmt.Println("PASS: L1 hit p99 < 1ms")
}
