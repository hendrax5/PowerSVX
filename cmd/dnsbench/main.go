// Command dnsbench fires UDP DNS queries at a target resolver and reports
// sustained QPS plus p50/p95/p99 latency. Modes isolate cache-hit, miss,
// NXDOMAIN flood, and mixed qtype paths.
//
//	go run ./cmd/dnsbench -server 127.0.0.1:53 -mode hit -c 100 -d 20s
package main

import (
	"flag"
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

func main() {
	server := flag.String("server", "127.0.0.1:53", "target resolver host:port")
	mode := flag.String("mode", "hit", "hit|miss|nx|mixed")
	base := flag.String("domain", "example.com.", "base domain for hit/nx modes")
	conc := flag.Int("c", 50, "concurrent workers")
	dur := flag.Duration("d", 10*time.Second, "test duration")
	timeout := flag.Duration("timeout", 2*time.Second, "per-query timeout")
	flag.Parse()

	var (
		sent   uint64
		ok     uint64
		errs   uint64
		nx     uint64
		servf  uint64
		latMu  sync.Mutex
		latAll []time.Duration
	)

	deadline := time.Now().Add(*dur)
	var wg sync.WaitGroup
	start := time.Now()

	for w := 0; w < *conc; w++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed))
			cl := &dns.Client{Net: "udp", Timeout: *timeout}
			local := make([]time.Duration, 0, 4096)
			for time.Now().Before(deadline) {
				msg := buildQuery(*mode, *base, rng)
				atomic.AddUint64(&sent, 1)
				t0 := time.Now()
				resp, _, err := cl.Exchange(msg, *server)
				lat := time.Since(t0)
				if err != nil {
					atomic.AddUint64(&errs, 1)
					continue
				}
				local = append(local, lat)
				switch resp.Rcode {
				case dns.RcodeSuccess:
					atomic.AddUint64(&ok, 1)
				case dns.RcodeNameError:
					atomic.AddUint64(&nx, 1)
				case dns.RcodeServerFailure:
					atomic.AddUint64(&servf, 1)
				default:
					atomic.AddUint64(&ok, 1)
				}
			}
			latMu.Lock()
			latAll = append(latAll, local...)
			latMu.Unlock()
		}(int64(w)*7919 + time.Now().UnixNano())
	}
	wg.Wait()
	elapsed := time.Since(start)

	sort.Slice(latAll, func(i, j int) bool { return latAll[i] < latAll[j] })
	qps := float64(sent) / elapsed.Seconds()

	fmt.Println("========== PowerSVX dnsbench ==========")
	fmt.Printf("target=%s mode=%s concurrency=%d duration=%s\n", *server, *mode, *conc, elapsed.Round(time.Millisecond))
	fmt.Printf("sent=%d  ok=%d  nxdomain=%d  servfail=%d  errors=%d\n", sent, ok, nx, servf, errs)
	fmt.Printf("QPS(sustained) = %.0f\n", qps)
	if len(latAll) > 0 {
		fmt.Printf("latency  p50=%s  p95=%s  p99=%s  max=%s\n",
			pct(latAll, 50), pct(latAll, 95), pct(latAll, 99), latAll[len(latAll)-1])
	}
	fmt.Println("=======================================")
}

func buildQuery(mode, base string, rng *rand.Rand) *dns.Msg {
	m := new(dns.Msg)
	m.RecursionDesired = true
	switch mode {
	case "miss":
		m.SetQuestion(fmt.Sprintf("r%d-%d.%s", rng.Int63(), rng.Int31(), dns.Fqdn(base)), dns.TypeA)
	case "nx":
		m.SetQuestion(fmt.Sprintf("nx-%d.%s", rng.Int63(), dns.Fqdn(base)), dns.TypeA)
	case "mixed":
		types := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeTXT}
		fq := dns.Fqdn(base)
		names := []string{"a." + fq, "b." + fq, "c." + fq}
		m.SetQuestion(names[rng.Intn(len(names))], types[rng.Intn(len(types))])
	default:
		m.SetQuestion(dns.Fqdn(base), dns.TypeA)
	}
	m.SetEdns0(1232, false)
	return m
}

func pct(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := (p * len(sorted)) / 100
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}
