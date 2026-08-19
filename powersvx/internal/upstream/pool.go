// Package upstream implements a health-checked, latency-aware pool of forwarding
// upstreams. Dead or slow resolvers are demoted so misses don't pay their
// latency: queries are tried against a lock-free ranked snapshot (healthy first,
// fastest first), failures demote a server after N consecutive errors, and a
// background prober revives servers and refreshes the ranking.
package upstream

import (
	"errors"
	"sort"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"powersvx/internal/metrics"
)

var ErrAllDown = errors.New("all upstreams failed")

type Server struct {
	Addr   string
	up     atomic.Bool
	fails  atomic.Uint32
	ewmaNs atomic.Uint64
}

func (s *Server) markOK(rtt time.Duration) {
	s.fails.Store(0)
	s.up.Store(true)
	cur := uint64(rtt.Nanoseconds())
	prev := s.ewmaNs.Load()
	if prev == 0 {
		s.ewmaNs.Store(cur)
	} else {
		s.ewmaNs.Store((prev*8 + cur*2) / 10) // EWMA, alpha=0.2
	}
}

func (s *Server) markFail(maxFails uint32) {
	if s.fails.Add(1) >= maxFails {
		s.up.Store(false)
	}
}

type Pool struct {
	servers  []*Server
	ranked   atomic.Pointer[[]*Server]
	udp, tcp *dns.Client
	maxFails uint32
	m        *metrics.Metrics
	quit     chan struct{}
}

func New(addrs []string, timeout time.Duration, maxFails int, probeInterval time.Duration, m *metrics.Metrics) *Pool {
	if maxFails < 1 {
		maxFails = 3
	}
	p := &Pool{
		udp:      &dns.Client{Net: "udp", Timeout: timeout},
		tcp:      &dns.Client{Net: "tcp", Timeout: timeout},
		maxFails: uint32(maxFails),
		m:        m,
		quit:     make(chan struct{}),
	}
	for _, a := range addrs {
		s := &Server{Addr: a}
		s.up.Store(true)
		p.servers = append(p.servers, s)
	}
	p.rerank()
	if probeInterval <= 0 {
		probeInterval = 10 * time.Second
	}
	go p.prober(probeInterval)
	return p
}

func (p *Pool) Close() { close(p.quit) }

// Exchange sends req to the best available upstream, failing over on error or
// truncation. The ranked snapshot is loaded lock-free.
func (p *Pool) Exchange(req *dns.Msg) (*dns.Msg, error) {
	snap := p.ranked.Load()
	if snap == nil {
		return nil, ErrAllDown
	}
	var lastErr error = ErrAllDown
	for _, s := range *snap {
		t0 := time.Now()
		resp, _, err := p.udp.Exchange(req, s.Addr)
		if err != nil {
			lastErr = err
			s.markFail(p.maxFails)
			if p.m != nil {
				p.m.IncUpstreamErr()
			}
			continue
		}
		if resp.Truncated {
			if p.m != nil {
				p.m.IncTCP()
			}
			resp2, _, err2 := p.tcp.Exchange(req, s.Addr)
			if err2 != nil {
				lastErr = err2
				s.markFail(p.maxFails)
				if p.m != nil {
					p.m.IncUpstreamErr()
				}
				continue
			}
			resp = resp2
		}
		s.markOK(time.Since(t0))
		return resp, nil
	}
	return nil, lastErr
}

// rerank publishes a new ordering: healthy servers first, each group ordered by
// ascending EWMA latency. Unhealthy servers stay at the tail so the pool still
// tries them when everything is down.
func (p *Pool) rerank() {
	ss := make([]*Server, len(p.servers))
	copy(ss, p.servers)
	sort.SliceStable(ss, func(i, j int) bool {
		ui, uj := ss[i].up.Load(), ss[j].up.Load()
		if ui != uj {
			return ui
		}
		return ss[i].ewmaNs.Load() < ss[j].ewmaNs.Load()
	})
	p.ranked.Store(&ss)
}

// prober revives DOWN upstreams with a lightweight probe and refreshes the
// ranking. Healthy upstreams are intentionally NOT probed — they are demoted
// only by real query failures, which avoids false-negatives from synthetic
// probes being rate-limited by a busy but healthy resolver.
func (p *Pool) prober(interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	probe := new(dns.Msg)
	probe.SetQuestion(".", dns.TypeNS)
	probe.RecursionDesired = true
	for {
		select {
		case <-p.quit:
			return
		case <-t.C:
		}
		for _, s := range p.servers {
			if s.up.Load() {
				continue // only probe down servers to revive them
			}
			q := probe.Copy()
			q.Id = dns.Id()
			t0 := time.Now()
			if resp, _, err := p.udp.Exchange(q, s.Addr); err == nil && resp != nil {
				s.markOK(time.Since(t0))
			}
		}
		p.rerank()
	}
}

// Stats returns a per-upstream snapshot for low-cardinality metrics (few
// upstreams => safe to label by address).
func (p *Pool) Stats() []metrics.UpstreamStat {
	out := make([]metrics.UpstreamStat, 0, len(p.servers))
	for _, s := range p.servers {
		out = append(out, metrics.UpstreamStat{
			Addr:       s.Addr,
			Up:         s.up.Load(),
			RTTSeconds: float64(s.ewmaNs.Load()) / 1e9,
		})
	}
	return out
}
