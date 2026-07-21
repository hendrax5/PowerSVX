package ratelimit

import (
	"net"
	"sync"
	"time"
)

// Limiter is a token-bucket rate limiter keyed by client IP (/32 or exact).
type Limiter struct {
	mu          sync.Mutex
	buckets     map[string]*bucket
	qps         float64
	burst       float64
	whitelist   []*net.IPNet
	blockDur    time.Duration
	blocked     map[string]time.Time
	enabled     bool
}

type bucket struct {
	tokens float64
	last   time.Time
}

func New(enabled bool, qps, burst int, blockSeconds int, whitelistCIDRs []string) *Limiter {
	if qps <= 0 {
		qps = 100
	}
	if burst <= 0 {
		burst = 200
	}
	if blockSeconds <= 0 {
		blockSeconds = 300
	}
	l := &Limiter{
		buckets:   make(map[string]*bucket),
		blocked:   make(map[string]time.Time),
		qps:       float64(qps),
		burst:     float64(burst),
		blockDur:  time.Duration(blockSeconds) * time.Second,
		enabled:   enabled,
	}
	for _, cidr := range whitelistCIDRs {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			ip := net.ParseIP(cidr)
			if ip == nil {
				continue
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			n = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
		}
		l.whitelist = append(l.whitelist, n)
	}
	return l
}

func (l *Limiter) Enabled() bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.enabled
}

func (l *Limiter) SetEnabled(on bool) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.enabled = on
	l.mu.Unlock()
}

// Allow returns false if the client should be refused.
func (l *Limiter) Allow(ipStr string) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	on := l.enabled
	l.mu.Unlock()
	if !on {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true
	}
	for _, n := range l.whitelist {
		if n.Contains(ip) {
			return true
		}
	}
	key := ip.String()

	l.mu.Lock()
	defer l.mu.Unlock()

	if until, ok := l.blocked[key]; ok {
		if time.Now().Before(until) {
			return false
		}
		delete(l.blocked, key)
	}

	b := l.buckets[key]
	now := time.Now()
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * l.qps
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		l.blocked[key] = now.Add(l.blockDur)
		return false
	}
	b.tokens--
	return true
}

// BlockedIP is a currently blocked client.
type BlockedIP struct {
	IP        string    `json:"ip"`
	Until     time.Time `json:"until"`
	Remaining int       `json:"remaining_sec"`
}

// SnapshotBlocked returns currently blocked IPs (not yet expired).
func (l *Limiter) SnapshotBlocked(limit int) []BlockedIP {
	if l == nil {
		return nil
	}
	if limit <= 0 {
		limit = 20
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]BlockedIP, 0, len(l.blocked))
	for ip, until := range l.blocked {
		if now.Before(until) {
			out = append(out, BlockedIP{
				IP:        ip,
				Until:     until,
				Remaining: int(until.Sub(now).Seconds()) + 1,
			})
		} else {
			delete(l.blocked, ip)
		}
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}
