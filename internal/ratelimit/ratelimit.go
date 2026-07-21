package ratelimit

import (
	"net"
	"strings"
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
		whitelist: parseWhitelist(whitelistCIDRs),
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

// Config is the live rate-limit parameters.
type Config struct {
	Enabled       bool     `json:"enabled"`
	QPS           int      `json:"qps"`
	Burst         int      `json:"burst"`
	BlockDuration int      `json:"block_duration"`
	Whitelist     []string `json:"whitelist"`
}

// Configure updates QPS/burst/block duration/whitelist atomically.
func (l *Limiter) Configure(qps, burst, blockSeconds int, whitelistCIDRs []string) {
	if l == nil {
		return
	}
	if qps <= 0 {
		qps = 100
	}
	if burst <= 0 {
		burst = 200
	}
	if blockSeconds <= 0 {
		blockSeconds = 300
	}
	nets := parseWhitelist(whitelistCIDRs)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.qps = float64(qps)
	l.burst = float64(burst)
	l.blockDur = time.Duration(blockSeconds) * time.Second
	l.whitelist = nets
	// Reset buckets so new limits apply immediately; keep blocked until expiry.
	l.buckets = make(map[string]*bucket)
}

func parseWhitelist(cidrs []string) []*net.IPNet {
	var out []*net.IPNet
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
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
		out = append(out, n)
	}
	return out
}

// SnapshotConfig returns current limiter parameters.
func (l *Limiter) SnapshotConfig() Config {
	if l == nil {
		return Config{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	wl := make([]string, 0, len(l.whitelist))
	for _, n := range l.whitelist {
		wl = append(wl, n.String())
	}
	return Config{
		Enabled:       l.enabled,
		QPS:           int(l.qps),
		Burst:         int(l.burst),
		BlockDuration: int(l.blockDur / time.Second),
		Whitelist:     wl,
	}
}

// ClearBlocked removes temporary IP blocks.
func (l *Limiter) ClearBlocked() {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.blocked = make(map[string]time.Time)
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
