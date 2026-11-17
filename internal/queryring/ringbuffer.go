package queryring

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const DefaultCap = 20000

// QueryEvent represents a single DNS query held in the in-memory ring buffer.
type QueryEvent struct {
	Seq       uint64    `json:"seq"`
	Time      time.Time `json:"time"`
	ClientIP  string    `json:"client_ip"`
	QName     string    `json:"qname"`
	QType     string    `json:"qtype"`
	Protocol  string    `json:"protocol"`
	RCode     string    `json:"rcode"`
	Path      string    `json:"path"`
	LatencyMS float64   `json:"latency_ms"`
	Blocked   bool      `json:"blocked"`
	Source    string    `json:"source,omitempty"` // go | dnsdist
}

// QueryFilter filters ring-buffer queries cleanly.
type QueryFilter struct {
	QName       string
	ClientIP    string
	RCode       string
	BlockedOnly bool
	Limit       int
}

// Ring is a bounded, lock-safe, zero-disk-IOPS in-memory query ring buffer with SSE pub/sub.
type Ring struct {
	mu      sync.RWMutex
	buf     []QueryEvent
	cap     int
	head    int
	count   int
	seq     atomic.Uint64
	subsMu  sync.Mutex
	subs    map[uint64]chan QueryEvent
	nextSub atomic.Uint64
}

func New(capacity int) *Ring {
	if capacity <= 0 {
		capacity = DefaultCap
	}
	return &Ring{
		buf:  make([]QueryEvent, capacity),
		cap:  capacity,
		subs: make(map[uint64]chan QueryEvent),
	}
}

// Push records one QueryEvent and fans it out to active stream subscribers (non-blocking).
func (r *Ring) Push(ev QueryEvent) {
	if r == nil {
		return
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	ev.Seq = r.seq.Add(1)

	r.mu.Lock()
	idx := (r.head + r.count) % r.cap
	if r.count < r.cap {
		r.buf[idx] = ev
		r.count++
	} else {
		r.buf[r.head] = ev
		r.head = (r.head + 1) % r.cap
	}
	r.mu.Unlock()

	r.subsMu.Lock()
	for _, ch := range r.subs {
		select {
		case ch <- ev:
		default:
		}
	}
	r.subsMu.Unlock()
}

// Recent returns up to f.Limit newest matching events (newest first).
func (r *Ring) Recent(f QueryFilter) []QueryEvent {
	if r == nil {
		return nil
	}
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	qnFilter := strings.ToLower(strings.TrimSpace(f.QName))
	ipFilter := strings.TrimSpace(f.ClientIP)
	rcFilter := strings.ToUpper(strings.TrimSpace(f.RCode))

	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]QueryEvent, 0, minInt(limit, r.count))
	for i := 0; i < r.count && len(out) < limit; i++ {
		pos := (r.head + r.count - 1 - i) % r.cap
		ev := r.buf[pos]
		if f.BlockedOnly && !ev.Blocked {
			continue
		}
		if qnFilter != "" && !strings.Contains(strings.ToLower(ev.QName), qnFilter) {
			continue
		}
		if ipFilter != "" && !strings.Contains(ev.ClientIP, ipFilter) {
			continue
		}
		if rcFilter != "" && strings.ToUpper(ev.RCode) != rcFilter {
			continue
		}
		out = append(out, ev)
	}
	return out
}

// Len returns current buffered event count.
func (r *Ring) Len() int {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.count
}

// Subscribe streams newly recorded QueryEvents until ctx is canceled.
func (r *Ring) Subscribe(ctx context.Context, bufSize int) <-chan QueryEvent {
	if bufSize <= 0 {
		bufSize = 128
	}
	ch := make(chan QueryEvent, bufSize)
	id := r.nextSub.Add(1)
	r.subsMu.Lock()
	r.subs[id] = ch
	r.subsMu.Unlock()

	go func() {
		<-ctx.Done()
		r.subsMu.Lock()
		if sub, ok := r.subs[id]; ok {
			delete(r.subs, id)
			close(sub)
		}
		r.subsMu.Unlock()
	}()
	return ch
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
