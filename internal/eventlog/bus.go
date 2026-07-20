package eventlog

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// Event is an operational error/warning — not a per-query log line.
type Event struct {
	ID      int64             `json:"id"`
	Time    time.Time         `json:"time"`
	Level   string            `json:"level"` // error | warn
	Kind    string            `json:"kind"`
	Message string            `json:"message"`
	Attrs   map[string]string `json:"attrs,omitempty"`
}

// Bus keeps a ring of recent events and fans out to live subscribers.
type Bus struct {
	mu       sync.RWMutex
	buf      []Event
	cap      int
	head     int // next write index
	count    int
	subs     map[chan Event]struct{}
	sampleMu sync.Mutex
	sampled  map[string]time.Time
	seq      atomic.Int64
}

func New(capacity int) *Bus {
	if capacity <= 0 {
		capacity = 200
	}
	return &Bus{
		buf:     make([]Event, capacity),
		cap:     capacity,
		subs:    make(map[chan Event]struct{}),
		sampled: make(map[string]time.Time),
	}
}

func (b *Bus) Emit(level, kind, message string, attrs map[string]string) {
	if b == nil {
		return
	}
	ev := Event{
		ID:      b.seq.Add(1),
		Time:    time.Now().UTC(),
		Level:   level,
		Kind:    kind,
		Message: message,
		Attrs:   attrs,
	}
	b.mu.Lock()
	b.buf[b.head] = ev
	b.head = (b.head + 1) % b.cap
	if b.count < b.cap {
		b.count++
	}
	subs := make([]chan Event, 0, len(b.subs))
	for ch := range b.subs {
		subs = append(subs, ch)
	}
	b.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

// EmitSampled emits at most once per key within every interval (noisy kinds like rate_limit).
func (b *Bus) EmitSampled(key string, every time.Duration, level, kind, message string, attrs map[string]string) {
	if b == nil {
		return
	}
	now := time.Now()
	b.sampleMu.Lock()
	if t, ok := b.sampled[key]; ok && now.Sub(t) < every {
		b.sampleMu.Unlock()
		return
	}
	b.sampled[key] = now
	// prune stale keys occasionally
	if len(b.sampled) > 10_000 {
		b.sampled = map[string]time.Time{key: now}
	}
	b.sampleMu.Unlock()
	b.Emit(level, kind, message, attrs)
}

func (b *Bus) Recent(limit int) []Event {
	if b == nil {
		return nil
	}
	if limit <= 0 {
		limit = 100
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.count == 0 {
		return nil
	}
	n := b.count
	if n > limit {
		n = limit
	}
	out := make([]Event, n)
	// oldest at (head - count + cap) % cap; take last n
	start := (b.head - b.count + b.cap) % b.cap
	skip := b.count - n
	for i := 0; i < n; i++ {
		out[i] = b.buf[(start+skip+i)%b.cap]
	}
	return out
}

// Subscribe returns a channel of live events. Cancel ctx to unsubscribe.
func (b *Bus) Subscribe(ctx context.Context, buf int) <-chan Event {
	if b == nil {
		ch := make(chan Event)
		close(ch)
		return ch
	}
	if buf < 8 {
		buf = 32
	}
	ch := make(chan Event, buf)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()

	go func() {
		<-ctx.Done()
		b.mu.Lock()
		delete(b.subs, ch)
		b.mu.Unlock()
		close(ch)
	}()
	return ch
}
