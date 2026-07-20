package audit

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Event is a control-plane audit record (API mutations / auth).
type Event struct {
	Time   time.Time         `json:"time"`
	Actor  string            `json:"actor"`
	Role   string            `json:"role"`
	Action string            `json:"action"`
	Path   string            `json:"path"`
	Status int               `json:"status"`
	Meta   map[string]string `json:"meta,omitempty"`
}

// Log is an in-memory ring; optionally mirrors to slog.
type Log struct {
	mu     sync.Mutex
	events []Event
	max    int
	slog   *slog.Logger
}

func New(max int, log *slog.Logger) *Log {
	if max <= 0 {
		max = 500
	}
	return &Log{max: max, slog: log}
}

func (l *Log) Record(e Event) {
	if l == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	l.mu.Lock()
	l.events = append(l.events, e)
	if len(l.events) > l.max {
		l.events = l.events[len(l.events)-l.max:]
	}
	l.mu.Unlock()
	if l.slog != nil {
		l.slog.Info("audit", "actor", e.Actor, "role", e.Role, "action", e.Action, "path", e.Path, "status", e.Status)
	}
}

func (l *Log) Recent(n int) []Event {
	if l == nil {
		return nil
	}
	if n <= 0 {
		n = 100
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if n > len(l.events) {
		n = len(l.events)
	}
	out := make([]Event, n)
	copy(out, l.events[len(l.events)-n:])
	return out
}

// PersistHook is reserved for future DB persistence (ctx unused for now).
func (l *Log) PersistHook(_ context.Context) {}
