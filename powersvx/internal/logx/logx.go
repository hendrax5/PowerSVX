// Package logx is an async, sampled, bounded query logger (Phase 3). The hot
// path never blocks on the log sink: lines are sampled (1/N), pushed to a
// bounded channel, and DROPPED when the channel is full (drop policy, not an
// unbounded queue). A slow sink therefore cannot back up the resolver.
package logx

import (
	"bufio"
	"os"
	"sync/atomic"
)

type Logger struct {
	ch      chan string
	enabled bool
	sample  uint64
	counter uint64
	dropped uint64
	done    chan struct{}
}

// New starts the consumer goroutine. sample<=1 logs everything; N logs 1/N.
func New(enabled bool, sample, bufSize int) *Logger {
	if sample < 1 {
		sample = 1
	}
	l := &Logger{
		ch:      make(chan string, bufSize),
		enabled: enabled,
		sample:  uint64(sample),
		done:    make(chan struct{}),
	}
	go l.consume()
	return l
}

// Log samples and enqueues without blocking. Returns immediately on a full
// buffer, incrementing the drop counter.
func (l *Logger) Log(line string) {
	if !l.enabled {
		return
	}
	c := atomic.AddUint64(&l.counter, 1)
	if l.sample > 1 && c%l.sample != 0 {
		return
	}
	select {
	case l.ch <- line:
	default:
		atomic.AddUint64(&l.dropped, 1)
	}
}

func (l *Logger) Dropped() uint64 { return atomic.LoadUint64(&l.dropped) }

func (l *Logger) consume() {
	w := bufio.NewWriter(os.Stdout)
	defer close(l.done)
	for line := range l.ch {
		w.WriteString(line)
		w.WriteByte('\n')
		if len(l.ch) == 0 {
			w.Flush()
		}
	}
	w.Flush()
}

func (l *Logger) Close() {
	if !l.enabled {
		return
	}
	close(l.ch)
	<-l.done
}
