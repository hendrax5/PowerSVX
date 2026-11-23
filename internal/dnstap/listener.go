package dnstap

import (
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
)

// SocketName is the file name of the listening socket inside the shared directory.
const SocketName = "query.sock"

// Listener accepts the Dataplane's dnstap connection on a unix socket and hands
// every decoded client response to a handler.
type Listener struct {
	path      string
	ln        net.Listener
	handle    func(Entry)
	log       *slog.Logger
	conns     atomic.Int32
	mu        sync.Mutex
	open      map[net.Conn]struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once
	closed    atomic.Bool
}

// Listen binds the socket. The directory is created if needed and a stale socket
// file from an earlier run is replaced. The socket is mode 0660: only the owner
// and root (dnsdist runs as root) can write to it, so no other local user can
// inject entries into the log.
func Listen(path string, handle func(Entry), log *slog.Logger) (*Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, errors.New(path + " exists and is not a socket")
		}
		_ = os.Remove(path)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(path, 0o660)
	if log == nil {
		log = slog.Default()
	}
	return &Listener{path: path, ln: ln, handle: handle, log: log, open: map[net.Conn]struct{}{}}, nil
}

// Path returns the socket path.
func (l *Listener) Path() string { return l.path }

// Connected reports whether a Dataplane is currently streaming to the socket.
func (l *Listener) Connected() bool { return l.conns.Load() > 0 }

// Serve accepts connections until Close. Call it in its own goroutine.
func (l *Listener) Serve() {
	for {
		c, err := l.ln.Accept()
		if err != nil {
			return
		}
		l.mu.Lock()
		l.open[c] = struct{}{}
		l.mu.Unlock()
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			l.conns.Add(1)
			defer l.conns.Add(-1)
			defer func() {
				l.mu.Lock()
				delete(l.open, c)
				l.mu.Unlock()
				_ = c.Close()
			}()
			err := ReadStream(c, func(frame []byte) {
				e, ok, derr := Decode(frame)
				if derr != nil {
					l.log.Debug("dnstap frame dropped", "err", derr)
					return
				}
				if ok {
					l.handle(e)
				}
			})
			if err != nil && !l.closed.Load() {
				l.log.Warn("dnstap stream ended with an error", "err", err)
			}
		}()
	}
}

// Close stops accepting, closes the socket file and open streams, and waits for them.
func (l *Listener) Close() {
	l.closeOnce.Do(func() {
		l.closed.Store(true)
		_ = l.ln.Close()
		_ = os.Remove(l.path)
		l.mu.Lock()
		for c := range l.open {
			_ = c.Close()
		}
		l.mu.Unlock()
		l.wg.Wait()
	})
}
