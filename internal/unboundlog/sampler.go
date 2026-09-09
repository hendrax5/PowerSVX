package unboundlog

import (
	"bufio"
	"io"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"log/slog"

	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/database"
)

// Default shared path inside containers / host bind.
func DefaultPath() string {
	if v := strings.TrimSpace(os.Getenv("POWERSVX_UNBOUND_QUERYLOG_PATH")); v != "" {
		return v
	}
	return "/data/unbound-logs/unbound.log"
}

// Query line examples (Unbound 1.x):
//
//	[1700000000] unbound[1:0] info: 1.2.3.4 example.com. A IN
//	info: 1.2.3.4 example.com. A IN
var (
	reInfoQuery = regexp.MustCompile(`(?i)\binfo:\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*$`)
	reBracketTS = regexp.MustCompile(`^\[(\d+)\]`)
)

// ParseQueryLine extracts client / qname / type from an Unbound log-queries line.
func ParseQueryLine(line string) (clientIP, qname, qtype string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.Contains(line, "response:") {
		return "", "", "", false
	}
	m := reInfoQuery.FindStringSubmatch(line)
	if m == nil {
		return "", "", "", false
	}
	ip, name, typ, class := m[1], m[2], m[3], m[4]
	if !strings.EqualFold(class, "IN") {
		return "", "", "", false
	}
	if net.ParseIP(ip) == nil {
		return "", "", "", false
	}
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if name == "" {
		return "", "", "", false
	}
	return ip, name, strings.ToUpper(typ), true
}

// Sampler tails Unbound's query logfile and inserts a sampled subset into Postgres.
type Sampler struct {
	path       string
	qlog       *database.QueryLogger
	cfg        *config.Config
	log        *slog.Logger
	stop       chan struct{}
	seen       atomic.Uint64
	kept       atomic.Uint64
	maxPerSec  int
	rng        *rand.Rand
}

func NewSampler(path string, qlog *database.QueryLogger, cfg *config.Config, log *slog.Logger) *Sampler {
	if path == "" {
		path = DefaultPath()
	}
	if log == nil {
		log = slog.Default()
	}
	return &Sampler{
		path:      path,
		qlog:      qlog,
		cfg:       cfg,
		log:       log,
		stop:      make(chan struct{}),
		maxPerSec: 40,
		rng:       rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Start begins background tail+sample. Safe if path missing (waits for file).
func (s *Sampler) Start() {
	if s == nil || s.qlog == nil {
		return
	}
	go s.loop()
	s.log.Info("unbound query log sampler started",
		"path", s.path,
		"max_per_sec", s.maxPerSec,
	)
}

func (s *Sampler) Stop() {
	if s == nil {
		return
	}
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
}

func (s *Sampler) Stats() (seen, kept uint64) {
	return s.seen.Load(), s.kept.Load()
}

func (s *Sampler) sampleRate() float64 {
	if s.cfg == nil {
		return 0.05
	}
	r := s.cfg.Logging.QueryLogSampleRate
	if r <= 0 {
		return 0.05
	}
	if r > 1 {
		return 1
	}
	return r
}

func (s *Sampler) loop() {
	var (
		f      *os.File
		offset int64
		r      *bufio.Reader
	)
	defer func() {
		if f != nil {
			_ = f.Close()
		}
	}()

	open := func() bool {
		if f != nil {
			_ = f.Close()
			f = nil
			r = nil
		}
		_ = os.MkdirAll(filepath.Dir(s.path), 0o755)
		fh, err := os.Open(s.path)
		if err != nil {
			return false
		}
		// Start at end so we only see new queries after boot (avoid backlog flood).
		st, err := fh.Stat()
		if err == nil {
			offset = st.Size()
			_, _ = fh.Seek(offset, io.SeekStart)
		}
		f = fh
		r = bufio.NewReaderSize(fh, 64*1024)
		return true
	}

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	truncateTick := time.NewTicker(10 * time.Second)
	defer truncateTick.Stop()

	var keptThisSec int
	secMark := time.Now().Unix()

	for {
		select {
		case <-s.stop:
			return
		case <-truncateTick.C:
			s.maybeTruncate(&f, &r, &offset)
		case <-ticker.C:
			if f == nil && !open() {
				continue
			}
			st, err := f.Stat()
			if err != nil {
				_ = f.Close()
				f = nil
				continue
			}
			// Log rotated / truncated under us.
			if st.Size() < offset {
				offset = 0
				_, _ = f.Seek(0, io.SeekStart)
				r = bufio.NewReaderSize(f, 64*1024)
			}
			for {
				line, err := r.ReadString('\n')
				if len(line) > 0 {
					offset += int64(len(line))
					s.handleLine(strings.TrimRight(line, "\r\n"), &keptThisSec, &secMark)
				}
				if err != nil {
					break
				}
			}
		}
	}
}

func (s *Sampler) handleLine(line string, keptThisSec *int, secMark *int64) {
	ip, qname, qtype, ok := ParseQueryLine(line)
	if !ok {
		return
	}
	s.seen.Add(1)
	if s.cfg != nil && !s.cfg.Logging.QueryLogEnabled {
		return
	}
	now := time.Now().Unix()
	if now != *secMark {
		*secMark = now
		*keptThisSec = 0
	}
	if *keptThisSec >= s.maxPerSec {
		return
	}
	rate := s.sampleRate()
	if rate < 1 && s.rng.Float64() > rate {
		return
	}
	if s.cfg != nil && s.cfg.Logging.QueryLogMaskIP {
		ip = database.MaskClientIP(ip)
	}
	ts := time.Now()
	if m := reBracketTS.FindStringSubmatch(line); m != nil {
		if sec, err := parseInt64(m[1]); err == nil && sec > 0 {
			ts = time.Unix(sec, 0)
		}
	}
	s.qlog.Log(database.QueryLogEntry{
		Timestamp:    ts,
		ClientIP:     ip,
		QueryName:    qname,
		QueryType:    qtype,
		ResponseCode: -1, // unknown (queries-only log)
		ResponseMS:   0,
		Cached:       false,
		Protocol:     "unbound",
	})
	s.kept.Add(1)
	*keptThisSec++
}

func parseInt64(s string) (int64, error) {
	var n int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, io.ErrUnexpectedEOF
		}
		n = n*10 + int64(c-'0')
	}
	return n, nil
}

// maybeTruncate keeps the logfile from filling the disk; Unbound reopens on write
// after truncate when using a normal file (may need log_reopen — we truncate by
// renaming away and recreating empty so writers continue on inode replace poorly).
// Safer: truncate in place after seeking readers; Unbound keeps FD and continues.
func (s *Sampler) maybeTruncate(f **os.File, r **bufio.Reader, offset *int64) {
	const maxBytes = 16 << 20 // 16 MiB — Unbound log-queries grows fast at multi-k QPS
	st, err := os.Stat(s.path)
	if err != nil || st.Size() < maxBytes {
		return
	}
	if err := os.Truncate(s.path, 0); err != nil {
		s.log.Debug("unbound querylog truncate", "err", err)
		return
	}
	*offset = 0
	if *f != nil {
		_, _ = (*f).Seek(0, io.SeekStart)
		*r = bufio.NewReaderSize(*f, 64*1024)
	}
	s.log.Info("unbound querylog truncated", "path", s.path, "was_bytes", st.Size())
}
