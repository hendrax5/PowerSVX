package api

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/database"
	"github.com/powersvx/powersvx/internal/dnstap"
	"github.com/powersvx/powersvx/internal/queryring"
)

// StartQueryLog listens for the sampled query log dnsdist sends over a unix socket in
// the shared dnstap directory, and writes the configured sample rate next to it for
// dnsdist to pick up. Every sampled query goes to the live stream; with a database it
// is also stored. It never blocks start-up: if the socket cannot be bound the console
// simply has no live queries.
func (a *API) StartQueryLog() {
	if a == nil || a.srv == nil || a.srv.QueryRing() == nil {
		return
	}
	dir := config.DNSTapDir(a.dataDir)
	if a.db != nil && a.cfg != nil && a.cfg.Database.Enabled {
		a.qlog = database.NewQueryLogger(a.db, true, a.log)
	}
	l, err := dnstap.Listen(filepath.Join(dir, dnstap.SocketName), a.recordQuery, a.log)
	if err != nil {
		a.log.Warn("query log listener not started", "dir", dir, "err", err)
		return
	}
	a.qlistener = l
	go l.Serve()
	a.SyncQueryLogRate()
	a.log.Info("query log listener ready", "socket", l.Path(), "rate", a.cfg.QueryLogRate())
}

// StopQueryLog closes the listener and flushes the history writer.
func (a *API) StopQueryLog() {
	if a == nil {
		return
	}
	if a.qlistener != nil {
		a.qlistener.Close()
	}
	if a.qlog != nil {
		a.qlog.Close()
	}
}

// SyncQueryLogRate tells the Dataplane how much to sample: the configured rate when the
// query log is enabled, otherwise 0. dnsdist reads the file about once a second.
func (a *API) SyncQueryLogRate() {
	if a == nil || a.cfg == nil || a.qlistener == nil {
		return
	}
	path := filepath.Join(config.DNSTapDir(a.dataDir), "rate")
	if err := writeQueryLogRate(path, a.cfg.QueryLogRate()); err != nil {
		a.log.Warn("query log rate not written", "path", path, "err", err)
	}
}

// queryLogConnected reports whether dnsdist is streaming to the listener, which is
// only the case for a Dataplane generated with the sampled query log.
func (a *API) queryLogConnected() bool {
	return a.qlistener != nil && a.qlistener.Connected()
}

func writeQueryLogRate(path string, rate float64) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.FormatFloat(rate, 'f', -1, 64)+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// recordQuery feeds one sampled query to the live stream and, when history is on, the database.
func (a *API) recordQuery(e dnstap.Entry) {
	path := e.Action
	if path == "" {
		path = "dnsdist"
	}
	a.srv.QueryRing().Push(queryring.QueryEvent{
		Time:      e.Time,
		ClientIP:  e.ClientIP,
		QName:     e.QName,
		QType:     e.QType,
		Protocol:  e.Protocol,
		RCode:     e.RCode,
		Path:      path,
		LatencyMS: float64(e.Latency) / float64(time.Millisecond),
		Blocked:   e.Blocked(),
		Source:    "dnsdist",
		Action:    e.Action,
	})
	if a.qlog == nil || !a.cfg.Logging.QueryLogEnabled {
		return
	}
	client := e.ClientIP
	if a.cfg.Logging.QueryLogMaskIP {
		client = database.MaskClientIP(client)
	}
	if client == "" {
		return
	}
	a.qlog.Log(database.QueryLogEntry{
		Timestamp:    e.Time,
		ClientIP:     client,
		QueryName:    strings.ToLower(e.QName),
		QueryType:    e.QType,
		ResponseCode: e.RCodeNum,
		ResponseMS:   int(e.Latency / time.Millisecond),
		Protocol:     e.Protocol,
		Action:       e.Action,
	})
}
