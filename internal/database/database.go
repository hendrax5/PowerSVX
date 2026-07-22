package database

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/config"
)

type DB struct {
	sql *sql.DB
	log *slog.Logger

	queryLogRetentionDays atomic.Int64
	queryLogMaxSizeMB     atomic.Int64
}

func Connect(cfg config.DatabaseConfig, log *slog.Logger) (*DB, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if log == nil {
		log = slog.Default()
	}
	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.Database,
	)

	var lastErr error
	for attempt := 1; attempt <= 30; attempt++ {
		db, err := sql.Open("pgx", dsn)
		if err != nil {
			return nil, err
		}
		max := cfg.MaxConnections
		if max <= 0 {
			max = 20
		}
		db.SetMaxOpenConns(max)
		db.SetMaxIdleConns(max / 2)
		db.SetConnMaxLifetime(time.Hour)

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err = db.PingContext(ctx)
		cancel()
		if err == nil {
			if attempt > 1 && log != nil {
				log.Info("postgres ready", "attempt", attempt, "host", cfg.Host, "port", cfg.Port)
			}
			return &DB{sql: db, log: log}, nil
		}
		lastErr = err
		_ = db.Close()
		msg := err.Error()
		// 57P03 = starting up / not accepting connections; also retry refused during boot.
		transient := strings.Contains(msg, "57P03") ||
			strings.Contains(msg, "not yet accepting") ||
			strings.Contains(msg, "connection refused") ||
			strings.Contains(msg, "connect: no route to host")
		if !transient || attempt == 30 {
			break
		}
		if log != nil && (attempt == 1 || attempt%5 == 0) {
			log.Warn("postgres not ready, retrying", "attempt", attempt, "err", err)
		}
		time.Sleep(2 * time.Second)
	}
	return nil, fmt.Errorf("ping postgres: %w", lastErr)
}

func (d *DB) Close() error {
	if d == nil || d.sql == nil {
		return nil
	}
	return d.sql.Close()
}

// SetQueryLogLimits updates live retention/size caps read by StartRetentionLoop.
func (d *DB) SetQueryLogLimits(retentionDays, maxSizeMB int) {
	if d == nil {
		return
	}
	if retentionDays < 0 {
		retentionDays = 0
	}
	if maxSizeMB < 0 {
		maxSizeMB = 0
	}
	d.queryLogRetentionDays.Store(int64(retentionDays))
	d.queryLogMaxSizeMB.Store(int64(maxSizeMB))
}

func (d *DB) Ping(ctx context.Context) error {
	if d == nil || d.sql == nil {
		return fmt.Errorf("database disabled")
	}
	return d.sql.PingContext(ctx)
}

func (d *DB) Migrate(ctx context.Context) error {
	if d == nil || d.sql == nil {
		return nil
	}
	_, err := d.sql.ExecContext(ctx, schemaSQL)
	return err
}

func (d *DB) LoadZones(ctx context.Context) (map[string][]authoritative.Record, error) {
	out := make(map[string][]authoritative.Record)
	if d == nil || d.sql == nil {
		return out, nil
	}
	rows, err := d.sql.QueryContext(ctx, `
		SELECT z.name, r.name, r.type, r.content, r.ttl, r.prio,
		       COALESCE(r.geo_tag, ''), COALESCE(r.view_name, '')
		FROM zones z
		LEFT JOIN records r ON r.zone_id = z.id AND r.disabled = false
		ORDER BY z.name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var zoneName string
		var rName, rType, content, geoTag, viewName sql.NullString
		var ttl, prio sql.NullInt64
		if err := rows.Scan(&zoneName, &rName, &rType, &content, &ttl, &prio, &geoTag, &viewName); err != nil {
			return nil, err
		}
		zoneName = config.NormalizeName(zoneName)
		if _, ok := out[zoneName]; !ok {
			out[zoneName] = nil
		}
		if !rName.Valid {
			continue
		}
		ttlVal := uint32(3600)
		if ttl.Valid {
			ttlVal = uint32(ttl.Int64)
		}
		prioVal := uint16(0)
		if prio.Valid {
			prioVal = uint16(prio.Int64)
		}
		out[zoneName] = append(out[zoneName], authoritative.Record{
			Name:    config.NormalizeName(rName.String),
			Type:    authoritative.TypeFromString(rType.String),
			Content: content.String,
			TTL:     ttlVal,
			Prio:    prioVal,
			GeoTag:  geoTag.String,
			View:    viewName.String,
		})
	}
	return out, rows.Err()
}

// QueryLogEntry is written asynchronously.
type QueryLogEntry struct {
	Timestamp    time.Time
	ClientIP     string
	QueryName    string
	QueryType    string
	ResponseCode int
	ResponseMS   int
	Cached       bool
	Protocol     string
}

type QueryLogger struct {
	db     *DB
	ch     chan QueryLogEntry
	done   chan struct{}
	log    *slog.Logger
}

func NewQueryLogger(db *DB, enabled bool, log *slog.Logger) *QueryLogger {
	if db == nil || db.sql == nil {
		return nil
	}
	_ = enabled // enable/disable is controlled at call site via config flag
	ql := &QueryLogger{
		db:   db,
		ch:   make(chan QueryLogEntry, 4096),
		done: make(chan struct{}),
		log:  log,
	}
	go ql.loop()
	return ql
}

func (q *QueryLogger) Log(e QueryLogEntry) {
	if q == nil {
		return
	}
	select {
	case q.ch <- e:
	default:
		// drop under pressure — never block hot path
	}
}

func (q *QueryLogger) loop() {
	defer close(q.done)
	batch := make([]QueryLogEntry, 0, 64)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	flush := func() {
		if len(batch) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		tx, err := q.db.sql.BeginTx(ctx, nil)
		if err != nil {
			batch = batch[:0]
			return
		}
		stmt, err := tx.PrepareContext(ctx, `
			INSERT INTO query_logs (timestamp, client_ip, query_name, query_type, response_code, response_time_ms, cached, protocol)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		`)
		if err != nil {
			_ = tx.Rollback()
			batch = batch[:0]
			return
		}
		for _, e := range batch {
			_, _ = stmt.ExecContext(ctx, e.Timestamp, e.ClientIP, e.QueryName, e.QueryType, e.ResponseCode, e.ResponseMS, e.Cached, e.Protocol)
		}
		_ = stmt.Close()
		_ = tx.Commit()
		batch = batch[:0]
	}
	for {
		select {
		case e, ok := <-q.ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, e)
			if len(batch) >= 64 {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (q *QueryLogger) Close() {
	if q == nil {
		return
	}
	close(q.ch)
	<-q.done
}

// QueryLogRow is a read model for the UI/API.
type QueryLogRow struct {
	ID           int64     `json:"id"`
	Timestamp    time.Time `json:"timestamp"`
	ClientIP     string    `json:"client_ip"`
	QueryName    string    `json:"query_name"`
	QueryType    string    `json:"query_type"`
	ResponseCode int       `json:"response_code"`
	ResponseMS   int       `json:"response_time_ms"`
	Cached       bool      `json:"cached"`
	Protocol     string    `json:"protocol"`
}

// QueryLogFilter selects recent query log rows.
type QueryLogFilter struct {
	ClientIP string
	Limit    int
	Offset   int
}

// ListQueryLogs returns newest-first rows, optional exact client IP filter.
// Avoids SELECT COUNT(*) on the full table — that timed out on multi‑10M row logs.
func (db *DB) ListQueryLogs(ctx context.Context, f QueryLogFilter) ([]QueryLogRow, int, error) {
	if db == nil || db.sql == nil {
		return nil, 0, fmt.Errorf("database unavailable")
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	where := ""
	args := []any{}
	if ip := strings.TrimSpace(f.ClientIP); ip != "" {
		where = "WHERE client_ip = $1::inet"
		args = append(args, ip)
	}

	total, err := db.estimateQueryLogTotal(ctx, where, args)
	if err != nil {
		return nil, 0, err
	}

	// Fetch one extra row to know if another page exists without a full count.
	fetch := limit + 1
	listArgs := append(append([]any{}, args...), fetch, offset)
	limIdx, offIdx := len(args)+1, len(args)+2
	listQ := fmt.Sprintf(`
		SELECT id, timestamp, host(client_ip), query_name, query_type,
		       COALESCE(response_code,0), COALESCE(response_time_ms,0),
		       COALESCE(cached,false), COALESCE(protocol,'')
		FROM query_logs
		%s
		ORDER BY timestamp DESC, id DESC
		LIMIT $%d OFFSET $%d
	`, where, limIdx, offIdx)

	rows, err := db.sql.QueryContext(ctx, listQ, listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := make([]QueryLogRow, 0, limit)
	for rows.Next() {
		var r QueryLogRow
		if err := rows.Scan(&r.ID, &r.Timestamp, &r.ClientIP, &r.QueryName, &r.QueryType,
			&r.ResponseCode, &r.ResponseMS, &r.Cached, &r.Protocol); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if len(out) > limit {
		out = out[:limit]
		// Ensure paginator can advance when planner estimate is stale/low.
		if total < offset+limit+1 {
			total = offset + limit + 1
		}
	} else if total < offset+len(out) {
		total = offset + len(out)
	}
	return out, total, nil
}

// estimateQueryLogTotal prefers pg_class.reltuples (instant). Filtered lists use a capped COUNT.
func (db *DB) estimateQueryLogTotal(ctx context.Context, where string, args []any) (int, error) {
	if where == "" {
		var n float64
		err := db.sql.QueryRowContext(ctx, `
			SELECT COALESCE(reltuples, 0) FROM pg_class WHERE oid = 'query_logs'::regclass`).Scan(&n)
		if err != nil {
			return 0, err
		}
		if n < 0 {
			n = 0
		}
		return int(n), nil
	}
	// Cap so a hot client_ip cannot scan tens of millions inside the API timeout.
	q := fmt.Sprintf(`SELECT COUNT(*) FROM (
		SELECT 1 FROM query_logs %s LIMIT 10001
	) s`, where)
	var n int
	if err := db.sql.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

const schemaSQL = `
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS zones (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    type VARCHAR(20) DEFAULT 'native',
    dnssec_enabled BOOLEAN DEFAULT false,
    soa_serial BIGINT DEFAULT 1,
    soa_refresh INT DEFAULT 3600,
    soa_retry INT DEFAULT 600,
    soa_expire INT DEFAULT 86400,
    soa_minimum INT DEFAULT 3600,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    zone_id UUID REFERENCES zones(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(10) NOT NULL,
    content TEXT NOT NULL,
    ttl INT DEFAULT 3600,
    prio INT DEFAULT 0,
    disabled BOOLEAN DEFAULT false,
    geo_tag VARCHAR(50) DEFAULT '',
    view_name VARCHAR(50) DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE records ADD COLUMN IF NOT EXISTS geo_tag VARCHAR(50) DEFAULT '';
ALTER TABLE records ADD COLUMN IF NOT EXISTS view_name VARCHAR(50) DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_records_zone_name ON records(zone_id, name);

CREATE TABLE IF NOT EXISTS config (
    key VARCHAR(255) PRIMARY KEY,
    value TEXT,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS query_logs (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    client_ip INET NOT NULL,
    client_subnet INET,
    query_name VARCHAR(255) NOT NULL,
    query_type VARCHAR(10) NOT NULL,
    response_code INT,
    response_time_ms INT,
    cached BOOLEAN DEFAULT false,
    blocked BOOLEAN DEFAULT false,
    protocol VARCHAR(10),
    metadata JSONB DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_query_logs_time ON query_logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_query_logs_client ON query_logs (client_ip);
CREATE INDEX IF NOT EXISTS idx_query_logs_client_time ON query_logs (client_ip, timestamp DESC);

INSERT INTO config (key, value) VALUES ('version', '1.0.0'), ('setup_complete', 'false')
ON CONFLICT (key) DO NOTHING;
`
