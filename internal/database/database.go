package database

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/config"
)

type DB struct {
	sql *sql.DB
	log *slog.Logger
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return &DB{sql: db, log: log}, nil
}

func (d *DB) Close() error {
	if d == nil || d.sql == nil {
		return nil
	}
	return d.sql.Close()
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
		SELECT z.name, r.name, r.type, r.content, r.ttl, r.prio
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
		var rName, rType, content sql.NullString
		var ttl, prio sql.NullInt64
		if err := rows.Scan(&zoneName, &rName, &rType, &content, &ttl, &prio); err != nil {
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
	if !enabled || db == nil || db.sql == nil {
		return nil
	}
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
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

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

INSERT INTO config (key, value) VALUES ('version', '1.0.0'), ('setup_complete', 'false')
ON CONFLICT (key) DO NOTHING;
`
