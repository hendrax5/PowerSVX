package database

import (
	"context"
	"net"
	"strings"
	"time"
)

// MaskClientIP truncates IPv4 to /24 and IPv6 to /48 for privacy.
func MaskClientIP(ipStr string) string {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return ipStr
	}
	if v4 := ip.To4(); v4 != nil {
		masked := net.IPv4(v4[0], v4[1], v4[2], 0)
		return masked.String()
	}
	ip = ip.To16()
	if ip == nil {
		return ipStr
	}
	// /48: keep first 6 bytes
	out := make(net.IP, net.IPv6len)
	copy(out, ip)
	for i := 6; i < net.IPv6len; i++ {
		out[i] = 0
	}
	return out.String()
}

// StartRetentionLoop enforces time and/or size caps on query_logs. Stop via cancel.
// Limits are read each run via SetQueryLogLimits (safe to change from the UI).
func (db *DB) StartRetentionLoop(ctx context.Context, retentionDays, maxSizeMB int, interval time.Duration) {
	if db == nil || db.sql == nil {
		return
	}
	db.SetQueryLogLimits(retentionDays, maxSizeMB)
	if retentionDays <= 0 && maxSizeMB <= 0 {
		// Still start the loop so a later UI enable can take effect without restart.
	}
	if interval <= 0 {
		interval = time.Hour
	}
	run := func() {
		days := int(db.queryLogRetentionDays.Load())
		maxMB := int(db.queryLogMaxSizeMB.Load())
		var purged int64
		if days > 0 {
			purged += db.purgeQueryLogsByAge(days)
		}
		if maxMB > 0 {
			purged += db.purgeQueryLogsBySize(maxMB)
		}
		if purged > 0 {
			c, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			_, err := db.sql.ExecContext(c, `VACUUM (ANALYZE) query_logs`)
			cancel()
			if err != nil && db.log != nil {
				db.log.Warn("query log vacuum failed", "err", err)
			}
			if db.log != nil {
				db.log.Info("query log retention purged",
					"rows", purged,
					"older_than_days", days,
					"max_size_mb", maxMB,
				)
			}
		}
	}
	go func() {
		run()
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				run()
			}
		}
	}()
}

func (db *DB) purgeQueryLogsByAge(retentionDays int) int64 {
	cutoff := time.Now().UTC().Add(-time.Duration(retentionDays) * 24 * time.Hour)
	var purged int64
	for i := 0; i < 200; i++ {
		c, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		res, err := db.sql.ExecContext(c, `
			DELETE FROM query_logs
			WHERE ctid IN (
				SELECT ctid FROM query_logs
				WHERE timestamp < $1
				LIMIT 50000
			)`, cutoff)
		cancel()
		if err != nil {
			if db.log != nil {
				db.log.Warn("query log age purge failed", "err", err)
			}
			return purged
		}
		n, _ := res.RowsAffected()
		purged += n
		if n == 0 {
			break
		}
	}
	return purged
}

func (db *DB) queryLogsSizeBytes(ctx context.Context) (int64, error) {
	var n int64
	err := db.sql.QueryRowContext(ctx, `SELECT pg_total_relation_size('query_logs')`).Scan(&n)
	return n, err
}

// purgeQueryLogsBySize deletes oldest rows until table+indexes are under ~90% of maxSizeMB.
func (db *DB) purgeQueryLogsBySize(maxSizeMB int) int64 {
	maxBytes := int64(maxSizeMB) * 1024 * 1024
	target := maxBytes * 90 / 100 // hysteresis so we don't thrash at the limit
	if target < 1 {
		target = maxBytes
	}
	var purged int64
	for i := 0; i < 400; i++ {
		c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		size, err := db.queryLogsSizeBytes(c)
		cancel()
		if err != nil {
			if db.log != nil {
				db.log.Warn("query log size check failed", "err", err)
			}
			return purged
		}
		stopAt := maxBytes
		if purged > 0 {
			stopAt = target
		}
		if size <= stopAt {
			return purged
		}
		c2, cancel2 := context.WithTimeout(context.Background(), 60*time.Second)
		res, err := db.sql.ExecContext(c2, `
			DELETE FROM query_logs
			WHERE ctid IN (
				SELECT ctid FROM query_logs
				ORDER BY timestamp ASC, id ASC
				LIMIT 50000
			)`)
		cancel2()
		if err != nil {
			if db.log != nil {
				db.log.Warn("query log size purge failed", "err", err)
			}
			return purged
		}
		n, _ := res.RowsAffected()
		purged += n
		if n == 0 {
			break
		}
	}
	return purged
}
