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

// StartRetentionLoop deletes query_logs older than retentionDays. Stop via cancel.
func (db *DB) StartRetentionLoop(ctx context.Context, retentionDays int, interval time.Duration) {
	if db == nil || db.sql == nil || retentionDays <= 0 {
		return
	}
	if interval <= 0 {
		interval = time.Hour
	}
	run := func() {
		// Batched deletes: a single DELETE on tens of millions of rows never finishes
		// inside a short timeout and blocks the UI/API.
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
					db.log.Warn("query log retention failed", "err", err)
				}
				return
			}
			n, _ := res.RowsAffected()
			purged += n
			if n == 0 {
				break
			}
		}
		if purged > 0 {
			c, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			_, err := db.sql.ExecContext(c, `VACUUM (ANALYZE) query_logs`)
			cancel()
			if err != nil && db.log != nil {
				db.log.Warn("query log vacuum failed", "err", err)
			}
			if db.log != nil {
				db.log.Info("query log retention purged", "rows", purged, "older_than_days", retentionDays)
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
