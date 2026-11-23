package database

import (
	"context"
	"fmt"

	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/config"
)

// LoadZoneMeta reads the per-zone metadata of the legacy zones table. It is
// only used by the one-time export of zones to files; the table is never
// written to.
func (d *DB) LoadZoneMeta(ctx context.Context) (map[string]authoritative.ZoneMeta, error) {
	if d == nil || d.sql == nil {
		return nil, fmt.Errorf("database disabled")
	}
	rows, err := d.sql.QueryContext(ctx, `
		SELECT name, COALESCE(type, 'native'), COALESCE(dnssec_enabled, false),
		       COALESCE(soa_serial, 1), COALESCE(soa_refresh, 3600), COALESCE(soa_retry, 600),
		       COALESCE(soa_expire, 86400), COALESCE(soa_minimum, 3600)
		FROM zones
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]authoritative.ZoneMeta)
	for rows.Next() {
		var name string
		var m authoritative.ZoneMeta
		if err := rows.Scan(&name, &m.Type, &m.DNSSECEnabled, &m.SOASerial, &m.SOARefresh, &m.SOARetry, &m.SOAExpire, &m.SOAMinimum); err != nil {
			return nil, err
		}
		out[config.NormalizeName(name)] = m
	}
	return out, rows.Err()
}
