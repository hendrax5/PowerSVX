package database

import (
	"context"
	"fmt"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/config"
)

type ZoneRow struct {
	ID   string
	Name string
}

func (d *DB) ListZoneRows(ctx context.Context) ([]ZoneRow, error) {
	if d == nil || d.sql == nil {
		return nil, fmt.Errorf("database disabled")
	}
	rows, err := d.sql.QueryContext(ctx, `SELECT id::text, name FROM zones ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ZoneRow
	for rows.Next() {
		var z ZoneRow
		if err := rows.Scan(&z.ID, &z.Name); err != nil {
			return nil, err
		}
		out = append(out, z)
	}
	return out, rows.Err()
}

func (d *DB) CreateZone(ctx context.Context, name string) (string, error) {
	if d == nil || d.sql == nil {
		return "", fmt.Errorf("database disabled")
	}
	name = config.NormalizeName(name)
	var id string
	err := d.sql.QueryRowContext(ctx,
		`INSERT INTO zones (name) VALUES ($1) ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id::text`,
		name,
	).Scan(&id)
	return id, err
}

func (d *DB) DeleteZone(ctx context.Context, name string) error {
	if d == nil || d.sql == nil {
		return fmt.Errorf("database disabled")
	}
	_, err := d.sql.ExecContext(ctx, `DELETE FROM zones WHERE name = $1`, config.NormalizeName(name))
	return err
}

func (d *DB) AddRecord(ctx context.Context, zone string, rec authoritative.Record) error {
	if d == nil || d.sql == nil {
		return fmt.Errorf("database disabled")
	}
	zone = config.NormalizeName(zone)
	_, err := d.sql.ExecContext(ctx, `
		INSERT INTO records (zone_id, name, type, content, ttl, prio, geo_tag, view_name)
		SELECT id, $2, $3, $4, $5, $6, $7, $8 FROM zones WHERE name = $1
	`, zone, config.NormalizeName(rec.Name), dns.TypeToString[rec.Type], rec.Content, rec.TTL, rec.Prio, rec.GeoTag, rec.View)
	return err
}

func (d *DB) UpdateRecord(ctx context.Context, zone, oldName, oldType string, rec authoritative.Record) error {
	if d == nil || d.sql == nil {
		return fmt.Errorf("database disabled")
	}
	zone = config.NormalizeName(zone)
	oldName = config.NormalizeName(oldName)
	res, err := d.sql.ExecContext(ctx, `
		UPDATE records r SET
			name = $4, type = $5, content = $6, ttl = $7, prio = $8, geo_tag = $9, view_name = $10, updated_at = NOW()
		FROM zones z
		WHERE r.zone_id = z.id AND z.name = $1 AND r.name = $2 AND ($3 = '' OR r.type = $3)
	`, zone, oldName, oldType,
		config.NormalizeName(rec.Name), dns.TypeToString[rec.Type], rec.Content, rec.TTL, rec.Prio, rec.GeoTag, rec.View)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("record not found")
	}
	return nil
}

func (d *DB) GetZoneMeta(ctx context.Context, name string) (map[string]any, error) {
	if d == nil || d.sql == nil {
		return nil, fmt.Errorf("database disabled")
	}
	name = config.NormalizeName(name)
	var (
		typ string
		dnssec bool
		serial int64
		refresh, retry, expire, minimum int
	)
	err := d.sql.QueryRowContext(ctx, `
		SELECT type, dnssec_enabled, soa_serial, soa_refresh, soa_retry, soa_expire, soa_minimum
		FROM zones WHERE name = $1
	`, name).Scan(&typ, &dnssec, &serial, &refresh, &retry, &expire, &minimum)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"name": name, "type": typ, "dnssec_enabled": dnssec,
		"soa_serial": serial, "soa_refresh": refresh, "soa_retry": retry,
		"soa_expire": expire, "soa_minimum": minimum,
	}, nil
}

func (d *DB) UpdateZoneMeta(ctx context.Context, name string, dnssec *bool, serial *int64, refresh, retry, expire, minimum *int) error {
	if d == nil || d.sql == nil {
		return fmt.Errorf("database disabled")
	}
	name = config.NormalizeName(name)
	_, err := d.sql.ExecContext(ctx, `
		UPDATE zones SET
			dnssec_enabled = COALESCE($2, dnssec_enabled),
			soa_serial = COALESCE($3, soa_serial),
			soa_refresh = COALESCE($4, soa_refresh),
			soa_retry = COALESCE($5, soa_retry),
			soa_expire = COALESCE($6, soa_expire),
			soa_minimum = COALESCE($7, soa_minimum),
			updated_at = NOW()
		WHERE name = $1
	`, name, dnssec, serial, refresh, retry, expire, minimum)
	return err
}

func (d *DB) DeleteRecord(ctx context.Context, zone, name, typ string) error {
	if d == nil || d.sql == nil {
		return fmt.Errorf("database disabled")
	}
	_, err := d.sql.ExecContext(ctx, `
		DELETE FROM records r USING zones z
		WHERE r.zone_id = z.id AND z.name = $1 AND r.name = $2 AND ($3 = '' OR r.type = $3)
	`, config.NormalizeName(zone), config.NormalizeName(name), typ)
	return err
}
