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
