// Package zonesexport_test runs the one-time export of Authoritative Zones from
// a real Postgres (postgres:16-alpine in Docker, schema from db.Migrate) and
// checks the zone files against the table contents.
//
// The test needs Docker, so it only runs when POWERSVX_DOCKER_TESTS=1.
//
//	POWERSVX_DOCKER_TESTS=1 go test -count=1 -timeout 10m ./test/zonesexport/
//
// POWERSVX_DOCKER_TEST_HOST is the address the published port is reachable on
// (default 127.0.0.1), as for ./test/dataplane.
package zonesexport_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/database"
)

const pgPassword = "export-test-only"

func docker(t *testing.T, args ...string) string {
	t.Helper()
	var out, errb bytes.Buffer
	cmd := exec.Command("docker", args...)
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("docker %s: %v\n%s%s", strings.Join(args, " "), err, out.String(), errb.String())
	}
	return strings.TrimSpace(out.String())
}

// startPostgres runs a throwaway postgres on a random published port and
// returns the host and port. The container is removed even if the test fails.
func startPostgres(t *testing.T) (string, int) {
	t.Helper()
	var b [6]byte
	_, _ = rand.Read(b[:])
	name := "powersvx-zonesexport-" + hex.EncodeToString(b[:])
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", "-v", name).Run() })
	docker(t, "run", "-d", "--name", name, "-p", "127.0.0.1::5432",
		"-e", "POSTGRES_PASSWORD="+pgPassword, "-e", "POSTGRES_DB=powersvx", "-e", "POSTGRES_USER=powersvx",
		"postgres:16-alpine")
	line, _, _ := strings.Cut(docker(t, "port", name, "5432/tcp"), "\n")
	_, p, err := net.SplitHostPort(strings.TrimSpace(line))
	if err != nil {
		t.Fatalf("docker port: %q: %v", line, err)
	}
	port, _ := strconv.Atoi(p)
	host := os.Getenv("POWERSVX_DOCKER_TEST_HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	// The image restarts the server once while initialising; wait for the final one.
	dsn := fmt.Sprintf("host=%s port=%d user=powersvx password=%s dbname=powersvx sslmode=disable", host, port, pgPassword)
	deadline := time.Now().Add(90 * time.Second)
	for {
		if db, err := sql.Open("pgx", dsn); err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			err = db.PingContext(ctx)
			cancel()
			_ = db.Close()
			if err == nil {
				// Two clean pings in a row, so we are past the init restart.
				time.Sleep(time.Second)
				if db2, err := sql.Open("pgx", dsn); err == nil {
					err = db2.Ping()
					_ = db2.Close()
					if err == nil {
						return host, port
					}
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("postgres not ready: %s", docker(t, "logs", "--tail", "20", name))
		}
		time.Sleep(time.Second)
	}
}

func count(t *testing.T, raw *sql.DB, table string) int {
	t.Helper()
	var n int
	if err := raw.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestExportFromRealPostgres(t *testing.T) {
	if os.Getenv("POWERSVX_DOCKER_TESTS") != "1" {
		t.Skip("set POWERSVX_DOCKER_TESTS=1 to run (needs Docker)")
	}
	host, port := startPostgres(t)

	db, err := database.Connect(config.DatabaseConfig{Enabled: true, Host: host, Port: port, User: "powersvx", Password: pgPassword, Database: "powersvx"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	raw, err := sql.Open("pgx", fmt.Sprintf("host=%s port=%d user=powersvx password=%s dbname=powersvx sslmode=disable", host, port, pgPassword))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	// A zone with every metadata field off its default, and a mixed-case name.
	var fullID, emptyID string
	if err := raw.QueryRow(`INSERT INTO zones (name, type, dnssec_enabled, soa_serial, soa_refresh, soa_retry, soa_expire, soa_minimum)
		VALUES ('Example.COM', 'native', true, 2024010101, 1800, 300, 604800, 120) RETURNING id::text`).Scan(&fullID); err != nil {
		t.Fatal(err)
	}
	// A zone with no records and default metadata.
	if err := raw.QueryRow(`INSERT INTO zones (name) VALUES ('empty.test') RETURNING id::text`).Scan(&emptyID); err != nil {
		t.Fatal(err)
	}
	recs := []struct {
		name, typ, content string
		ttl, prio          int
		disabled           bool
		geo, view          string
	}{
		{"Example.COM", "SOA", "ns1.example.com. admin.example.com. 2024010101 1800 300 604800 120", 3600, 0, false, "", ""},
		{"www.Example.COM", "A", "192.0.2.1", 60, 0, false, "ID", "lan"},
		{"www.example.com", "A", "192.0.2.2", 60, 0, false, "", ""},
		{"*.example.com", "A", "192.0.2.3", 300, 0, false, "", ""},
		{"example.com", "MX", "mx.example.com.", 300, 10, false, "", ""},
		{"example.com", "TXT", "v=spf1 -all", 300, 0, false, "", ""},
		{"off.example.com", "A", "192.0.2.4", 60, 0, true, "", ""},
	}
	for _, r := range recs {
		if _, err := raw.Exec(`INSERT INTO records (zone_id, name, type, content, ttl, prio, disabled, geo_tag, view_name)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, fullID, r.name, r.typ, r.content, r.ttl, r.prio, r.disabled, r.geo, r.view); err != nil {
			t.Fatal(err)
		}
	}
	zonesBefore, recordsBefore := count(t, raw, "zones"), count(t, raw, "records")

	served, err := db.LoadZones(ctx) // what the node served before the export existed
	if err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(t.TempDir(), "zones")
	n, ran, err := authoritative.ExportFromSource(ctx, db, dir)
	if err != nil || !ran || n != 2 {
		t.Fatalf("export: n=%d ran=%v err=%v", n, ran, err)
	}

	store := authoritative.NewStore()
	if loaded, err := store.EnablePersistence(dir); err != nil || loaded != 2 {
		t.Fatalf("load: n=%d err=%v", loaded, err)
	}

	// Records: exactly what LoadZones returned (disabled record excluded).
	for name, want := range served {
		got, ok := store.GetRecords(name)
		if !ok {
			t.Fatalf("zone %s missing from files", name)
		}
		if len(want) == 0 && len(got) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("zone %s records\n got %+v\nwant %+v", name, got, want)
		}
	}
	if store.ZoneCount() != len(served) {
		t.Fatalf("zone count %d, want %d", store.ZoneCount(), len(served))
	}
	full, _ := store.GetRecords("example.com.")
	if len(full) != 6 {
		t.Fatalf("example.com. has %d records, want the 6 enabled ones", len(full))
	}
	var sawWildcard, sawGeoView bool
	for _, r := range full {
		if r.Content == "192.0.2.4" {
			t.Fatal("disabled record was exported")
		}
		sawWildcard = sawWildcard || (r.Name == "*.example.com." && r.Content == "192.0.2.3")
		sawGeoView = sawGeoView || (r.Content == "192.0.2.1" && r.GeoTag == "ID" && r.View == "lan" && r.TTL == 60)
	}
	if !sawWildcard || !sawGeoView {
		t.Fatalf("wildcard=%v geo/view=%v in %+v", sawWildcard, sawGeoView, full)
	}

	// Meta: compare with the table values, read independently of LoadZoneMeta.
	rows, err := raw.Query(`SELECT name, type, dnssec_enabled, soa_serial, soa_refresh, soa_retry, soa_expire, soa_minimum FROM zones`)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for rows.Next() {
		var name string
		var want authoritative.ZoneMeta
		if err := rows.Scan(&name, &want.Type, &want.DNSSECEnabled, &want.SOASerial, &want.SOARefresh, &want.SOARetry, &want.SOAExpire, &want.SOAMinimum); err != nil {
			t.Fatal(err)
		}
		got, ok := store.GetZoneMeta(config.NormalizeName(name))
		if !ok || got != want {
			t.Fatalf("zone %s meta: got %+v want %+v", name, got, want)
		}
		seen++
	}
	rows.Close()
	if seen != 2 {
		t.Fatalf("read %d zone rows", seen)
	}
	// And against literal values, so a default-vs-default match cannot pass.
	wantFull := authoritative.ZoneMeta{Type: "native", DNSSECEnabled: true, SOASerial: 2024010101, SOARefresh: 1800, SOARetry: 300, SOAExpire: 604800, SOAMinimum: 120}
	if got, _ := store.GetZoneMeta("example.com."); got != wantFull {
		t.Fatalf("example.com. meta %+v want %+v", got, wantFull)
	}
	if got, _ := store.GetZoneMeta("empty.test."); got != authoritative.DefaultZoneMeta() {
		t.Fatalf("empty.test. meta %+v", got)
	}

	// The served answer for the wildcard comes out of the files too.
	if rrs, _ := store.Lookup("anything.example.com.", dns.TypeA); len(rrs) != 1 {
		t.Fatalf("wildcard lookup: %v", rrs)
	}

	// Second run does nothing, and the tables are as they were.
	if _, ran, err := authoritative.ExportFromSource(ctx, db, dir); err != nil || ran {
		t.Fatalf("second export: ran=%v err=%v", ran, err)
	}
	if z, r := count(t, raw, "zones"), count(t, raw, "records"); z != zonesBefore || r != recordsBefore {
		t.Fatalf("tables changed: zones %d->%d records %d->%d", zonesBefore, z, recordsBefore, r)
	}
}
