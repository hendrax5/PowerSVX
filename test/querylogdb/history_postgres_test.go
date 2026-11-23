// Package querylogdb_test checks where the sampled query log is stored. It starts a
// real Postgres (postgres:16-alpine in Docker), upgrades an old query_logs table
// with db.Migrate, replays a stream captured from dnsdist 1.9.16 into the Control
// Plane's listener and reads the rows back over the API.
//
// The test needs Docker, so it only runs when POWERSVX_DOCKER_TESTS=1.
//
//	POWERSVX_DOCKER_TESTS=1 go test -count=1 -timeout 10m ./test/querylogdb/
//
// POWERSVX_DOCKER_TEST_HOST is the address the published port is reachable on
// (default 127.0.0.1), as for ./test/dataplane.
package querylogdb_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/powersvx/powersvx/internal/api"
	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/database"
	"github.com/powersvx/powersvx/internal/server"
)

const pgPassword = "querylog-test-only"

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

func startPostgres(t *testing.T) (string, int) {
	t.Helper()
	var b [6]byte
	_, _ = rand.Read(b[:])
	name := "powersvx-querylogdb-" + hex.EncodeToString(b[:])
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
	dsn := fmt.Sprintf("host=%s port=%d user=powersvx password=%s dbname=powersvx sslmode=disable", host, port, pgPassword)
	deadline := time.Now().Add(90 * time.Second)
	for {
		if db, err := sql.Open("pgx", dsn); err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			err = db.PingContext(ctx)
			cancel()
			_ = db.Close()
			if err == nil {
				// Past the image's init restart: a second clean ping a moment later.
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

// oldQueryLogs is the table as releases before the sampled query log created it.
const oldQueryLogs = `CREATE TABLE query_logs (
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
)`

// startControlPlane runs the API with a database and the query log listener.
func startControlPlane(t *testing.T, db *database.DB, host string, port int, maskIP, logEnabled bool) (*api.API, http.Handler, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "qldb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	t.Setenv("POWERSVX_DNSTAP_DIR", filepath.Join(dir, "dnstap"))
	t.Setenv("POWERSVX_BLOCKLIST_DIR", filepath.Join(dir, "blocklist"))

	cfg := &config.Config{}
	cfg.API.RESTEnabled = true
	cfg.API.AuthType = "token"
	cfg.API.APIToken = "secret"
	cfg.Resolver.Mode = "forward"
	cfg.Resolver.DNSSECMode = "off"
	cfg.Database = config.DatabaseConfig{Enabled: true, Host: host, Port: port, User: "powersvx", Password: pgPassword, Database: "powersvx"}
	cfg.Logging.QueryLogEnabled = logEnabled
	cfg.Logging.QueryLogSampleRate = 1
	cfg.Logging.QueryLogMaskIP = maskIP
	auth := authoritative.NewStore()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := server.New(cfg, server.Deps{Auth: auth}, log)
	a := api.New(cfg, srv, db, auth, log)
	a.SetDataDir(dir)
	a.StartQueryLog()
	return a, a.Handler(), filepath.Join(dir, "dnstap", "query.sock")
}

// replay plays the capture of a real dnsdist stream, answering as dnsdist expects.
func replay(t *testing.T, sock string) net.Conn {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "internal", "dnstap", "testdata", "stream.bin"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	const ready = 42
	if _, err := c.Write(raw[:ready]); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, make([]byte, 8+4+8+len("protobuf:dnstap.Dnstap"))); err != nil {
		t.Fatalf("no ACCEPT: %v", err)
	}
	if _, err := c.Write(raw[ready:]); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSampledQueryLogHistory(t *testing.T) {
	if os.Getenv("POWERSVX_DOCKER_TESTS") != "1" {
		t.Skip("set POWERSVX_DOCKER_TESTS=1 to run (needs Docker)")
	}
	host, port := startPostgres(t)
	dsn := fmt.Sprintf("host=%s port=%d user=powersvx password=%s dbname=powersvx sslmode=disable", host, port, pgPassword)
	raw, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	db, err := database.Connect(config.DatabaseConfig{Enabled: true, Host: host, Port: port, User: "powersvx", Password: pgPassword, Database: "powersvx"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// A new node: the table is created with the action column.
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate on a fresh database: %v", err)
	}
	var cols int
	if err := raw.QueryRow(`SELECT count(*) FROM information_schema.columns WHERE table_name='query_logs' AND column_name='action'`).Scan(&cols); err != nil || cols != 1 {
		t.Fatalf("fresh database has no action column (count %d, err %v)", cols, err)
	}
	if _, err := raw.Exec(`DROP TABLE query_logs`); err != nil {
		t.Fatal(err)
	}

	// A node upgrading from a release that already had the table, with a row in it.
	if _, err := raw.Exec(oldQueryLogs); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO query_logs (client_ip, query_name, query_type) VALUES ('192.0.2.1', 'old.example', 'A')`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ { // twice: the migration must be idempotent
		if err := db.Migrate(context.Background()); err != nil {
			t.Fatalf("migrate #%d: %v", i+1, err)
		}
	}

	t.Run("history is written, masked, with the action", func(t *testing.T) {
		a, h, sock := startControlPlane(t, db, host, port, true, true)
		defer a.StopQueryLog()
		c := replay(t, sock)
		defer c.Close()

		type row struct{ client, name, typ, action, proto string }
		var rows []row
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			rows = nil
			rs, err := raw.Query(`SELECT host(client_ip), query_name, query_type, COALESCE(action,''), COALESCE(protocol,'') FROM query_logs WHERE query_name <> 'old.example'`)
			if err != nil {
				t.Fatal(err)
			}
			for rs.Next() {
				var r row
				if err := rs.Scan(&r.client, &r.name, &r.typ, &r.action, &r.proto); err != nil {
					t.Fatal(err)
				}
				rows = append(rows, r)
			}
			_ = rs.Close()
			if len(rows) >= 6 {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		if len(rows) < 6 {
			t.Fatalf("only %d rows stored", len(rows))
		}
		actions := map[string]bool{}
		for _, r := range rows {
			actions[r.action] = true
			if !strings.HasSuffix(r.client, ".0") || r.client == "172.17.0.1" {
				t.Errorf("client %q was stored without masking", r.client)
			}
			if r.proto != "udp" {
				t.Errorf("protocol %q", r.proto)
			}
		}
		for _, want := range []string{"allowed", "blocked-filter", "blocked-custom", "auth", "recursed", "refused"} {
			if !actions[want] {
				t.Errorf("no stored row with action %s", want)
			}
		}

		// The API lists them, newest first, with the action; the pre-upgrade row has none.
		req := httptest.NewRequest(http.MethodGet, "/api/v1/query-logs?limit=100", nil)
		req.Header.Set("Authorization", "Bearer secret")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("query-logs: %d %s", rr.Code, rr.Body.String())
		}
		var out struct {
			Logs []struct {
				QueryName string `json:"query_name"`
				Action    string `json:"action"`
			} `json:"logs"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		var sawOld, sawFilter bool
		for _, l := range out.Logs {
			if l.QueryName == "old.example" && l.Action == "" {
				sawOld = true
			}
			if l.QueryName == "blocked.filter.powersvx.test" && l.Action == "blocked-filter" {
				sawFilter = true
			}
		}
		if !sawOld || !sawFilter {
			t.Errorf("API listing: old row %v, filter row %v", sawOld, sawFilter)
		}
	})

	t.Run("nothing is stored while the query log is disabled", func(t *testing.T) {
		if _, err := raw.Exec(`DELETE FROM query_logs`); err != nil {
			t.Fatal(err)
		}
		a, h, sock := startControlPlane(t, db, host, port, false, false)
		defer a.StopQueryLog()
		c := replay(t, sock)
		defer c.Close()
		// Wait for the live stream to have the queries, then check the table.
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/queries/live", nil)
			req.Header.Set("Authorization", "Bearer secret")
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if strings.Contains(rr.Body.String(), "blocked-filter") {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		time.Sleep(time.Second) // longer than the writer's flush interval
		var n int
		if err := raw.QueryRow(`SELECT count(*) FROM query_logs`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("%d rows stored with the query log disabled", n)
		}
	})
}
