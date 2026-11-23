package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/powersvx/powersvx/internal/api"
	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/server"
)

type queryLogRig struct {
	t    *testing.T
	h    http.Handler
	api  *api.API
	cfg  *config.Config
	dir  string
	sock string
}

func newQueryLogRig(t *testing.T, enabled bool, rate float64) *queryLogRig {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the dnstap socket is exercised on Linux")
	}
	dir, err := os.MkdirTemp("", "qlapi")
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
	cfg.Logging.QueryLogEnabled = enabled
	cfg.Logging.QueryLogSampleRate = rate
	auth := authoritative.NewStore()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := server.New(cfg, server.Deps{Auth: auth}, log)
	a := api.New(cfg, srv, nil, auth, log)
	a.SetDataDir(dir)
	a.StartQueryLog()
	t.Cleanup(a.StopQueryLog)
	return &queryLogRig{t: t, h: a.Handler(), api: a, cfg: cfg, dir: dir, sock: filepath.Join(dir, "dnstap", "query.sock")}
}

func (r *queryLogRig) rate() string {
	b, err := os.ReadFile(filepath.Join(r.dir, "dnstap", "rate"))
	if err != nil {
		r.t.Fatalf("rate file: %v", err)
	}
	return strings.TrimSpace(string(b))
}

func (r *queryLogRig) call(method, path, body string) *httptest.ResponseRecorder {
	r.t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer secret")
	rr := httptest.NewRecorder()
	r.h.ServeHTTP(rr, req)
	return rr
}

// replay plays the capture of a real dnsdist 1.9.16 stream into the listener.
func (r *queryLogRig) replay() net.Conn {
	r.t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "dnstap", "testdata", "stream.bin"))
	if err != nil {
		r.t.Fatal(err)
	}
	c, err := net.Dial("unix", r.sock)
	if err != nil {
		r.t.Fatal(err)
	}
	const ready = 42 // the READY control frame; the reader answers ACCEPT before START
	if _, err := c.Write(raw[:ready]); err != nil {
		r.t.Fatal(err)
	}
	accept := make([]byte, 8+4+8+len("protobuf:dnstap.Dnstap"))
	if _, err := io.ReadFull(c, accept); err != nil {
		r.t.Fatalf("no ACCEPT from the listener: %v", err)
	}
	if _, err := c.Write(raw[ready:]); err != nil {
		r.t.Fatal(err)
	}
	return c
}

type liveQuery struct {
	QName    string `json:"qname"`
	ClientIP string `json:"client_ip"`
	Path     string `json:"path"`
	Action   string `json:"action"`
	Blocked  bool   `json:"blocked"`
	Source   string `json:"source"`
}

// live returns the live stream once it has wantAtLeast entries and one for each action in waitFor.
func (r *queryLogRig) live(wantAtLeast int, waitFor ...string) []liveQuery {
	r.t.Helper()
	var out struct {
		Queries []liveQuery `json:"queries"`
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		rr := r.call(http.MethodGet, "/api/v1/queries/live?limit=500", "")
		if rr.Code != http.StatusOK {
			r.t.Fatalf("live: %d %s", rr.Code, rr.Body.String())
		}
		out.Queries = nil
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			r.t.Fatal(err)
		}
		seen := map[string]bool{}
		for _, q := range out.Queries {
			seen[q.Action] = true
		}
		missing := false
		for _, a := range waitFor {
			missing = missing || !seen[a]
		}
		if len(out.Queries) >= wantAtLeast && !missing {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return out.Queries
}

func TestQueryLogFeedsLiveStreamWithActions(t *testing.T) {
	r := newQueryLogRig(t, true, 1)
	c := r.replay()
	defer c.Close()

	qs := r.live(6, "allowed", "blocked-filter", "blocked-custom", "auth", "recursed", "refused")
	if len(qs) < 6 {
		t.Fatalf("only %d queries reached the live stream", len(qs))
	}
	actions := map[string]liveQuery{}
	for _, q := range qs {
		actions[q.Action] = q
		if q.Source != "dnsdist" || q.ClientIP == "" || q.Path != q.Action {
			t.Errorf("unexpected entry %+v", q)
		}
	}
	for action, blocked := range map[string]bool{
		"allowed": false, "blocked-filter": true, "blocked-custom": true, "auth": false, "recursed": false, "refused": false,
	} {
		q, ok := actions[action]
		if !ok {
			t.Errorf("no entry with action %s", action)
			continue
		}
		if q.Blocked != blocked {
			t.Errorf("action %s: blocked=%v, want %v", action, q.Blocked, blocked)
		}
	}
	if q := actions["blocked-filter"]; q.QName != "blocked.filter.powersvx.test" {
		t.Errorf("filter entry names %q", q.QName)
	}

	// The blocked-only filter is a fact now, not a guess from the response code.
	rr := r.call(http.MethodGet, "/api/v1/queries/live?blocked=1&limit=500", "")
	var blockedOnly struct {
		Queries []liveQuery `json:"queries"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &blockedOnly)
	for _, q := range blockedOnly.Queries {
		if !strings.HasPrefix(q.Action, "blocked-") {
			t.Errorf("blocked filter returned action %s", q.Action)
		}
	}
	if len(blockedOnly.Queries) == 0 {
		t.Error("blocked filter returned nothing")
	}

	rr = r.call(http.MethodGet, "/api/v1/settings", "")
	var st map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &st)
	if st["query_log_dataplane_connected"] != true {
		t.Errorf("settings should report the Dataplane as connected: %v", st["query_log_dataplane_connected"])
	}
}

func TestQueryLogRateFollowsTheConsoleSettings(t *testing.T) {
	// Default: query log off, so the Dataplane is told 0 and no sampling rule is installed.
	r := newQueryLogRig(t, false, 0.05)
	if got := r.rate(); got != "0" {
		t.Fatalf("query log off: rate file %q, want 0", got)
	}

	put := func(body string) {
		t.Helper()
		if rr := r.call(http.MethodPut, "/api/v1/settings", body); rr.Code != http.StatusOK {
			t.Fatalf("PUT %s: %d %s", body, rr.Code, rr.Body.String())
		}
	}
	put(`{"query_log_enabled":true}`)
	if got := r.rate(); got != "0.05" {
		t.Fatalf("enabled at 5%%: rate file %q", got)
	}
	put(`{"query_log_sample_rate":0.5}`)
	if got := r.rate(); got != "0.5" {
		t.Fatalf("rate 0.5: rate file %q", got)
	}
	put(`{"query_log_sample_rate":0}`)
	if got := r.rate(); got != "0" {
		t.Fatalf("rate 0 with the log enabled must mean no sampling: rate file %q", got)
	}
	put(`{"query_log_sample_rate":1}`)
	put(`{"query_log_enabled":false}`)
	if got := r.rate(); got != "0" {
		t.Fatalf("disabled: rate file %q", got)
	}
	if rr := r.call(http.MethodPut, "/api/v1/settings", `{"query_log_sample_rate":2}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("rate above 1 must be rejected, got %d", rr.Code)
	}
}

// Without the Observability Profile the live stream still works and nothing is stored.
func TestQueryLogWithoutDatabaseKeepsLiveStream(t *testing.T) {
	r := newQueryLogRig(t, true, 1)
	c := r.replay()
	defer c.Close()
	if len(r.live(1)) == 0 {
		t.Fatal("no live queries without a database")
	}
	rr := r.call(http.MethodGet, "/api/v1/query-logs", "")
	if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), "query_history_unavailable") {
		t.Fatalf("history without a database: %d %s", rr.Code, rr.Body.String())
	}
}
