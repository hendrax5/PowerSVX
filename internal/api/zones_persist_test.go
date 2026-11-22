package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/powersvx/powersvx/internal/api"
	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/cache"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/server"
)

// startNode builds a node with the database disabled whose zones live in dir,
// the way cmd/powersvx wires it at start.
func startNode(t *testing.T, dir string) http.Handler {
	t.Helper()
	cfg := &config.Config{}
	cfg.API.RESTEnabled = true
	cfg.Resolver.Mode = "forward"
	cfg.Resolver.DNSSECMode = "off"
	cfg.Database.Enabled = false
	auth := authoritative.NewStore()
	if _, err := auth.EnablePersistence(dir); err != nil {
		t.Fatal(err)
	}
	tier := cache.NewTier(cache.NewL1(1000), nil, time.Minute, time.Minute)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := server.New(cfg, server.Deps{Cache: tier, Auth: auth}, log)
	return api.New(cfg, srv, nil, tier, auth, log).Handler()
}

func call(t *testing.T, h http.Handler, method, path, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

func TestZonesSurviveRestartWithDatabaseDisabled(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "zones")
	h := startNode(t, dir)

	if c, _ := call(t, h, "POST", "/api/v1/zones", `{"name":"example.com"}`); c != http.StatusCreated {
		t.Fatalf("create zone %d", c)
	}
	if c, _ := call(t, h, "POST", "/api/v1/zones/example.com/records", `{"name":"www.example.com","type":"A","content":"192.0.2.1","ttl":60}`); c != http.StatusCreated {
		t.Fatalf("add record %d", c)
	}
	if c, _ := call(t, h, "POST", "/api/v1/zones/example.com/records", `{"name":"old.example.com","type":"A","content":"192.0.2.9","ttl":60}`); c != http.StatusCreated {
		t.Fatalf("add record %d", c)
	}
	if c, _ := call(t, h, "PUT", "/api/v1/zones/example.com/records", `{"old_name":"www.example.com","old_type":"A","name":"www.example.com","type":"A","content":"192.0.2.2","ttl":60}`); c != http.StatusOK {
		t.Fatalf("update record %d", c)
	}
	if c, _ := call(t, h, "DELETE", "/api/v1/zones/example.com/records?name=old.example.com&type=A", ""); c != http.StatusNoContent {
		t.Fatalf("delete record %d", c)
	}
	call(t, h, "POST", "/api/v1/zones", `{"name":"gone.test"}`)
	if c, _ := call(t, h, "DELETE", "/api/v1/zones/gone.test", ""); c != http.StatusNoContent {
		t.Fatalf("delete zone %d", c)
	}

	h = startNode(t, dir) // restart
	c, z := call(t, h, "GET", "/api/v1/zones/example.com", "")
	if c != http.StatusOK {
		t.Fatalf("zone missing after restart: %d", c)
	}
	recs := z["records"].([]any)
	if len(recs) != 1 || recs[0].(map[string]any)["content"] != "192.0.2.2" {
		t.Fatalf("records after restart: %v", recs)
	}
	if c, _ := call(t, h, "GET", "/api/v1/zones/gone.test", ""); c != http.StatusNotFound {
		t.Fatalf("deleted zone came back: %d", c)
	}
}

func TestZoneMetaSOAAndDNSSECFlagWithDatabaseDisabled(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "zones")
	h := startNode(t, dir)
	call(t, h, "POST", "/api/v1/zones", `{"name":"example.com"}`)

	c, meta := call(t, h, "PUT", "/api/v1/zones/example.com", `{"dnssec_enabled":true,"soa_refresh":7200,"soa_serial":99}`)
	if c != http.StatusOK {
		t.Fatalf("meta update %d %v", c, meta)
	}
	if meta["dnssec_enabled"] != true || meta["soa_refresh"] != float64(7200) || meta["soa_serial"] != float64(99) {
		t.Fatalf("meta %v", meta)
	}
	if c, _ := call(t, h, "PUT", "/api/v1/zones/example.com", `{"soa_refresh":-1}`); c != http.StatusBadRequest {
		t.Fatalf("negative timer should be 400, got %d", c)
	}
	if c, _ := call(t, h, "PUT", "/api/v1/zones/missing.test", `{"soa_refresh":5}`); c != http.StatusNotFound {
		t.Fatalf("unknown zone should be 404, got %d", c)
	}

	h = startNode(t, dir) // restart
	_, z := call(t, h, "GET", "/api/v1/zones/example.com", "")
	m, _ := z["meta"].(map[string]any)
	if m == nil || m["dnssec_enabled"] != true || m["soa_refresh"] != float64(7200) || m["soa_serial"] != float64(99) {
		t.Fatalf("meta after restart: %v", z["meta"])
	}
}

func TestImportedZoneSurvivesRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "zones")
	h := startNode(t, dir)
	body, _ := json.Marshal(map[string]string{"zone": "example.org", "content": "$TTL 300\n@ IN SOA ns1 admin 1 3600 600 86400 300\nwww IN A 192.0.2.7\n"})
	if c, out := call(t, h, "POST", "/api/v1/zones/import", string(body)); c != http.StatusOK {
		t.Fatalf("import %d %v", c, out)
	}
	h = startNode(t, dir)
	_, z := call(t, h, "GET", "/api/v1/zones/example.org", "")
	if recs, _ := z["records"].([]any); len(recs) != 2 {
		t.Fatalf("records after restart: %v", z["records"])
	}
}
