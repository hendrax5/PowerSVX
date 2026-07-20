package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/powersvx/powersvx/internal/api"
	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/cache"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/eventlog"
	"github.com/powersvx/powersvx/internal/server"
)

func TestZonesCRUDAndAuth(t *testing.T) {
	cfg := &config.Config{}
	cfg.API.RESTEnabled = true
	cfg.API.AuthType = "token"
	cfg.API.APIToken = "secret"
	cfg.Resolver.Mode = "forward"
	cfg.Resolver.DNSSECMode = "off"
	auth := authoritative.NewStore()
	tier := cache.NewTier(cache.NewL1(1000), nil, time.Minute, time.Minute)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := server.New(cfg, server.Deps{Cache: tier, Auth: auth}, log)
	a := api.New(cfg, srv, nil, tier, auth, log)
	h := a.Handler()

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/zones", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}

	body := bytes.NewBufferString(`{"name":"example.com"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/zones", body)
	req.Header.Set("Authorization", "Bearer secret")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/zones", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("list: %d", rr.Code)
	}
	var list struct {
		Zones []struct {
			Name        string `json:"name"`
			RecordCount int    `json:"record_count"`
		} `json:"zones"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Zones) != 1 {
		t.Fatalf("zones=%v", list.Zones)
	}

	body = bytes.NewBufferString(`{"name":"www.example.com","type":"A","content":"1.2.3.4","ttl":60}`)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/zones/example.com/records", body)
	req.Header.Set("Authorization", "Bearer secret")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("record: %d %s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("health: %d", rr.Code)
	}
}

func TestEventsRecent(t *testing.T) {
	cfg := &config.Config{}
	cfg.API.RESTEnabled = true
	cfg.Resolver.Mode = "forward"
	auth := authoritative.NewStore()
	tier := cache.NewTier(cache.NewL1(100), nil, time.Minute, time.Minute)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := server.New(cfg, server.Deps{Cache: tier, Auth: auth}, log)
	bus := eventlog.New(10)
	bus.Emit("warn", "test", "hello", map[string]string{"k": "v"})
	a := api.New(cfg, srv, nil, tier, auth, log)
	a.SetEvents(bus)
	h := a.Handler()

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/events", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("code %d", rr.Code)
	}
	var body struct {
		Events []map[string]any `json:"events"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Events) != 1 || body.Events[0]["message"] != "hello" {
		t.Fatalf("%s", rr.Body.String())
	}
}
