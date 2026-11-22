package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/powersvx/powersvx/internal/allowlist"
	"github.com/powersvx/powersvx/internal/api"
	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/denylist"
	"github.com/powersvx/powersvx/internal/eventlog"
	"github.com/powersvx/powersvx/internal/geo"
	"github.com/powersvx/powersvx/internal/rpz"
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
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := server.New(cfg, server.Deps{Auth: auth}, log)
	a := api.New(cfg, srv, nil, auth, log)
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
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := server.New(cfg, server.Deps{Auth: auth}, log)
	bus := eventlog.New(10)
	bus.Emit("warn", "test", "hello", map[string]string{"k": "v"})
	a := api.New(cfg, srv, nil, auth, log)
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

func TestSettingsToggle(t *testing.T) {
	cfg := &config.Config{}
	cfg.API.RESTEnabled = true
	cfg.GeoDNS.Enabled = true
	cfg.Resolver.Mode = "forward"
	cfg.Resolver.ForwardOnFail = true
	auth := authoritative.NewStore()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	geoRes, _ := geo.New(true, "", "default")
	srv := server.New(cfg, server.Deps{Auth: auth, Geo: geoRes}, log)
	a := api.New(cfg, srv, nil, auth, log)
	h := a.Handler()

	body := bytes.NewBufferString(`{"geodns":false}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings", body)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	if geoRes.Enabled() {
		t.Fatal("geodns should be off")
	}
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out["geodns"] != false {
		t.Fatalf("%v", out)
	}

	body = bytes.NewBufferString(`{"resolver_mode":"recursive","forward_on_fail":true,"forwarders":["1.0.0.1","8.8.4.4:53"],"query_log_enabled":true}`)
	req = httptest.NewRequest(http.MethodPut, "/api/v1/settings", body)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("forwarders settings: %d %s", rr.Code, rr.Body.String())
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out["resolver_mode"] != "recursive" {
		t.Fatalf("%v", out)
	}
	fw, _ := out["forwarders"].([]any)
	if len(fw) != 2 || fw[0] != "1.0.0.1:53" || fw[1] != "8.8.4.4:53" {
		t.Fatalf("forwarders=%v", out["forwarders"])
	}
	if len(cfg.Resolver.Forwarders) != 2 || cfg.Resolver.Forwarders[0] != "1.0.0.1:53" {
		t.Fatalf("stored forwarders=%v", cfg.Resolver.Forwarders)
	}
}

func TestWhitelistAndDomainLookup(t *testing.T) {
	cfg := &config.Config{}
	cfg.API.RESTEnabled = true
	cfg.API.AuthType = "token"
	cfg.API.APIToken = "secret"
	auth := authoritative.NewStore()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	wl := allowlist.New("")
	bl := denylist.New("")
	eng := rpz.New(true)
	eng.Replace(map[string]rpz.Action{"bad.example.com.": rpz.ActionNXDOMAIN})
	srv := server.New(cfg, server.Deps{Auth: auth, Allow: wl, Deny: bl, RPZ: eng}, log)
	a := api.New(cfg, srv, nil, auth, log)
	h := a.Handler()
	authH := func(method, url string, body io.Reader) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, url, body)
		req.Header.Set("Authorization", "Bearer secret")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	rr := authH(http.MethodPost, "/api/v1/domains/whitelist", bytes.NewBufferString(`{"domain":"bad.example.com"}`))
	if rr.Code != http.StatusCreated {
		t.Fatalf("add wl: %d %s", rr.Code, rr.Body.String())
	}
	rr = authH(http.MethodGet, "/api/v1/domains/lookup?name=bad.example.com", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("lookup: %d", rr.Code)
	}
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out["whitelisted"] != true || out["blocked"] != false || out["in_rpz"] != true {
		t.Fatalf("%v", out)
	}
	rr = authH(http.MethodDelete, "/api/v1/domains/whitelist?name=bad.example.com", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("del: %d %s", rr.Code, rr.Body.String())
	}
	rr = authH(http.MethodGet, "/api/v1/domains/lookup?name=bad.example.com", nil)
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out["blocked"] != true {
		t.Fatalf("should block after remove: %v", out)
	}

	rr = authH(http.MethodPost, "/api/v1/domains/blacklist", bytes.NewBufferString(`{"domain":"manual.block.test"}`))
	if rr.Code != http.StatusCreated {
		t.Fatalf("add bl: %d %s", rr.Code, rr.Body.String())
	}
	rr = authH(http.MethodGet, "/api/v1/domains/lookup?name=sub.manual.block.test", nil)
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out["blacklisted"] != true || out["blocked"] != true || out["block_source"] != "manual" {
		t.Fatalf("manual bl: %v", out)
	}
	// whitelist wins over manual blacklist
	rr = authH(http.MethodPost, "/api/v1/domains/whitelist", bytes.NewBufferString(`{"domain":"manual.block.test"}`))
	if rr.Code != http.StatusCreated {
		t.Fatalf("wl over bl: %d %s", rr.Code, rr.Body.String())
	}
	rr = authH(http.MethodGet, "/api/v1/domains/lookup?name=sub.manual.block.test", nil)
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out["whitelisted"] != true || out["blocked"] != false {
		t.Fatalf("whitelist should win: %v", out)
	}
}
