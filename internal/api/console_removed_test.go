package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/powersvx/powersvx/internal/api"
	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/geo"
	"github.com/powersvx/powersvx/internal/server"
)

func newConsoleHandler(t *testing.T) http.Handler {
	t.Helper()
	cfg := &config.Config{}
	cfg.API.RESTEnabled = true
	auth := authoritative.NewStore()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	geoRes, _ := geo.New(true, "", "default")
	srv := server.New(cfg, server.Deps{Auth: auth, Geo: geoRes}, log)
	return api.New(cfg, srv, nil, auth, log).Handler()
}

func getJSON(t *testing.T, h http.Handler, path string) map[string]any {
	t.Helper()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET %s: %d %s", path, rr.Code, rr.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestPayloadsCarryNothingForRemovedFeatures(t *testing.T) {
	h := newConsoleHandler(t)
	gone := map[string][]string{
		"/api/v1/status": {
			"mode", "dns_dataplane", "cache_l1_size",
			"dot_enabled", "doh_enabled", "doh3_enabled", "doq_enabled",
			"dot_addr", "doh_addr", "doq_addr",
		},
		"/api/v1/settings":    {"tls_min_version"},
		"/api/v1/cache/stats": {"go", "dataplane"},
	}
	for path, keys := range gone {
		out := getJSON(t, h, path)
		for _, k := range keys {
			if _, ok := out[k]; ok {
				t.Errorf("%s still returns %q", path, k)
			}
		}
	}
	checks, _ := getJSON(t, h, "/api/v1/health")["checks"].(map[string]any)
	for _, k := range []string{"dns_dot", "dns_doh", "dns_doh3", "dns_doq", "cache"} {
		if _, ok := checks[k]; ok {
			t.Errorf("health still reports %q", k)
		}
	}
}

func TestSettingsPutIgnoresFieldsAnOlderConsoleStillSends(t *testing.T) {
	h := newConsoleHandler(t)
	body := `{"geodns":false,"tproxy_listen":true,"tproxy_intercept":true,"tls_min_version":"1.2"}`
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPut, "/api/v1/settings", bytes.NewBufferString(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s", rr.Code, rr.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["geodns"] != false {
		t.Fatalf("the known field in the same request must still apply: %v", out["geodns"])
	}
}

func TestTProxyEndpointsAreGone(t *testing.T) {
	h := newConsoleHandler(t)
	for _, p := range []string{"/api/v1/tproxy", "/api/v1/tproxy/apply"} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, p, nil))
		if rr.Code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", p, rr.Code)
		}
	}
}
