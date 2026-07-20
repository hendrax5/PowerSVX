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
	"github.com/powersvx/powersvx/internal/apiauth"
	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/cache"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/server"
)

func TestLocalLoginSessionAndRBAC(t *testing.T) {
	dir := t.TempDir()
	hash, err := apiauth.HashPassword("pass1234")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.API.RESTEnabled = true
	cfg.API.AuthType = "local"
	cfg.API.APIToken = "script-token"
	cfg.API.Users = []config.APIUserTOML{
		{Name: "admin", PasswordHash: hash, Role: "admin"},
		{Name: "viewer", PasswordHash: hash, Role: "readonly"},
	}
	cfg.Resolver.Mode = "forward"
	cfg.Resolver.DNSSECMode = "off"

	users, err := apiauth.NewUserStore(dir, cfg.API.Users)
	if err != nil {
		t.Fatal(err)
	}
	sess := apiauth.NewSessionStore(filepath.Join(dir, "sess"), apiauth.DefaultTTL, false)

	auth := authoritative.NewStore()
	tier := cache.NewTier(cache.NewL1(100), nil, time.Minute, time.Minute)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := server.New(cfg, server.Deps{Cache: tier, Auth: auth}, log)
	a := api.New(cfg, srv, nil, tier, auth, log)
	a.SetUserStore(users)
	a.SetSessionStore(sess)
	h := a.Handler()

	// login fail
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(`{"username":"admin","password":"wrong"}`))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("login fail want 401 got %d", rr.Code)
	}

	// login ok
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(`{"username":"admin","password":"pass1234"}`))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("login: %d %s", rr.Code, rr.Body.String())
	}
	cookie := rr.Result().Cookies()
	var sid *http.Cookie
	for _, c := range cookie {
		if c.Name == apiauth.SessionCookie {
			sid = c
		}
	}
	if sid == nil {
		t.Fatal("missing session cookie")
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.AddCookie(sid)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("me: %d", rr.Code)
	}

	// bearer token still works
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/v1/zones", nil)
	req.Header.Set("Authorization", "Bearer script-token")
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("token zones: %d", rr.Code)
	}

	// readonly cannot POST zones
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(`{"username":"viewer","password":"pass1234"}`))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("viewer login: %d", rr.Code)
	}
	var vCookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == apiauth.SessionCookie {
			vCookie = c
		}
	}
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/zones", bytes.NewBufferString(`{"name":"x.com"}`))
	req.AddCookie(vCookie)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("readonly POST want 403 got %d %s", rr.Code, rr.Body.String())
	}

	// admin can list users
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/v1/auth/users", nil)
	req.AddCookie(sid)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("users: %d %s", rr.Code, rr.Body.String())
	}
	var body struct {
		Users []map[string]any `json:"users"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Users) < 2 {
		t.Fatalf("users=%v", body.Users)
	}
}
