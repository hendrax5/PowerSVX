package api

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/powersvx/powersvx/internal/apiauth"
	"github.com/powersvx/powersvx/internal/audit"
)

type loginLimiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{hits: map[string][]time.Time{}}
}

func (l *loginLimiter) allow(ip string) bool {
	const max = 5
	const window = time.Minute
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	cut := now.Add(-window)
	arr := l.hits[ip]
	n := 0
	for _, t := range arr {
		if t.After(cut) {
			arr[n] = t
			n++
		}
	}
	arr = arr[:n]
	if len(arr) >= max {
		l.hits[ip] = arr
		return false
	}
	arr = append(arr, now)
	l.hits[ip] = arr
	return true
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (a *API) handleAuth(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/auth/")
	rest = strings.Trim(rest, "/")
	parts := strings.Split(rest, "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	switch parts[0] {
	case "login":
		a.handleLogin(w, r)
	case "logout":
		a.withAuth(a.handleLogout)(w, r)
	case "me":
		a.withAuth(a.handleMe)(w, r)
	case "users":
		a.withAuth(a.handleAuthUsers)(w, r)
	case "tokens":
		a.withAuth(a.handleAuthTokens)(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (a *API) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if strings.ToLower(a.cfg.API.AuthType) != "local" {
		http.Error(w, "local auth disabled", http.StatusBadRequest)
		return
	}
	if a.users == nil || a.sessions == nil {
		http.Error(w, "auth not configured", http.StatusServiceUnavailable)
		return
	}
	ip := clientIP(r)
	if a.loginLim != nil && !a.loginLim.allow(ip) {
		http.Error(w, "too many login attempts", http.StatusTooManyRequests)
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	p, ok := a.users.Authenticate(body.Username, body.Password)
	if !ok {
		if a.audit != nil {
			a.audit.Record(audit.Event{Actor: body.Username, Action: "login_fail", Path: r.URL.Path, Status: http.StatusUnauthorized})
		}
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	id, err := a.sessions.Create(p)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	a.sessions.SetCookie(w, r, id)
	if a.audit != nil {
		a.audit.Record(audit.Event{Actor: p.Name, Role: p.Role, Action: "login", Path: r.URL.Path, Status: http.StatusOK})
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": p.Name, "role": p.Role})
}

func (a *API) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.sessions != nil {
		id := apiauth.ReadSessionCookie(r)
		a.sessions.Delete(id)
		a.sessions.ClearCookie(w, r)
	}
	if p, ok := apiauth.PrincipalFrom(r.Context()); ok && a.audit != nil {
		a.audit.Record(audit.Event{Actor: p.Name, Role: p.Role, Action: "logout", Path: r.URL.Path, Status: http.StatusOK})
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) handleMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p, ok := apiauth.PrincipalFrom(r.Context())
	if !ok {
		// auth_type=none
		writeJSON(w, http.StatusOK, map[string]any{
			"name": "anonymous", "role": "admin", "auth_type": a.cfg.API.AuthType, "auth_required": false,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name": p.Name, "role": p.Role, "auth_type": a.cfg.API.AuthType, "auth_required": true,
	})
}

func (a *API) handleAuthUsers(w http.ResponseWriter, r *http.Request) {
	if a.users == nil {
		http.Error(w, "user store unavailable", http.StatusServiceUnavailable)
		return
	}
	p, _ := apiauth.PrincipalFrom(r.Context())
	if p.Role != apiauth.RoleAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"users": a.users.List()})
	case http.MethodPost:
		var body struct {
			Name     string `json:"name"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		if err := a.users.Upsert(body.Name, body.Password, body.Role); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if a.audit != nil {
			a.audit.Record(audit.Event{Actor: p.Name, Role: p.Role, Action: "user_upsert", Path: r.URL.Path, Status: http.StatusOK, Meta: map[string]string{"user": body.Name}})
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case http.MethodDelete:
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "name required", http.StatusBadRequest)
			return
		}
		if err := a.users.Delete(name); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if a.audit != nil {
			a.audit.Record(audit.Event{Actor: p.Name, Role: p.Role, Action: "user_delete", Path: r.URL.Path, Status: http.StatusNoContent, Meta: map[string]string{"user": name}})
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *API) handleAuthTokens(w http.ResponseWriter, r *http.Request) {
	if a.tokens == nil {
		http.Error(w, "token store unavailable", http.StatusServiceUnavailable)
		return
	}
	p, _ := apiauth.PrincipalFrom(r.Context())
	if strings.EqualFold(a.cfg.API.AuthType, "local") || strings.EqualFold(a.cfg.API.AuthType, "token") {
		if p.Role != apiauth.RoleAdmin {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	switch r.Method {
	case http.MethodGet:
		list := a.tokens.List()
		if list == nil {
			list = []apiauth.StoredToken{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"tokens": list})
	case http.MethodPost:
		var body struct {
			Name    string `json:"name"`
			Role    string `json:"role"`
			TTLDays int    `json:"ttl_days"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		meta, plain, err := a.tokens.Create(body.Name, body.Role, body.TTLDays)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if a.audit != nil {
			a.audit.Record(audit.Event{
				Actor: p.Name, Role: p.Role, Action: "token_create", Path: r.URL.Path, Status: http.StatusCreated,
				Meta: map[string]string{"id": meta.ID, "name": meta.Name, "role": meta.Role},
			})
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"id":         meta.ID,
			"name":       meta.Name,
			"role":       meta.Role,
			"prefix":     meta.Prefix,
			"created_at": meta.CreatedAt,
			"expires_at": meta.ExpiresAt,
			"token":      plain,
		})
	case http.MethodDelete:
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if id == "" {
			http.Error(w, "id required", http.StatusBadRequest)
			return
		}
		if err := a.tokens.Revoke(id); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		if a.audit != nil {
			a.audit.Record(audit.Event{
				Actor: p.Name, Role: p.Role, Action: "token_revoke", Path: r.URL.Path, Status: http.StatusNoContent,
				Meta: map[string]string{"id": id},
			})
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
