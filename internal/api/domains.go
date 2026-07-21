package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/rpz"
)

func (a *API) handleDomains(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/domains")
	path = strings.Trim(path, "/")
	switch {
	case path == "lookup" || path == "search":
		a.handleDomainLookup(w, r)
	case path == "whitelist":
		a.handleWhitelist(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (a *API) handleDomainLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		name = strings.TrimSpace(r.URL.Query().Get("q"))
	}
	if name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}
	norm := config.NormalizeName(name)
	whitelisted := false
	if wl := a.srv.Allowlist(); wl != nil {
		whitelisted = wl.Allows(norm)
	}
	out := map[string]any{
		"name":        strings.TrimSuffix(norm, "."),
		"whitelisted": whitelisted,
		"blocked":     false,
		"action":      "",
		"target":      "",
		"in_rpz":      false,
	}
	if eng := a.srv.RPZ(); eng != nil && eng.Enabled() {
		hit, ok := eng.Lookup(norm)
		if ok {
			out["in_rpz"] = true
			out["action"] = string(hit.Action)
			out["target"] = hit.Target
			if hit.Action != rpz.ActionPass && !whitelisted {
				out["blocked"] = true
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) handleWhitelist(w http.ResponseWriter, r *http.Request) {
	wl := a.srv.Allowlist()
	if wl == nil {
		http.Error(w, "whitelist unavailable", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"domains": wl.List(),
			"count":   wl.Count(),
		})
	case http.MethodPost:
		var body struct {
			Domain string `json:"domain"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Domain) == "" {
			http.Error(w, "domain required", http.StatusBadRequest)
			return
		}
		d, err := wl.Add(body.Domain)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"domain":  strings.TrimSuffix(d, "."),
			"domains": wl.List(),
			"count":   wl.Count(),
		})
	case http.MethodDelete:
		name := strings.TrimSpace(r.URL.Query().Get("name"))
		if name == "" {
			var body struct {
				Domain string `json:"domain"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			name = body.Domain
		}
		if strings.TrimSpace(name) == "" {
			http.Error(w, "name required", http.StatusBadRequest)
			return
		}
		ok, err := wl.Remove(name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"removed": strings.TrimSuffix(config.NormalizeName(name), "."),
			"domains": wl.List(),
			"count":   wl.Count(),
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
