package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/powersvx/powersvx/internal/allowlist"
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
	case path == "blacklist":
		a.handleBlacklist(w, r)
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
	whitelisted := a.srv.Allowlist().Allows(norm)
	blacklisted := false
	if bl := a.srv.Denylist(); bl != nil {
		blacklisted = bl.Blocks(norm)
	}
	out := map[string]any{
		"name":         strings.TrimSuffix(norm, "."),
		"whitelisted":  whitelisted,
		"blacklisted":  blacklisted,
		"blocked":      false,
		"action":       "",
		"target":       "",
		"in_rpz":       false,
		"block_source": "",
	}
	if eng := a.srv.RPZ(); eng != nil && eng.Enabled() {
		hit, ok := eng.Lookup(norm)
		if ok {
			hit.Action = rpz.Action(allowlist.BankSafeRPZAction(norm, string(hit.Action)))
			if hit.Action == rpz.ActionPass {
				ok = false
				hit = rpz.Hit{}
			} else if hit.Action == rpz.ActionNXDOMAIN {
				hit.Target = ""
			}
			out["in_rpz"] = ok
			out["action"] = string(hit.Action)
			out["target"] = hit.Target
		}
	}
	if whitelisted {
		writeJSON(w, http.StatusOK, out)
		return
	}
	if blacklisted {
		out["blocked"] = true
		out["action"] = "nxdomain"
		out["block_source"] = "manual"
		writeJSON(w, http.StatusOK, out)
		return
	}
	if out["in_rpz"] == true {
		if action, _ := out["action"].(string); action != "" && action != string(rpz.ActionPass) {
			out["blocked"] = true
			out["block_source"] = "rpz"
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

func (a *API) handleBlacklist(w http.ResponseWriter, r *http.Request) {
	bl := a.srv.Denylist()
	if bl == nil {
		http.Error(w, "blacklist unavailable", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"domains": bl.List(),
			"count":   bl.Count(),
		})
	case http.MethodPost:
		var body struct {
			Domain string `json:"domain"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Domain) == "" {
			http.Error(w, "domain required", http.StatusBadRequest)
			return
		}
		d, err := bl.Add(body.Domain)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"domain":  strings.TrimSuffix(d, "."),
			"domains": bl.List(),
			"count":   bl.Count(),
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
		ok, err := bl.Remove(name)
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
			"domains": bl.List(),
			"count":   bl.Count(),
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
