package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/secondary"
)

func (a *API) handleSecondary(w http.ResponseWriter, r *http.Request) {
	mgr := a.srv.Secondary()
	if mgr == nil {
		http.Error(w, "secondary manager unavailable", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"zones": mgr.List()})
	case http.MethodPost:
		var body secondary.Zone
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		if err := mgr.Upsert(body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		go func() {
			_ = mgr.Transfer(r.Context(), body.Name)
		}()
		writeJSON(w, http.StatusCreated, map[string]any{"zone": body.Name, "zones": mgr.List()})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *API) handleSecondarySub(w http.ResponseWriter, r *http.Request) {
	mgr := a.srv.Secondary()
	if mgr == nil {
		http.Error(w, "secondary manager unavailable", http.StatusServiceUnavailable)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/secondary/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	zone := config.NormalizeName(parts[0])

	if len(parts) == 1 {
		switch r.Method {
		case http.MethodDelete:
			if !mgr.Delete(zone) {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		case http.MethodPut, http.MethodPatch:
			var body secondary.Zone
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "invalid json", http.StatusBadRequest)
				return
			}
			body.Name = zone
			if err := mgr.Upsert(body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"zones": mgr.List()})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	if len(parts) == 2 && parts[1] == "transfer" && r.Method == http.MethodPost {
		if err := mgr.Transfer(r.Context(), zone); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "zones": mgr.List()})
		return
	}
	http.NotFound(w, r)
}
