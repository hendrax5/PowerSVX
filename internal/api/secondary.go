package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/secondary"
)

func (a *API) secondaryTSIGKeyNames() []string {
	if a == nil || a.srv == nil || a.srv.TSIG() == nil {
		return []string{}
	}
	names := a.srv.TSIG().Names()
	if names == nil {
		return []string{}
	}
	return names
}

func (a *API) handleSecondary(w http.ResponseWriter, r *http.Request) {
	mgr := a.srv.Secondary()
	if mgr == nil {
		http.Error(w, "secondary manager unavailable", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"zones":     mgr.List(),
			"tsig_keys": a.secondaryTSIGKeyNames(),
		})
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
		zoneName := config.NormalizeName(body.Name)
		a.SyncSecondaryDataplane(zoneName)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			if err := mgr.Transfer(ctx, zoneName); err != nil && a.log != nil {
				a.log.Warn("initial secondary AXFR/IXFR failed", "zone", zoneName, "err", err)
			}
		}()
		writeJSON(w, http.StatusCreated, map[string]any{
			"zone":      zoneName,
			"zones":     mgr.List(),
			"tsig_keys": a.secondaryTSIGKeyNames(),
		})
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
			a.SyncSecondaryDataplane(zone)
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
			a.SyncSecondaryDataplane(zone)
			writeJSON(w, http.StatusOK, map[string]any{
				"zones":     mgr.List(),
				"tsig_keys": a.secondaryTSIGKeyNames(),
			})
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
		a.SyncSecondaryDataplane(zone)
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":        true,
			"zones":     mgr.List(),
			"tsig_keys": a.secondaryTSIGKeyNames(),
		})
		return
	}
	http.NotFound(w, r)
}
