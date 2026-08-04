package api

import (
	"encoding/json"
	"net/http"

	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/conntrack"
)

func (a *API) handleConntrack(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, a.conntrackPayload())
	case http.MethodPut, http.MethodPatch:
		var body struct {
			Managed  *bool   `json:"conntrack_managed"`
			Max      *uint64 `json:"conntrack_max"`
			Hashsize *uint64 `json:"conntrack_hashsize"`
			Persist  *bool   `json:"conntrack_persist"`
			ApplyNow *bool   `json:"apply_now"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		rs := a.loadRuntimeSettings()
		if body.Managed != nil {
			rs.ConntrackManaged = body.Managed
		}
		if body.Max != nil {
			rs.ConntrackMax = body.Max
		}
		if body.Hashsize != nil {
			rs.ConntrackHashsize = body.Hashsize
		}
		if body.Persist != nil {
			rs.ConntrackPersist = body.Persist
		}
		cfg := a.conntrackCfgFromRuntime(rs)
		if cfg.Managed {
			if _, err := conntrack.Normalize(cfg); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		if err := config.SaveRuntimeSettings(config.RuntimeSettingsPath(a.dataDir), rs); err != nil {
			http.Error(w, "persist failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		applyNow := body.ApplyNow == nil || *body.ApplyNow
		if applyNow && cfg.Managed {
			if err := conntrack.Apply(cfg); err != nil {
				writeJSON(w, http.StatusOK, a.conntrackPayloadWithErr(err))
				return
			}
		}
		writeJSON(w, http.StatusOK, a.conntrackPayload())
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *API) handleConntrackApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rs := a.loadRuntimeSettings()
	on := true
	rs.ConntrackManaged = &on
	if rs.ConntrackMax == nil {
		m := conntrack.DefaultMax
		rs.ConntrackMax = &m
	}
	if rs.ConntrackPersist == nil {
		p := true
		rs.ConntrackPersist = &p
	}
	_ = config.SaveRuntimeSettings(config.RuntimeSettingsPath(a.dataDir), rs)
	cfg := a.conntrackCfgFromRuntime(rs)
	if err := conntrack.Apply(cfg); err != nil {
		writeJSON(w, http.StatusOK, a.conntrackPayloadWithErr(err))
		return
	}
	writeJSON(w, http.StatusOK, a.conntrackPayload())
}

func (a *API) conntrackCfgFromRuntime(rs config.RuntimeSettings) conntrack.Config {
	cfg := conntrack.Config{
		Managed: rs.ConntrackManaged != nil && *rs.ConntrackManaged,
		Persist: rs.ConntrackPersist == nil || (rs.ConntrackPersist != nil && *rs.ConntrackPersist),
	}
	if rs.ConntrackMax != nil {
		cfg.Max = *rs.ConntrackMax
	}
	if rs.ConntrackHashsize != nil {
		cfg.Hashsize = *rs.ConntrackHashsize
	}
	return cfg
}

func (a *API) conntrackPayloadWithErr(err error) map[string]any {
	p := a.conntrackPayload()
	if err != nil {
		p["apply_error"] = err.Error()
	}
	return p
}

func (a *API) conntrackPayload() map[string]any {
	rs := a.loadRuntimeSettings()
	cfg := a.conntrackCfgFromRuntime(rs)
	st := conntrack.GetStatus(cfg)
	presets := []map[string]any{
		{"label": "512K", "max": uint64(524_288)},
		{"label": "1M", "max": uint64(1_048_576)},
		{"label": "2M (recommended)", "max": conntrack.DefaultMax},
		{"label": "4M", "max": uint64(4_194_304)},
	}
	hash := cfg.Hashsize
	if hash == 0 && cfg.Max > 0 {
		hash = conntrack.SuggestHashsize(cfg.Max)
	} else if hash == 0 {
		hash = conntrack.SuggestHashsize(conntrack.DefaultMax)
	}
	maxOut := cfg.Max
	if maxOut == 0 {
		maxOut = conntrack.DefaultMax
	}
	return map[string]any{
		"supported":           conntrack.Supported(),
		"conntrack_managed":   cfg.Managed,
		"conntrack_max":       maxOut,
		"conntrack_hashsize":  hash,
		"conntrack_persist":   cfg.Persist,
		"min_max":             conntrack.MinMax,
		"max_max":             conntrack.MaxMax,
		"default_max":         conntrack.DefaultMax,
		"presets":             presets,
		"status":              st,
		"note": "Live apply needs writable host sysctl paths (host compose bind-mounts /powersvx-sys). Persist writes /etc/sysctl.d + modprobe.d when writable; PowerSVX also re-applies on startup from runtime-settings.json.",
	}
}

// SyncConntrackOnStartup applies managed conntrack limits after boot.
func SyncConntrackOnStartup(dataDir string) error {
	rs, err := config.LoadRuntimeSettings(config.RuntimeSettingsPath(dataDir))
	if err != nil {
		return nil
	}
	if rs.ConntrackManaged == nil || !*rs.ConntrackManaged {
		return nil
	}
	cfg := conntrack.Config{
		Managed: true,
		Persist: rs.ConntrackPersist == nil || (rs.ConntrackPersist != nil && *rs.ConntrackPersist),
	}
	if rs.ConntrackMax != nil {
		cfg.Max = *rs.ConntrackMax
	}
	if rs.ConntrackHashsize != nil {
		cfg.Hashsize = *rs.ConntrackHashsize
	}
	return conntrack.Apply(cfg)
}
