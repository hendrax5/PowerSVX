package api

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/tproxy"
)

func (a *API) handleTProxy(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, a.tproxyPayload())
	case http.MethodPut, http.MethodPatch:
		var body struct {
			TProxyListen    *bool    `json:"tproxy_listen"`
			TProxyIntercept *bool    `json:"tproxy_intercept"`
			TProxyIface     *string  `json:"tproxy_iface"`
			TProxyMode      *string  `json:"tproxy_mode"`
			TProxyResolvers *[]string `json:"tproxy_resolvers"`
			TProxyMark      *uint32  `json:"tproxy_mark"`
			ApplyNow        *bool    `json:"apply_now"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		rs := a.loadRuntimeSettings()
		if body.TProxyListen != nil {
			rs.TProxyListen = body.TProxyListen
		}
		if body.TProxyIntercept != nil {
			rs.TProxyIntercept = body.TProxyIntercept
		}
		if body.TProxyIface != nil {
			rs.TProxyIface = strings.TrimSpace(*body.TProxyIface)
		}
		if body.TProxyMode != nil {
			mode := strings.ToLower(strings.TrimSpace(*body.TProxyMode))
			switch mode {
			case "public", "all", "custom":
				rs.TProxyMode = mode
			default:
				http.Error(w, "tproxy_mode must be public, all, or custom", http.StatusBadRequest)
				return
			}
		}
		if body.TProxyResolvers != nil {
			rs.TProxyResolvers = append([]string(nil), *body.TProxyResolvers...)
		}
		if body.TProxyMark != nil {
			rs.TProxyMark = body.TProxyMark
		}
		if err := config.SaveRuntimeSettings(config.RuntimeSettingsPath(a.dataDir), rs); err != nil {
			http.Error(w, "persist failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		applyNow := body.ApplyNow == nil || *body.ApplyNow
		if applyNow {
			if err := a.applyTProxyIntercept(rs); err != nil {
				writeJSON(w, http.StatusOK, a.tproxyPayloadWithErr(err))
				return
			}
		}
		writeJSON(w, http.StatusOK, a.tproxyPayload())
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *API) handleTProxyApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rs := a.loadRuntimeSettings()
	on := true
	rs.TProxyIntercept = &on
	_ = config.SaveRuntimeSettings(config.RuntimeSettingsPath(a.dataDir), rs)
	if err := a.applyTProxyIntercept(rs); err != nil {
		writeJSON(w, http.StatusOK, a.tproxyPayloadWithErr(err))
		return
	}
	writeJSON(w, http.StatusOK, a.tproxyPayload())
}

func (a *API) handleTProxyDisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rs := a.loadRuntimeSettings()
	off := false
	rs.TProxyIntercept = &off
	_ = config.SaveRuntimeSettings(config.RuntimeSettingsPath(a.dataDir), rs)
	if err := tproxy.Disable(); err != nil {
		writeJSON(w, http.StatusOK, a.tproxyPayloadWithErr(err))
		return
	}
	writeJSON(w, http.StatusOK, a.tproxyPayload())
}

func (a *API) handleTProxyRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"message": "restarting to apply tproxy_listen socket mode",
	})
	go func() {
		time.Sleep(400 * time.Millisecond)
		p, err := os.FindProcess(os.Getpid())
		if err == nil {
			_ = p.Signal(syscall.SIGTERM)
			return
		}
		os.Exit(0)
	}()
}

func (a *API) loadRuntimeSettings() config.RuntimeSettings {
	rs, err := config.LoadRuntimeSettings(config.RuntimeSettingsPath(a.dataDir))
	if err != nil {
		return config.RuntimeSettings{}
	}
	return rs
}

// withPreservedTProxy copies TPROXY + conntrack fields from disk so other settings saves do not wipe them.
func (a *API) withPreservedTProxy(rs config.RuntimeSettings) config.RuntimeSettings {
	cur := a.loadRuntimeSettings()
	rs.TProxyListen = cur.TProxyListen
	rs.TProxyIntercept = cur.TProxyIntercept
	rs.TProxyIface = cur.TProxyIface
	rs.TProxyMode = cur.TProxyMode
	rs.TProxyResolvers = cur.TProxyResolvers
	rs.TProxyMark = cur.TProxyMark
	rs.ConntrackManaged = cur.ConntrackManaged
	rs.ConntrackMax = cur.ConntrackMax
	rs.ConntrackHashsize = cur.ConntrackHashsize
	rs.ConntrackPersist = cur.ConntrackPersist
	return rs
}

func (a *API) interceptCfgFromRuntime(rs config.RuntimeSettings) tproxy.InterceptConfig {
	cfg := tproxy.InterceptConfig{
		Enabled:   rs.TProxyIntercept != nil && *rs.TProxyIntercept,
		Iface:     rs.TProxyIface,
		Mode:      rs.TProxyMode,
		Resolvers: append([]string(nil), rs.TProxyResolvers...),
	}
	if cfg.Mode == "" {
		cfg.Mode = "public"
	}
	if rs.TProxyMark != nil {
		cfg.Mark = *rs.TProxyMark
	}
	return cfg
}

func (a *API) applyTProxyIntercept(rs config.RuntimeSettings) error {
	cfg := a.interceptCfgFromRuntime(rs)
	if !cfg.Enabled {
		return tproxy.Disable()
	}
	return tproxy.Apply(cfg)
}

func (a *API) tproxyPayloadWithErr(err error) map[string]any {
	p := a.tproxyPayload()
	if err != nil {
		p["apply_error"] = err.Error()
	}
	return p
}

func (a *API) tproxyPayload() map[string]any {
	rs := a.loadRuntimeSettings()
	listenDesired := a.cfg != nil && a.cfg.Server.TProxy
	if rs.TProxyListen != nil {
		listenDesired = *rs.TProxyListen
	}
	listenActive := a.cfg != nil && a.cfg.Server.TProxy
	cfg := a.interceptCfgFromRuntime(rs)
	st := tproxy.GetStatus(cfg)
	ifs, _ := tproxy.ListIfaces()
	if cfg.Iface == "" {
		cfg.Iface = tproxy.PickDefaultIface()
	}
	return map[string]any{
		"supported":            tproxy.Supported(),
		"tproxy_listen":        listenDesired,
		"tproxy_listen_active": listenActive,
		"tproxy_listen_needs_restart": listenDesired != listenActive,
		"tproxy_intercept":     cfg.Enabled,
		"tproxy_iface":         cfg.Iface,
		"tproxy_mode":          cfg.Mode,
		"tproxy_resolvers":     cfg.Resolvers,
		"tproxy_mark":          cfg.Mark,
		"default_resolvers":    tproxy.DefaultPublicResolvers,
		"ifaces":               ifs,
		"status":               st,
		"note": "Intercept (nftables) applies live. Transparent socket (tproxy_listen) needs Restart service after Save.",
	}
}

// SyncTProxyOnStartup applies persisted intercept rules after boot.
func SyncTProxyOnStartup(dataDir string) error {
	rs, err := config.LoadRuntimeSettings(config.RuntimeSettingsPath(dataDir))
	if err != nil {
		return nil
	}
	if rs.TProxyIntercept == nil || !*rs.TProxyIntercept {
		return nil
	}
	cfg := tproxy.InterceptConfig{
		Enabled:   true,
		Iface:     rs.TProxyIface,
		Mode:      rs.TProxyMode,
		Resolvers: rs.TProxyResolvers,
	}
	if rs.TProxyMark != nil {
		cfg.Mark = *rs.TProxyMark
	}
	return tproxy.Apply(cfg)
}
