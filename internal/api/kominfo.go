package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/server"
)

func (a *API) handleAxfrSync(w http.ResponseWriter, r *http.Request) {
	mgr := a.srv.Kominfo()
	if mgr == nil {
		http.Error(w, "axfr sync unavailable", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, mgr.Snapshot())
	case http.MethodPut, http.MethodPatch:
		var body struct {
			Enabled *bool     `json:"enabled"`
			Targets *[]string `json:"targets"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		cur := a.srv.RuntimeFlags()
		changed := false
		if body.Targets != nil {
			if err := mgr.SetTargets(*body.Targets); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if a.cfg != nil {
				a.cfg.KominfoSync.Targets = mgr.Targets()
			}
			changed = true
		}
		if body.Enabled != nil {
			cur.KominfoSync = *body.Enabled
			a.srv.ApplyRuntimeFlags(cur)
			changed = true
		}
		if changed {
			a.saveRuntimeFromServer(a.srv.RuntimeFlags())
		}
		writeJSON(w, http.StatusOK, mgr.Snapshot())
	case http.MethodPost:
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			_ = mgr.SyncAll(ctx)
		}()
		writeJSON(w, http.StatusAccepted, mgr.Snapshot())
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *API) saveRuntimeFromServer(cur server.RuntimeFlags) {
	mode := cur.ResolverMode
	allow, deny := a.srv.QueryACL()
	fwd := cur.Forwarders
	if fwd == nil && a.cfg != nil {
		fwd = a.cfg.Resolver.Forwarders
	}
	fz := cur.ForwardZones
	if fz == nil && a.cfg != nil {
		fz = a.cfg.Resolver.ForwardZones
	}
	rlLive := a.srv.RateLimitConfig()
	en := cur.KominfoSync
	targets := []string(nil)
	if a.srv.Kominfo() != nil {
		targets = a.srv.Kominfo().Targets()
	}
	retDays := 0
	maxMB := 0
	if a.cfg != nil {
		retDays = a.cfg.Logging.QueryLogRetentionDays
		maxMB = a.cfg.Logging.QueryLogMaxSizeMB
	}
	_ = config.SaveRuntimeSettings(config.RuntimeSettingsPath(a.dataDir), config.RuntimeSettings{
		GeoDNS: &cur.GeoDNS, RPZ: &cur.RPZ, RateLimit: &cur.RateLimit,
		RateLimitQPS: &rlLive.QPS, RateLimitBurst: &rlLive.Burst, RateLimitBlockDur: &rlLive.BlockDuration,
		RateLimitWhitelist: rlLive.Whitelist,
		ECS: &cur.ECS, SplitHorizon: &cur.SplitHorizon,
		ResolverMode: &mode, ForwardOnFail: &cur.ForwardOnFail, QueryLog: &cur.QueryLog,
		QueryLogRetentionDays: &retDays, QueryLogMaxSizeMB: &maxMB,
		Forwarders: fwd, ForwardZones: fz, AllowQuery: allow, DenyQuery: deny,
		AxfrSyncEnabled: &en,
		AxfrSyncTargets: targets,
		KominfoSyncEnabled: &en, // legacy alias
	})
}
