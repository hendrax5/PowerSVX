package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/server"
)

func (a *API) handleKominfoSync(w http.ResponseWriter, r *http.Request) {
	mgr := a.srv.Kominfo()
	if mgr == nil {
		http.Error(w, "kominfo sync unavailable", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, mgr.Snapshot())
	case http.MethodPut, http.MethodPatch:
		var body struct {
			Enabled *bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		if body.Enabled != nil {
			cur := a.srv.RuntimeFlags()
			cur.KominfoSync = *body.Enabled
			a.srv.ApplyRuntimeFlags(cur)
			a.saveRuntimeFromServer(cur)
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
	_ = config.SaveRuntimeSettings(config.RuntimeSettingsPath(a.dataDir), config.RuntimeSettings{
		GeoDNS: &cur.GeoDNS, RPZ: &cur.RPZ, RateLimit: &cur.RateLimit,
		RateLimitQPS: &rlLive.QPS, RateLimitBurst: &rlLive.Burst, RateLimitBlockDur: &rlLive.BlockDuration,
		RateLimitWhitelist: rlLive.Whitelist,
		ECS: &cur.ECS, SplitHorizon: &cur.SplitHorizon,
		ResolverMode: &mode, ForwardOnFail: &cur.ForwardOnFail, QueryLog: &cur.QueryLog,
		Forwarders: fwd, ForwardZones: fz, AllowQuery: allow, DenyQuery: deny,
		KominfoSyncEnabled: &en,
	})
}
