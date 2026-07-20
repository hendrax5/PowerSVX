package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/cache"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/database"
	"github.com/powersvx/powersvx/internal/server"
)

const Version = "1.0.0-phase3"

type API struct {
	cfg   *config.Config
	srv   *server.Server
	db    *database.DB
	cache *cache.Tier
	auth  *authoritative.Store
	log   *slog.Logger
	http  *http.Server
	start time.Time
}

func New(cfg *config.Config, srv *server.Server, db *database.DB, tier *cache.Tier, auth *authoritative.Store, log *slog.Logger) *API {
	return &API{cfg: cfg, srv: srv, db: db, cache: tier, auth: auth, log: log, start: time.Now()}
}

func (a *API) Start() error {
	if !a.cfg.API.RESTEnabled {
		return nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health", a.handleHealth)
	mux.HandleFunc("/api/health", a.handleHealth)
	mux.HandleFunc("/api/v1/status", a.handleStatus)

	a.http = &http.Server{Addr: a.cfg.API.RESTBind, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	a.log.Info("REST API starting", "addr", a.cfg.API.RESTBind)
	go func() {
		if err := a.http.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			a.log.Error("api server error", "err", err)
		}
	}()
	return nil
}

func (a *API) Shutdown(ctx context.Context) error {
	if a.http == nil {
		return nil
	}
	return a.http.Shutdown(ctx)
}

func (a *API) handleHealth(w http.ResponseWriter, r *http.Request) {
	checks := map[string]any{}
	status := "healthy"
	checks["dns_udp"] = map[string]any{"status": "pass", "addr": a.srv.UDPAddr()}
	checks["dns_dot"] = statusOrDisabled(a.srv.DoTEnabled(), a.srv.DoTAddr())
	checks["dns_doh"] = statusOrDisabled(a.srv.DoHEnabled(), a.srv.DoHAddr())
	checks["dns_doq"] = statusOrDisabled(a.srv.DoQEnabled(), a.srv.DoQAddr())

	if a.cfg.Database.Enabled {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		start := time.Now()
		if a.db != nil && a.db.Ping(ctx) == nil {
			checks["database"] = map[string]any{"status": "pass", "latency_ms": time.Since(start).Milliseconds()}
		} else {
			checks["database"] = map[string]any{"status": "fail"}
			status = "degraded"
		}
	} else {
		checks["database"] = map[string]any{"status": "disabled"}
	}

	hits, misses, size := a.cache.L1.Stats()
	var ratio float64
	if hits+misses > 0 {
		ratio = float64(hits) / float64(hits+misses)
	}
	checks["cache"] = map[string]any{"status": "pass", "hit_ratio": ratio, "l1_size": size}
	checks["rpz"] = map[string]any{"status": "pass", "entries": a.srv.RPZCount()}

	writeJSON(w, http.StatusOK, map[string]any{
		"status": status, "checks": checks, "uptime_seconds": int(time.Since(a.start).Seconds()),
	})
}

func statusOrDisabled(on bool, addr string) map[string]any {
	if on {
		return map[string]any{"status": "pass", "addr": addr}
	}
	return map[string]any{"status": "disabled"}
}

func (a *API) handleStatus(w http.ResponseWriter, r *http.Request) {
	queries, uptime := a.srv.Stats()
	hits, misses, size := a.cache.L1.Stats()
	zones := 0
	if a.auth != nil {
		zones = a.auth.ZoneCount()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version": Version, "uptime_seconds": int(uptime.Seconds()),
		"mode": a.cfg.Resolver.Mode, "dnssec_mode": a.srv.DNSSECMode(),
		"dot_enabled": a.srv.DoTEnabled(), "doh_enabled": a.srv.DoHEnabled(), "doq_enabled": a.srv.DoQEnabled(),
		"dot_addr": a.srv.DoTAddr(), "doh_addr": a.srv.DoHAddr(), "doq_addr": a.srv.DoQAddr(),
		"queries_total": queries, "rate_limited": a.srv.Blocked(),
		"cache_hits": hits, "cache_misses": misses, "cache_l1_size": size,
		"rpz_entries": a.srv.RPZCount(), "zones": zones, "udp_addr": a.srv.UDPAddr(),
		"ratelimit_enabled": a.cfg.RateLimit.Enabled, "rpz_enabled": a.cfg.RPZ.Enabled,
		"ecs_enabled": a.cfg.Resolver.ECSEnabled,
		"geodns_enabled": a.cfg.GeoDNS.Enabled,
		"split_horizon_enabled": a.cfg.SplitHorizon.Enabled,
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
