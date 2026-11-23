package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/acme"
	"github.com/powersvx/powersvx/internal/apiauth"
	"github.com/powersvx/powersvx/internal/audit"
	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/database"
	"github.com/powersvx/powersvx/internal/dnsdistctl"
	"github.com/powersvx/powersvx/internal/dnssec"
	"github.com/powersvx/powersvx/internal/eventlog"
	"github.com/powersvx/powersvx/internal/monitor"
	"github.com/powersvx/powersvx/internal/rpz"
	"github.com/powersvx/powersvx/internal/server"
	"github.com/powersvx/powersvx/internal/unboundrpz"
)

type API struct {
	cfg      *config.Config
	srv      *server.Server
	db       *database.DB
	auth     *authoritative.Store
	events   *eventlog.Bus
	acmeMgr  *acme.Manager
	audit    *audit.Log
	users    *apiauth.UserStore
	sessions *apiauth.SessionStore
	tokens   *apiauth.TokenStore
	loginLim *loginLimiter
	log      *slog.Logger
	http     *http.Server
	start    time.Time
	webFS    fs.FS
	dataDir  string

	unboundRPZEntries atomic.Int64
	unboundSync       unboundSyncState

	rpzAutoMu   sync.Mutex
	rpzAutoStop chan struct{}
}

func New(cfg *config.Config, srv *server.Server, db *database.DB, auth *authoritative.Store, log *slog.Logger) *API {
	return &API{cfg: cfg, srv: srv, db: db, auth: auth, log: log, start: time.Now(), dataDir: "./data", loginLim: newLoginLimiter()}
}

func (a *API) SetWebFS(fsys fs.FS)                     { a.webFS = fsys }
func (a *API) SetEvents(bus *eventlog.Bus)             { a.events = bus }
func (a *API) SetACME(m *acme.Manager)                 { a.acmeMgr = m }
func (a *API) SetAudit(l *audit.Log)                   { a.audit = l }
func (a *API) SetUserStore(u *apiauth.UserStore)       { a.users = u }
func (a *API) SetSessionStore(s *apiauth.SessionStore) { a.sessions = s }
func (a *API) SetTokenStore(t *apiauth.TokenStore)     { a.tokens = t }
func (a *API) SetDataDir(dir string) {
	if dir != "" {
		a.dataDir = dir
	}
}

func (a *API) Start() error {
	if !a.cfg.API.RESTEnabled {
		return nil
	}
	a.http = &http.Server{Addr: a.cfg.API.RESTBind, Handler: withCORS(a.Handler()), ReadHeaderTimeout: 10 * time.Second}
	a.log.Info("REST API starting", "addr", a.cfg.API.RESTBind)
	go func() {
		if err := a.http.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			a.log.Error("api server error", "err", err)
		}
	}()
	return nil
}

// Handler returns the REST (+ optional SPA) mux without CORS wrapper.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health", a.handleHealth)
	mux.HandleFunc("/api/health", a.handleHealth)
	mux.HandleFunc("/api/v1/status", a.withAuth(a.handleStatus))
	mux.HandleFunc("/api/v1/dashboard", a.withAuth(a.handleDashboard))
	mux.HandleFunc("/api/v1/zones", a.withAuth(a.handleZones))
	mux.HandleFunc("/api/v1/zones/import", a.withAuth(a.handleZoneImport))
	mux.HandleFunc("/api/v1/zones/", a.withAuth(a.handleZoneSub))
	mux.HandleFunc("/api/v1/settings", a.withAuth(a.handleSettings))
	mux.HandleFunc("/api/v1/cache/stats", a.withAuth(a.handleCacheStats))
	mux.HandleFunc("/api/v1/cache/inspect", a.withAuth(a.handleCacheInspect))
	mux.HandleFunc("/api/v1/cache/flush", a.withAuth(a.handleCacheFlush))
	mux.HandleFunc("/api/v1/security/blocks", a.withAuth(a.handleSecurityBlocks))
	mux.HandleFunc("/api/v1/security/ban", a.withAuth(a.handleSecurityBan))
	mux.HandleFunc("/api/v1/security/dynblocks/clear", a.withAuth(a.handleSecurityClearDynBlocks))
	mux.HandleFunc("/api/v1/queries/live", a.withAuth(a.handleLiveQueries))
	mux.HandleFunc("/api/v1/queries/stream", a.withAuth(a.handleQueryStream))
	mux.HandleFunc("/api/v1/tproxy", a.withAuth(a.handleTProxy))
	mux.HandleFunc("/api/v1/tproxy/apply", a.withAuth(a.handleTProxyApply))
	mux.HandleFunc("/api/v1/tproxy/disable", a.withAuth(a.handleTProxyDisable))
	mux.HandleFunc("/api/v1/tproxy/restart", a.withAuth(a.handleTProxyRestart))
	mux.HandleFunc("/api/v1/conntrack", a.withAuth(a.handleConntrack))
	mux.HandleFunc("/api/v1/conntrack/apply", a.withAuth(a.handleConntrackApply))
	mux.HandleFunc("/api/v1/host/network", a.withAuth(a.handleHostNetwork))
	mux.HandleFunc("/api/v1/host/network/apply", a.withAuth(a.handleHostNetworkApply))
	mux.HandleFunc("/api/v1/host/network/remove-ip", a.withAuth(a.handleHostNetworkRemoveIP))
	mux.HandleFunc("/api/v1/secondary", a.withAuth(a.handleSecondary))
	mux.HandleFunc("/api/v1/secondary/", a.withAuth(a.handleSecondarySub))
	mux.HandleFunc("/api/v1/kominfo-sync", a.withAuth(a.handleAxfrSync)) // legacy alias
	mux.HandleFunc("/api/v1/axfr-sync", a.withAuth(a.handleAxfrSync))
	mux.HandleFunc("/api/v1/rpz", a.withAuth(a.handleRPZ))
	mux.HandleFunc("/api/v1/blocklist/seed", a.withAuth(a.handleBlocklistSeed))
	mux.HandleFunc("/api/v1/domains/", a.withAuth(a.handleDomains))
	mux.HandleFunc("/api/v1/tools/lookup", a.withAuth(a.handleLookup))
	mux.HandleFunc("/api/v1/tools/trace", a.withAuth(a.handleTrace))
	mux.HandleFunc("/api/v1/events", a.withAuth(a.handleEvents))
	mux.HandleFunc("/api/v1/events/stream", a.withAuth(a.handleEventStream))
	mux.HandleFunc("/api/v1/analytics", a.withAuth(a.handleAnalytics))
	mux.HandleFunc("/api/v1/anomaly", a.withAuth(a.handleAnomaly))
	mux.HandleFunc("/api/v1/query-logs", a.withAuth(a.handleQueryLogs))
	mux.HandleFunc("/api/v1/audit", a.withAuth(a.handleAudit))
	mux.HandleFunc("/api/v1/acme", a.withAuth(a.handleACME))
	mux.HandleFunc("/api/v1/backup", a.withAuth(a.handleBackup))
	mux.HandleFunc("/api/v1/terminal/ws", a.handleTerminalWS)
	mux.HandleFunc("/api/v1/auth/", a.handleAuth)
	if a.webFS != nil {
		mux.Handle("/", a.spaHandler())
	}
	return mux
}

func (a *API) Shutdown(ctx context.Context) error {
	if a.http == nil {
		return nil
	}
	return a.http.Shutdown(ctx)
}

func (a *API) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, role := "anonymous", ""
		authType := strings.ToLower(strings.TrimSpace(a.cfg.API.AuthType))
		if authType == "token" || authType == "local" {
			p, ok := a.resolvePrincipal(r)
			if !ok {
				if a.audit != nil {
					a.audit.Record(audit.Event{Actor: "unknown", Action: "auth_fail", Path: r.URL.Path, Status: http.StatusUnauthorized})
				}
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			actor, role = p.Name, p.Role
			if !apiauth.AllowPath(role, r.Method, r.URL.Path) {
				if a.audit != nil {
					a.audit.Record(audit.Event{Actor: actor, Role: role, Action: "forbidden", Path: r.URL.Path, Status: http.StatusForbidden})
				}
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			r = r.WithContext(apiauth.WithPrincipal(r.Context(), p))
		}
		if a.audit != nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
			a.audit.Record(audit.Event{Actor: actor, Role: role, Action: r.Method, Path: r.URL.Path, Status: 0})
		}
		next(w, r)
	}
}

func (a *API) resolvePrincipal(r *http.Request) (apiauth.Principal, bool) {
	authType := strings.ToLower(strings.TrimSpace(a.cfg.API.AuthType))
	got := bearerToken(r.Header.Get("Authorization"))
	if got == "" {
		got = r.URL.Query().Get("token")
	}
	if got != "" {
		if a.tokens != nil {
			if p, ok := a.tokens.Resolve(got); ok {
				return p, true
			}
		}
		if authType == "token" && a.cfg.API.APIToken == "" && len(a.cfg.API.Tokens) == 0 {
			return apiauth.Principal{}, false
		}
		return apiauth.ResolveToken(a.cfg.API, got)
	}
	if authType == "local" && a.sessions != nil {
		id := apiauth.ReadSessionCookie(r)
		return a.sessions.Get(id)
	}
	return apiauth.Principal{}, false
}

func bearerToken(h string) string {
	const p = "Bearer "
	if len(h) > len(p) && strings.EqualFold(h[:len(p)], p) {
		return strings.TrimSpace(h[len(p):])
	}
	return ""
}

func tokenEqual(got, want string) bool {
	if len(got) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func isAllowedOrigin(origin, host string) bool {
	if origin == "" || host == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	return strings.EqualFold(u.Host, host)
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Add("Vary", "Origin")
			if isAllowedOrigin(origin, r.Host) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
		}
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) spaHandler() http.Handler {
	fileServer := http.FileServer(http.FS(a.webFS))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p == "" || p == "." {
			p = "index.html"
		}
		// Hashed Vite assets can be cached; HTML must revalidate so deploys show up.
		if p == "index.html" || strings.HasSuffix(p, ".html") {
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		} else if strings.HasPrefix(p, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		if _, err := fs.Stat(a.webFS, p); err != nil {
			// Do NOT serve index.html for static assets or files with extensions (e.g. .js, .css, .map)
			// Returning index.html (text/html) for missing JS files causes browser "SyntaxError: Unexpected token '<'"
			if strings.HasPrefix(p, "assets/") || path.Ext(p) != "" {
				http.NotFound(w, r)
				return
			}
			r.URL.Path = "/"
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			fileServer.ServeHTTP(w, r)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}

func (a *API) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.healthPayload(r.Context()))
}

func (a *API) healthPayload(ctx context.Context) map[string]any {
	checks := map[string]any{}
	status := "healthy"
	// A Dataplane is expected on a host deployment only; in development the process
	// is a Control Plane with nothing to probe, and that is not a fault.
	if os.Getenv("POWERSVX_HOST_DEPLOYMENT") == "1" {
		checks["dns_dataplane"] = map[string]any{"status": "pass", "engine": "dnsdist-cdb", "public_dns": ":53", "backend": "127.0.0.1:5353"}
		udpOK := map[string]any{"status": "pass", "addr": "0.0.0.0:53", "engine": "dnsdist"}
		if c, err := net.DialTimeout("udp", "127.0.0.1:53", 500*time.Millisecond); err != nil {
			udpOK["status"] = "fail"
			udpOK["err"] = err.Error()
			status = "degraded"
		} else {
			_ = c.Close()
		}
		checks["dns_udp"] = udpOK
		if st, err := unboundrpz.Stats(); err == nil {
			checks["unbound"] = map[string]any{"status": "pass", "stats": st, "addr": "127.0.0.1:5353"}
		} else {
			checks["unbound"] = map[string]any{"status": "degraded", "err": err.Error(), "addr": "127.0.0.1:5353"}
			if status == "healthy" {
				status = "degraded"
			}
		}
		if rt := a.unboundSync.health(); rt != nil {
			checks["unbound_runtime"] = rt
			if rt["status"] != "pass" && status == "healthy" {
				status = "degraded"
			}
		}
	} else {
		checks["dns_dataplane"] = map[string]any{"status": "disabled", "hint": "no Dataplane expected outside a host deployment"}
		checks["dns_udp"] = map[string]any{"status": "pass", "addr": a.srv.UDPAddr()}
		// Probe Unbound if configured as backend or in forwarders
		isUnboundFwd := false
		for _, f := range a.srv.RuntimeFlags().Forwarders {
			if strings.Contains(f, "5353") {
				isUnboundFwd = true
				break
			}
		}
		if isUnboundFwd {
			if st, err := unboundrpz.Stats(); err == nil {
				checks["unbound"] = map[string]any{"status": "pass", "stats": st, "addr": "127.0.0.1:5353"}
			} else {
				c, dialErr := net.DialTimeout("udp", "127.0.0.1:5353", 400*time.Millisecond)
				if dialErr != nil {
					checks["unbound"] = map[string]any{
						"status": "fail",
						"err":    "read udp 127.0.0.1:5353: connection refused (Unbound service is not running)",
						"addr":   "127.0.0.1:5353",
					}
				} else {
					_ = c.Close()
					checks["unbound"] = map[string]any{"status": "pass", "addr": "127.0.0.1:5353"}
				}
				if status == "healthy" {
					status = "degraded"
				}
			}
		} else {
			checks["unbound"] = map[string]any{"status": "disabled", "hint": "Resolver mode: " + a.srv.RuntimeFlags().ResolverMode}
		}
	}
	checks["dns_dot"] = statusOrDisabled(a.srv.DoTEnabled(), a.srv.DoTAddr())
	checks["dns_doh"] = statusOrDisabled(a.srv.DoHEnabled(), a.srv.DoHAddr())
	checks["dns_doh3"] = statusOrDisabled(a.srv.DoH3Enabled(), a.srv.DoHAddr())
	checks["dns_doq"] = statusOrDisabled(a.srv.DoQEnabled(), a.srv.DoQAddr())

	if a.cfg.Database.Enabled {
		cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		start := time.Now()
		if a.db != nil && a.db.Ping(cctx) == nil {
			checks["database"] = map[string]any{"status": "pass", "latency_ms": time.Since(start).Milliseconds()}
		} else {
			checks["database"] = map[string]any{"status": "fail"}
			status = "degraded"
		}
	} else {
		checks["database"] = map[string]any{"status": "disabled", "hint": "not configured; query history needs the Observability Profile"}
	}

	// The Go process keeps no resolver cache; the Dataplane and Unbound report theirs.
	checks["cache"] = map[string]any{"status": "disabled", "hint": "resolver cache lives in dnsdist and Unbound"}
	rpzDetail := map[string]any{"status": "pass", "entries": a.srv.RPZCount(), "policies": len(a.cfg.RPZ.Policies)}
	if config.DNSDistDataplane() {
		a.refreshUnboundEntryCount()
		rpzDetail["entries"] = a.unboundRPZEntryCount()
		rpzDetail["engine"] = "dnsdist-cdb"
	}
	if a.cfg.RPZ.Enabled {
		if len(a.cfg.RPZ.Policies) == 0 {
			rpzDetail["status"] = "degraded"
			rpzDetail["reason"] = "enabled but no policies configured"
			if status == "healthy" {
				status = "degraded"
			}
		} else if !config.DNSDistDataplane() && a.srv.RPZCount() == 0 {
			loading := false
			if eng := a.srv.RPZ(); eng != nil {
				loading = eng.LoadStatus().Loading
			}
			if loading {
				rpzDetail["status"] = "pass"
				rpzDetail["reason"] = "loading"
			} else {
				rpzDetail["status"] = "degraded"
				rpzDetail["reason"] = "enabled with policies but 0 entries"
				if status == "healthy" {
					status = "degraded"
				}
			}
		} else if config.DNSDistDataplane() && a.unboundRPZEntryCount() == 0 {
			rpzDetail["status"] = "pass"
			rpzDetail["reason"] = "waiting for filter sync"
		} else if config.DNSDistDataplane() && a.unboundRPZEntryCount() > 0 {
			// Last sync may have failed while still serving a good CDB.
			if feedSyncFailed(a.axfrFeedSnapshot()) {
				rpzDetail["status"] = "pass"
				rpzDetail["reason"] = "filter sync failed; serving last CDB"
				rpzDetail["filter_sync"] = "failed"
			} else {
				rpzDetail["filter_sync"] = "ok"
			}
		}
	} else {
		rpzDetail["status"] = "disabled"
	}
	checks["rpz"] = rpzDetail

	// Forwarder / resource health from monitor.
	// Important: a few early OKs must NOT hide a high fail ratio (that caused a silent outage).
	fwdStatus := "unknown"
	fwdDetail := map[string]any{"status": "unknown"}
	if mon := a.srv.Monitor(); mon != nil {
		allow, _ := a.srv.QueryACL()
		snap := mon.Snapshot(allow, nil)
		res := snap.Resources
		resStatus := "pass"
		gomemMB := config.GoMemLimitMB()
		rssDegradeMB := config.RSSDegradeThresholdMB()
		resDetail := map[string]any{
			"status":                resStatus,
			"goroutines":            res.Goroutines,
			"rss_mb":                res.RSSMB,
			"cpu_percent":           res.CPUPercent,
			"gomemlimit_mb":         gomemMB,
			"rss_degrade_mb":        rssDegradeMB,
			"host_mem_total_mb":     res.HostMemTotalMB,
			"host_mem_available_mb": res.HostMemAvailableMB,
			"host_mem_used_pct":     res.HostMemUsedPct,
			"disk_total_gb":         res.DiskTotalGB,
			"disk_used_gb":          res.DiskUsedGB,
			"disk_used_pct":         res.DiskUsedPct,
			"load1":                 res.Load1,
		}
		if res.DiskUsedPct >= 95 {
			resStatus = "fail"
			status = "degraded"
			resDetail["status"] = resStatus
			resDetail["reason"] = "disk nearly full (>=95%)"
		} else if res.HostMemAvailableMB > 0 && res.HostMemAvailableMB < 512 {
			resStatus = "degraded"
			if status == "healthy" {
				status = "degraded"
			}
			resDetail["status"] = resStatus
			resDetail["reason"] = "low MemAvailable (<512 MiB)"
		} else if res.Goroutines >= 10000 {
			resStatus = "fail"
			status = "degraded"
			resDetail["status"] = resStatus
			resDetail["reason"] = "goroutine storm (>=10000)"
		} else if res.Goroutines >= 2000 || res.RSSMB >= rssDegradeMB {
			resStatus = "degraded"
			if status == "healthy" {
				status = "degraded"
			}
			resDetail["status"] = resStatus
			if res.Goroutines >= 2000 {
				resDetail["reason"] = "elevated goroutines"
			} else {
				resDetail["reason"] = "high RSS"
			}
		}
		checks["resources"] = resDetail

		var errTotal uint64
		for _, e := range snap.Errors {
			if e.Key == "SERVFAIL" || e.Key == "REFUSED" || e.Key == "FORMERR" {
				errTotal += e.Count
			}
		}
		if snap.QueriesTotal >= 200 && float64(errTotal)/float64(snap.QueriesTotal) >= 0.5 {
			checks["resolver"] = map[string]any{
				"status": "fail", "error_ratio": float64(errTotal) / float64(snap.QueriesTotal),
				"errors": errTotal, "queries": snap.QueriesTotal,
				"reason": "error RCODE ratio >= 50%",
			}
			status = "degraded"
		} else {
			checks["resolver"] = map[string]any{"status": "pass"}
		}

		if len(snap.Forwarders) == 0 {
			fwdDetail = map[string]any{"status": "idle", "note": "no forwarder attempts yet"}
			fwdStatus = "idle"
		} else {
			failing := 0
			degraded := 0
			for _, f := range snap.Forwarders {
				total := f.OK + f.Fail
				ratio := 0.0
				if total > 0 {
					ratio = float64(f.Fail) / float64(total)
				}
				switch {
				case total >= 50 && ratio >= 0.5:
					failing++
				case total >= 20 && ratio >= 0.2:
					degraded++
				case f.LastStatus != "ok" && f.Fail > 0 && f.OK == 0:
					failing++
				}
			}
			if failing == len(snap.Forwarders) {
				fwdStatus = "fail"
				status = "degraded"
			} else if failing > 0 || degraded > 0 {
				fwdStatus = "degraded"
				if status == "healthy" {
					status = "degraded"
				}
			} else {
				fwdStatus = "pass"
			}
			fwdDetail = map[string]any{"status": fwdStatus, "forwarders": snap.Forwarders}
		}
	}
	checks["forwarders"] = fwdDetail
	_ = fwdStatus

	authInfo := map[string]any{
		"auth_type": a.cfg.API.AuthType,
	}
	if a.users != nil {
		authInfo["users"] = a.users.Count()
		authInfo["admin_password_from_env"] = a.users.EnvAdminPasswordSet()
	}

	out := map[string]any{
		"status":         status,
		"checks":         checks,
		"auth":           authInfo,
		"uptime_seconds": int(time.Since(a.start).Seconds()),
		"started_at":     a.start.UTC().Format(time.RFC3339),
	}
	for k, v := range versionFields() {
		out[k] = v
	}
	return out
}

func statusOrDisabled(on bool, addr string) map[string]any {
	if on {
		return map[string]any{"status": "pass", "addr": addr}
	}
	return map[string]any{"status": "disabled"}
}

func (a *API) statusPayload() map[string]any {
	queries, uptime := a.srv.Stats()
	var hits, misses, size uint64 // the Go process keeps no resolver cache
	zones := 0
	if a.auth != nil {
		zones = a.auth.ZoneCount()
	}
	flags := a.srv.RuntimeFlags()
	out := map[string]any{
		"uptime_seconds": int(uptime.Seconds()),
		"mode":           a.cfg.Resolver.Mode, "dnssec_mode": a.srv.DNSSECMode(),
		"dot_enabled": a.srv.DoTEnabled(), "doh_enabled": a.srv.DoHEnabled(), "doh3_enabled": a.srv.DoH3Enabled(), "doq_enabled": a.srv.DoQEnabled(),
		"dot_addr": a.srv.DoTAddr(), "doh_addr": a.srv.DoHAddr(), "doq_addr": a.srv.DoQAddr(),
		"queries_total": queries, "rate_limited": a.srv.Blocked(),
		"cache_hits": hits, "cache_misses": misses, "cache_l1_size": size,
		"rpz_entries": a.srv.RPZCount(), "zones": zones, "udp_addr": a.srv.UDPAddr(),
		"ratelimit_enabled": flags.RateLimit, "rpz_enabled": flags.RPZ,
		"ecs_enabled":           flags.ECS,
		"geodns_enabled":        flags.GeoDNS,
		"split_horizon_enabled": flags.SplitHorizon,
		"dns_dataplane":         config.DNSDataplane(),
	}
	if config.DNSDistDataplane() {
		out["mode"] = "dnsdist"
		out["udp_addr"] = "0.0.0.0:53 (dnsdist)"
		out["rpz_entries"] = a.unboundRPZEntryCount()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		st, err := dnsdistctl.DefaultClient().Stats(ctx)
		cancel()
		if err == nil && st != nil {
			out["queries_total"] = uint64(st["queries"])
			out["cache_hits"] = uint64(st["cache-hits"])
			out["cache_misses"] = uint64(st["cache-misses"])
			out["dnsdist_self_answered"] = uint64(st["self-answered"])
			out["dnsdist_latency_avg100"] = st["latency-avg100"]
		}
	}
	for k, v := range versionFields() {
		out[k] = v
	}
	return out
}

func (a *API) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.statusPayload())
}

func (a *API) handleDashboard(w http.ResponseWriter, r *http.Request) {
	payload := map[string]any{
		"status": a.statusPayload(),
		"zones":  a.auth.ListZones(),
	}
	if col := a.srv.Analytics(); col != nil {
		names, rcodes := col.Snapshot(15)
		if names == nil {
			payload["top_names"] = []any{}
		} else {
			payload["top_names"] = names
		}
		if rcodes == nil {
			payload["rcodes"] = []any{}
		} else {
			payload["rcodes"] = rcodes
		}
	} else {
		payload["top_names"] = []any{}
		payload["rcodes"] = []any{}
	}
	if det := a.srv.Anomaly(); det != nil {
		payload["anomaly"] = det.Snapshot()
	} else {
		payload["anomaly"] = map[string]any{"alerts": []any{}, "warm": 0}
	}

	allow, _ := a.srv.QueryACL()
	active := a.srv.RateLimitBlocked(15)
	if mon := a.srv.Monitor(); mon != nil {
		payload["monitor"] = mon.Snapshot(allow, active)
	} else {
		payload["monitor"] = monitor.New().Snapshot(allow, active)
	}
	payload["health"] = a.healthPayload(r.Context())
	payload["dns_dataplane"] = config.DNSDataplane()
	writeJSON(w, http.StatusOK, payload)
}

func (a *API) handleZones(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"zones": a.auth.ListZones()})
	case http.MethodPost:
		var body struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
			http.Error(w, "name required", http.StatusBadRequest)
			return
		}
		a.auth.CreateZone(body.Name)
		if a.persistFailed(w) {
			return
		}
		a.SyncAllDataplanes()
		writeJSON(w, http.StatusCreated, map[string]any{"name": config.NormalizeName(body.Name)})
		a.srv.NotifySecondaries(body.Name)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *API) handleZoneSub(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/zones/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	zone := parts[0]

	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			recs, ok := a.auth.GetRecords(zone)
			if !ok {
				http.Error(w, "zone not found", http.StatusNotFound)
				return
			}
			payload := map[string]any{"name": config.NormalizeName(zone), "records": recordsDTO(recs)}
			if meta, ok := a.auth.GetZoneMeta(zone); ok {
				payload["meta"] = zoneMetaPayload(zone, meta)
			}
			writeJSON(w, http.StatusOK, payload)
		case http.MethodPut, http.MethodPatch:
			var body struct {
				DNSSECEnabled *bool  `json:"dnssec_enabled"`
				SOASerial     *int64 `json:"soa_serial"`
				SOARefresh    *int   `json:"soa_refresh"`
				SOARetry      *int   `json:"soa_retry"`
				SOAExpire     *int   `json:"soa_expire"`
				SOAMinimum    *int   `json:"soa_minimum"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "invalid json", http.StatusBadRequest)
				return
			}
			if msg := validateMetaPatch(body.SOASerial, body.SOARefresh, body.SOARetry, body.SOAExpire, body.SOAMinimum); msg != "" {
				http.Error(w, msg, http.StatusBadRequest)
				return
			}
			meta, ok := a.auth.UpdateZoneMeta(zone, authoritative.ZoneMetaPatch{
				DNSSECEnabled: body.DNSSECEnabled, SOASerial: body.SOASerial, SOARefresh: body.SOARefresh,
				SOARetry: body.SOARetry, SOAExpire: body.SOAExpire, SOAMinimum: body.SOAMinimum,
			})
			if !ok {
				http.Error(w, "zone not found", http.StatusNotFound)
				return
			}
			if a.persistFailed(w) {
				return
			}
			if body.DNSSECEnabled != nil && *body.DNSSECEnabled {
				if sig := a.srv.Signer(); sig != nil {
					if err := sig.Ensure(config.NormalizeName(zone)); err != nil {
						http.Error(w, "dnssec keys: "+err.Error(), http.StatusInternalServerError)
						return
					}
				}
			}
			out := zoneMetaPayload(zone, meta)
			if sig := a.srv.Signer(); sig != nil && sig.Enabled(zone) {
				out["signing"] = true
				if ds, err := sig.DS(zone); err == nil && ds != nil {
					out["ds"] = ds.String()
				}
			}
			writeJSON(w, http.StatusOK, out)
			return
		case http.MethodDelete:
			if !a.auth.DeleteZone(zone) {
				http.Error(w, "zone not found", http.StatusNotFound)
				return
			}
			if a.persistFailed(w) {
				return
			}
			a.SyncAllDataplanes()
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	if parts[1] == "export" {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		txt, ok := a.auth.ExportBINDZone(zone)
		if !ok {
			http.Error(w, "zone not found", http.StatusNotFound)
			return
		}
		if r.URL.Query().Get("raw") == "1" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Content-Disposition", "attachment; filename=\""+strings.TrimSuffix(config.NormalizeName(zone), ".")+".zone\"")
			_, _ = w.Write([]byte(txt))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"zone": config.NormalizeName(zone), "content": txt})
		return
	}

	if parts[1] == "dnssec" {
		normZone := config.NormalizeName(zone)
		switch r.Method {
		case http.MethodGet:
			sig := a.srv.Signer()
			if sig == nil || !sig.Enabled(normZone) {
				writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
				return
			}
			keys := []string{}
			for _, rr := range sig.DNSKEYs(normZone) {
				keys = append(keys, rr.String())
			}
			pol, _ := sig.Policy(normZone)
			out := map[string]any{
				"enabled":   true,
				"keys":      keys,
				"algorithm": dns.AlgorithmToString[pol.Algorithm],
				"nsec3":     pol.NSEC3,
			}
			if ds, err := sig.DS(normZone); err == nil && ds != nil {
				out["ds"] = ds.String()
			}
			writeJSON(w, http.StatusOK, out)
		case http.MethodPost:
			sig := a.srv.Signer()
			if sig == nil {
				http.Error(w, "signer unavailable", http.StatusServiceUnavailable)
				return
			}
			var body struct {
				Algorithm string `json:"algorithm"`
				NSEC3     bool   `json:"nsec3"`
				Action    string `json:"action"` // enable | rollover
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			beforePol, _ := sig.Policy(normZone)
			if strings.EqualFold(body.Action, "rollover") {
				if err := sig.RolloverZSK(normZone); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			} else {
				opts := dnssec.SignOptions{
					Algorithm: dnssec.ParseAlgorithm(body.Algorithm),
					NSEC3:     body.NSEC3,
				}
				if err := sig.EnsureWithOptions(normZone, opts); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			}
			// NSEC3PARAM follows the policy; a secondary learns of a change through the serial.
			if afterPol, _ := sig.Policy(normZone); afterPol.NSEC3 != beforePol.NSEC3 || afterPol.NSEC3 && afterPol.Salt != beforePol.Salt {
				_, _ = a.auth.BumpSOASerial(normZone)
				a.srv.NotifySecondaries(normZone)
			}
			on := true
			a.auth.UpdateZoneMeta(zone, authoritative.ZoneMetaPatch{DNSSECEnabled: &on})
			pol, _ := sig.Policy(normZone)
			ds, _ := sig.DS(normZone)
			out := map[string]any{
				"enabled":   true,
				"algorithm": dns.AlgorithmToString[pol.Algorithm],
				"nsec3":     pol.NSEC3,
			}
			if ds != nil {
				out["ds"] = ds.String()
			}
			writeJSON(w, http.StatusOK, out)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}

	if parts[1] != "records" {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		recs, ok := a.auth.GetRecords(zone)
		if !ok {
			http.Error(w, "zone not found", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"records": recordsDTO(recs)})
	case http.MethodPost:
		var body recordDTO
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		rec := body.toRecord()
		if err := authoritative.ValidateRecord(rec); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		a.auth.AddRecords(zone, []authoritative.Record{rec})
		if a.persistFailed(w) {
			return
		}
		if config.DNSDistDataplane() {
			go func(qname string) {
				cctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				_ = dnsdistctl.DefaultClient().ExpungeByName(cctx, qname)
			}(rec.Name)
		}
		a.srv.NotifySecondaries(zone)
		writeJSON(w, http.StatusCreated, body)
	case http.MethodPut:
		var body struct {
			OldName string `json:"old_name"`
			OldType string `json:"old_type"`
			recordDTO
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		if body.OldName == "" {
			body.OldName = body.Name
		}
		if body.OldType == "" {
			body.OldType = body.Type
		}
		rec := body.toRecord()
		if err := authoritative.ValidateRecord(rec); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		qt := authoritative.TypeFromString(body.OldType)
		if !a.auth.UpdateRecord(zone, body.OldName, qt, rec) {
			http.Error(w, "record not found", http.StatusNotFound)
			return
		}
		if a.persistFailed(w) {
			return
		}
		if config.DNSDistDataplane() {
			go func(qname, oldName string) {
				cctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				ctl := dnsdistctl.DefaultClient()
				_ = ctl.ExpungeByName(cctx, qname)
				if oldName != "" && oldName != qname {
					_ = ctl.ExpungeByName(cctx, oldName)
				}
			}(rec.Name, body.OldName)
		}
		a.srv.NotifySecondaries(zone)
		writeJSON(w, http.StatusOK, body.recordDTO)
	case http.MethodDelete:
		name := r.URL.Query().Get("name")
		typ := r.URL.Query().Get("type")
		if name == "" {
			http.Error(w, "name required", http.StatusBadRequest)
			return
		}
		qt := authoritative.TypeFromString(typ)
		a.auth.DeleteRecord(zone, name, qt)
		if a.persistFailed(w) {
			return
		}
		if config.DNSDistDataplane() {
			go func(qname string) {
				cctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				_ = dnsdistctl.DefaultClient().ExpungeByName(cctx, qname)
			}(name)
		}
		a.srv.NotifySecondaries(zone)
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *API) handleZoneImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Zone    string `json:"zone"`
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	zone := strings.TrimSpace(body.Zone)
	if zone == "" || strings.TrimSpace(body.Content) == "" {
		http.Error(w, "zone and content required", http.StatusBadRequest)
		return
	}
	recs, err := authoritative.ImportBINDZone(zone, body.Content)
	if err != nil {
		http.Error(w, "zone parse failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	a.auth.CreateZone(zone)
	a.auth.AddRecords(zone, recs)
	if a.persistFailed(w) {
		return
	}
	a.SyncAllDataplanes()
	a.srv.NotifySecondaries(zone)
	writeJSON(w, http.StatusOK, map[string]any{
		"zone":             config.NormalizeName(zone),
		"imported_records": len(recs),
	})
}

type recordDTO struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     uint32 `json:"ttl"`
	Prio    uint16 `json:"prio"`
	View    string `json:"view"`
	GeoTag  string `json:"geo_tag"`
}

func (d recordDTO) toRecord() authoritative.Record {
	ttl := d.TTL
	if ttl == 0 {
		ttl = 3600
	}
	return authoritative.Record{
		Name: d.Name, Type: authoritative.TypeFromString(d.Type),
		Content: d.Content, TTL: ttl, Prio: d.Prio, View: d.View, GeoTag: d.GeoTag,
	}
}

func recordsDTO(recs []authoritative.Record) []recordDTO {
	out := make([]recordDTO, 0, len(recs))
	for _, r := range recs {
		out = append(out, recordDTO{
			Name: r.Name, Type: dns.TypeToString[r.Type], Content: r.Content,
			TTL: r.TTL, Prio: r.Prio, View: r.View, GeoTag: r.GeoTag,
		})
	}
	return out
}

func (a *API) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, a.settingsPayload())
	case http.MethodPut, http.MethodPatch:
		var body struct {
			GeoDNS                *bool                       `json:"geodns"`
			RPZ                   *bool                       `json:"rpz_enabled"`
			RateLimit             *bool                       `json:"rate_limit"`
			RateLimitQPS          *int                        `json:"rate_limit_qps"`
			RateLimitBurst        *int                        `json:"rate_limit_burst"`
			RateLimitBlockDur     *int                        `json:"rate_limit_block_duration"`
			RateLimitWhitelist    *[]string                   `json:"rate_limit_whitelist"`
			ClearRateLimitBlocks  *bool                       `json:"clear_rate_limit_blocks"`
			ECS                   *bool                       `json:"ecs_enabled"`
			SplitHorizon          *bool                       `json:"split_horizon"`
			ResolverMode          *string                     `json:"resolver_mode"`
			ForwardOnFail         *bool                       `json:"forward_on_fail"`
			QueryLog              *bool                       `json:"query_log_enabled"`
			QueryLogRetentionDays *int                        `json:"query_log_retention_days"`
			QueryLogMaxSizeMB     *int                        `json:"query_log_max_size_mb"`
			QueryLogSampleRate    *float64                    `json:"query_log_sample_rate"`
			Forwarders            *[]string                   `json:"forwarders"`
			ForwardZones          *[]config.ForwardZoneConfig `json:"forward_zones"`
			AllowQuery            *[]string                   `json:"allow_query"`
			DenyQuery             *[]string                   `json:"deny_query"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		cur := a.srv.RuntimeFlags()
		if body.GeoDNS != nil {
			cur.GeoDNS = *body.GeoDNS
		}
		if body.RPZ != nil {
			cur.RPZ = *body.RPZ
		}
		if body.RateLimit != nil {
			cur.RateLimit = *body.RateLimit
		}
		if body.ECS != nil {
			cur.ECS = *body.ECS
		}
		if body.SplitHorizon != nil {
			cur.SplitHorizon = *body.SplitHorizon
		}
		if body.ResolverMode != nil {
			mode := strings.ToLower(strings.TrimSpace(*body.ResolverMode))
			if mode != "forward" && mode != "recursive" {
				http.Error(w, "resolver_mode must be forward or recursive", http.StatusBadRequest)
				return
			}
			cur.ResolverMode = mode
		}
		if body.ForwardOnFail != nil {
			cur.ForwardOnFail = *body.ForwardOnFail
		}
		if body.QueryLog != nil {
			cur.QueryLog = *body.QueryLog
			// Go-edge guard only.
			if config.QueryLogForcedOff() {
				cur.QueryLog = false
			}
		}
		if body.QueryLogRetentionDays != nil {
			if *body.QueryLogRetentionDays < 0 || *body.QueryLogRetentionDays > 3650 {
				http.Error(w, "query_log_retention_days must be 0–3650", http.StatusBadRequest)
				return
			}
			if a.cfg != nil {
				a.cfg.Logging.QueryLogRetentionDays = *body.QueryLogRetentionDays
			}
		}
		if body.QueryLogMaxSizeMB != nil {
			if *body.QueryLogMaxSizeMB < 0 || *body.QueryLogMaxSizeMB > 102400 {
				http.Error(w, "query_log_max_size_mb must be 0–102400", http.StatusBadRequest)
				return
			}
			if a.cfg != nil {
				a.cfg.Logging.QueryLogMaxSizeMB = *body.QueryLogMaxSizeMB
			}
		}
		if body.QueryLogSampleRate != nil {
			if *body.QueryLogSampleRate < 0 || *body.QueryLogSampleRate > 1 {
				http.Error(w, "query_log_sample_rate must be 0–1", http.StatusBadRequest)
				return
			}
			if a.cfg != nil {
				a.cfg.Logging.QueryLogSampleRate = *body.QueryLogSampleRate
			}
		}
		if body.Forwarders != nil {
			fwd, err := config.NormalizeForwarders(*body.Forwarders)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if err := loopForwarderError(fwd, nil); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			cur.Forwarders = fwd
		}
		if body.ForwardZones != nil {
			fz, err := config.NormalizeForwardZones(*body.ForwardZones)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if err := loopForwarderError(nil, fz); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			cur.ForwardZones = fz
		}
		a.srv.ApplyRuntimeFlags(cur)
		if a.db != nil && a.cfg != nil {
			a.db.SetQueryLogLimits(a.cfg.Logging.QueryLogRetentionDays, a.cfg.Logging.QueryLogMaxSizeMB)
		}

		rl := a.srv.RateLimitConfig()
		qps, burst, block := rl.QPS, rl.Burst, rl.BlockDuration
		wl := append([]string(nil), rl.Whitelist...)
		rlChanged := false
		if body.RateLimitQPS != nil {
			if *body.RateLimitQPS < 1 {
				http.Error(w, "rate_limit_qps must be >= 1", http.StatusBadRequest)
				return
			}
			qps = *body.RateLimitQPS
			rlChanged = true
		}
		if body.RateLimitBurst != nil {
			if *body.RateLimitBurst < 1 {
				http.Error(w, "rate_limit_burst must be >= 1", http.StatusBadRequest)
				return
			}
			burst = *body.RateLimitBurst
			rlChanged = true
		}
		if body.RateLimitBlockDur != nil {
			if *body.RateLimitBlockDur < 1 {
				http.Error(w, "rate_limit_block_duration must be >= 1", http.StatusBadRequest)
				return
			}
			block = *body.RateLimitBlockDur
			rlChanged = true
		}
		if body.RateLimitWhitelist != nil {
			wl = normalizeCIDRList(*body.RateLimitWhitelist)
			rlChanged = true
		}
		if rlChanged {
			a.srv.ApplyRateLimitConfig(qps, burst, block, wl)
		}
		if body.ClearRateLimitBlocks != nil && *body.ClearRateLimitBlocks {
			a.srv.ClearRateLimitBlocks()
		}

		if body.AllowQuery != nil || body.DenyQuery != nil {
			allow, deny := a.srv.QueryACL()
			if body.AllowQuery != nil {
				allow = *body.AllowQuery
			}
			if body.DenyQuery != nil {
				deny = *body.DenyQuery
			}
			if err := a.srv.SetQueryACL(allow, deny); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			a.SyncDNSDistACL()
		}
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
		// Values nobody typed just now (TOML defaults, earlier settings) must not write a loop back.
		fwd, fz, _ = dropLoopForwarders(fwd, fz)
		rlLive := a.srv.RateLimitConfig()
		kominfoOn := cur.KominfoSync
		axfrTargets := []string(nil)
		if a.srv.Kominfo() != nil {
			axfrTargets = a.srv.Kominfo().Targets()
		}
		retDays := 0
		maxMB := 0
		sampleRate := 0.0
		if a.cfg != nil {
			retDays = a.cfg.Logging.QueryLogRetentionDays
			maxMB = a.cfg.Logging.QueryLogMaxSizeMB
			sampleRate = a.cfg.Logging.QueryLogSampleRate
		}
		_ = config.SaveRuntimeSettings(config.RuntimeSettingsPath(a.dataDir), a.withPreservedTProxy(config.RuntimeSettings{
			GeoDNS: &cur.GeoDNS, RPZ: &cur.RPZ, RateLimit: &cur.RateLimit,
			RateLimitQPS: &rlLive.QPS, RateLimitBurst: &rlLive.Burst, RateLimitBlockDur: &rlLive.BlockDuration,
			RateLimitWhitelist: rlLive.Whitelist,
			ECS:                &cur.ECS, SplitHorizon: &cur.SplitHorizon,
			ResolverMode: &mode, ForwardOnFail: &cur.ForwardOnFail, QueryLog: &cur.QueryLog,
			QueryLogRetentionDays: &retDays, QueryLogMaxSizeMB: &maxMB, QueryLogSampleRate: &sampleRate,
			Forwarders: fwd, ForwardZones: fz, AllowQuery: allow, DenyQuery: deny,
			AxfrSyncEnabled: &kominfoOn, AxfrSyncTargets: axfrTargets,
			KominfoSyncEnabled: &kominfoOn,
		}))
		a.SyncAllDataplanes()
		writeJSON(w, http.StatusOK, a.settingsPayload())
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func normalizeCIDRList(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, c := range in {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out
}

func (a *API) settingsPayload() map[string]any {
	f := a.srv.RuntimeFlags()
	allow, deny := a.srv.QueryACL()
	forwarders := f.Forwarders
	if forwarders == nil && a.cfg != nil {
		forwarders = a.cfg.Resolver.Forwarders
	}
	forwardZones := f.ForwardZones
	if forwardZones == nil && a.cfg != nil {
		forwardZones = a.cfg.Resolver.ForwardZones
	}
	rl := a.srv.RateLimitConfig()
	out := map[string]any{
		"resolver_mode":             f.ResolverMode,
		"forward_on_fail":           f.ForwardOnFail,
		"forwarders":                forwarders,
		"forward_zones":             forwardZones,
		"dnssec_mode":               a.cfg.Resolver.DNSSECMode,
		"ecs_enabled":               f.ECS,
		"rpz_enabled":               f.RPZ,
		"geodns":                    f.GeoDNS,
		"split_horizon":             f.SplitHorizon,
		"rate_limit":                f.RateLimit,
		"rate_limit_qps":            rl.QPS,
		"rate_limit_burst":          rl.Burst,
		"rate_limit_block_duration": rl.BlockDuration,
		"rate_limit_whitelist":      rl.Whitelist,
		"query_log_enabled":         f.QueryLog,
		"query_history_available":   a.db != nil && a.cfg.Database.Enabled,
		"query_history_note":        queryHistoryUnavailable,
		"query_log_mask_ip":         a.cfg.Logging.QueryLogMaskIP,
		"query_log_retention_days":  a.cfg.Logging.QueryLogRetentionDays,
		"query_log_max_size_mb":     a.cfg.Logging.QueryLogMaxSizeMB,
		"query_log_sample_rate":     a.cfg.Logging.QueryLogSampleRate,
		"allow_query":               allow,
		"deny_query":                deny,
		"transfer": map[string]any{
			"allow_axfr":   a.cfg.Transfer.AllowAXFR,
			"require_tsig": a.cfg.Transfer.RequireTSIG,
			"notify":       a.cfg.Transfer.Notify,
			"allow_from":   a.cfg.Transfer.AllowFrom,
		},
		"kominfo_sync_enabled": a.srv.RuntimeFlags().KominfoSync,
		"axfr_sync_enabled":    a.srv.RuntimeFlags().KominfoSync,
		"udp_addr":             a.srv.UDPAddr(),
		"geodns_db":            a.cfg.GeoDNS.DatabasePath,
		"auth_type":            a.cfg.API.AuthType,
		"auth_required":        apiauth.AuthRequired(a.cfg.API.AuthType),
		"auth_configured":      a.authConfigured(),
		"tls_min_version":      "1.3",
		"editable": []string{
			"geodns", "rpz_enabled", "rate_limit", "rate_limit_qps", "rate_limit_burst",
			"rate_limit_block_duration", "rate_limit_whitelist",
			"ecs_enabled", "split_horizon",
			"resolver_mode", "forward_on_fail", "forwarders", "forward_zones", "query_log_enabled",
			"query_log_retention_days", "query_log_max_size_mb", "query_log_sample_rate", "allow_query", "deny_query",
		},
		"note": "Edit toggles, rate limit, query ACL, forwarders, conditional forward zones, query log size/retention/sample rate, and resolver mode, then Save. Persisted to data/runtime-settings.json. Empty allow_query = allow all. AXFR ACL and IP masking are TOML-only. IXFR is answered as full AXFR.",
	}
	for k, v := range versionFields() {
		out[k] = v
	}
	return out
}

func (a *API) authConfigured() bool {
	switch strings.ToLower(strings.TrimSpace(a.cfg.API.AuthType)) {
	case "token":
		return a.cfg.API.APIToken != "" || len(a.cfg.API.Tokens) > 0
	case "local":
		return a.users != nil && a.users.Count() > 0
	default:
		return true
	}
}

func (a *API) handleRPZ(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, a.rpzPayload())
	case http.MethodPut:
		var body struct {
			Policies           []config.RPZPolicyTOML `json:"policies"`
			UpdateInterval     *int                   `json:"update_interval"`
			UpdateAt           *string                `json:"update_at"`
			AxfrUpdateInterval *int                   `json:"axfr_update_interval"`
			Sync               *bool                  `json:"sync"`
			AxfrOnly           *bool                  `json:"axfr_only"`
			Force              *bool                  `json:"force"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		pols, err := normalizeRPZPolicies(body.Policies)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if a.cfg.RPZ.Enabled && len(pols) == 0 {
			http.Error(w, "refusing empty RPZ policies while rpz is enabled; disable rpz first or keep at least one policy", http.StatusBadRequest)
			return
		}
		interval := a.cfg.RPZ.UpdateInterval
		if body.UpdateInterval != nil {
			if *body.UpdateInterval < 0 {
				http.Error(w, "update_interval must be >= 0", http.StatusBadRequest)
				return
			}
			interval = *body.UpdateInterval
		}
		updateAt := a.cfg.RPZ.UpdateAt
		if body.UpdateAt != nil {
			at := strings.TrimSpace(*body.UpdateAt)
			if at != "" {
				if _, _, _, err := config.ParseHHMM(at); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
			}
			updateAt = at
		}
		axfrInterval := a.cfg.RPZ.AxfrUpdateInterval
		if body.AxfrUpdateInterval != nil {
			if *body.AxfrUpdateInterval < 0 {
				http.Error(w, "axfr_update_interval must be >= 0", http.StatusBadRequest)
				return
			}
			axfrInterval = *body.AxfrUpdateInterval
		}
		// Always persist policy edits first. A long AXFR/CDB rebuild must not
		// block saving the new AXFR masters (UI used to fail with 409).
		axfrPtr := axfrInterval
		path := config.RPZPoliciesPath(a.dataDir)
		if err := config.SaveRPZPoliciesFile(path, config.RPZPoliciesFile{
			Policies: pols, UpdateInterval: interval, UpdateAt: updateAt, AxfrUpdateInterval: &axfrPtr,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		a.cfg.RPZ.Policies = pols
		a.cfg.RPZ.UpdateInterval = interval
		a.cfg.RPZ.UpdateAt = updateAt
		a.cfg.RPZ.AxfrUpdateInterval = axfrInterval
		a.StartRPZAutoUpdate()
		sync := body.Sync != nil && *body.Sync
		axfrOnly := body.AxfrOnly != nil && *body.AxfrOnly
		force := body.Force != nil && *body.Force
		var startErr error
		if axfrOnly {
			startErr = a.startRPZAXFRRefresh(sync)
		} else {
			if hostsFullReloadDaytime(time.Now()) && !force {
				http.Error(w, "full hosts RPZ reload blocked 06:00–22:00 local; set force=true or wait for update_at", http.StatusForbidden)
				return
			}
			startErr = a.startRPZReload(sync)
		}
		payload := a.rpzPayload()
		if startErr != nil {
			// Policies are saved; sync just could not start (already running).
			payload["sync_skipped"] = true
			payload["sync_skip_reason"] = startErr.Error()
			a.log.Info("rpz policies saved; sync deferred", "err", startErr)
		}
		writeJSON(w, http.StatusOK, payload)
	case http.MethodPost:
		if a.srv.RPZ() != nil && a.srv.RPZ().LoadStatus().Loading {
			http.Error(w, "rpz sync already in progress", http.StatusConflict)
			return
		}
		axfrOnly := r.URL.Query().Get("axfr_only") == "1" || r.URL.Query().Get("axfr_only") == "true"
		force := r.URL.Query().Get("force") == "1" || r.URL.Query().Get("force") == "true"
		var startErr error
		if axfrOnly {
			startErr = a.startRPZAXFRRefresh(false)
		} else {
			if hostsFullReloadDaytime(time.Now()) && !force {
				http.Error(w, "full hosts RPZ reload blocked 06:00–22:00 local; set force=1 or wait for update_at", http.StatusForbidden)
				return
			}
			startErr = a.startRPZReload(false)
		}
		if startErr != nil {
			http.Error(w, startErr.Error(), http.StatusConflict)
			return
		}
		writeJSON(w, http.StatusAccepted, a.rpzPayload())
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *API) rpzPayload() map[string]any {
	st := rpz.LoadStatus{}
	axfrFeeds := map[string]rpz.FeedState{}
	var axfrEvents []rpz.AxfrEvent
	if eng := a.srv.RPZ(); eng != nil {
		st = eng.LoadStatus()
		axfrFeeds, axfrEvents = eng.AxfrStatus()
	}
	pols := a.cfg.RPZ.Policies
	if pols == nil {
		pols = []config.RPZPolicyTOML{}
	}
	entries := a.srv.RPZCount()
	if config.DNSDistDataplane() {
		a.refreshUnboundEntryCount()
		entries = a.unboundRPZEntryCount()
	}
	note := "PUT policies + update_interval + update_at (HH:MM local) + axfr_update_interval. Default feed is trustpositifkominfo AXFR (enabled); set enabled=false to disable without deleting. First boot may bootstrap CDB from GitHub seed (POWERSVX_FILTER_SEED_URL); later refreshes use IXFR. Filter sync failure keeps last-good CDB."
	return map[string]any{
		"enabled":              a.srv.RuntimeFlags().RPZ,
		"entries":              entries,
		"dataplane":            config.DNSDataplane(),
		"policies":             pols,
		"update_interval":      a.cfg.RPZ.UpdateInterval,
		"update_at":            a.cfg.RPZ.UpdateAt,
		"axfr_update_interval": a.cfg.RPZ.AxfrUpdateInterval,
		"loading":              st.Loading,
		"error":                st.Error,
		"last_loaded":          st.LastLoaded,
		"from_disk":            st.FromDisk,
		"axfr_feeds":           axfrFeeds,
		"axfr_events":          axfrEvents,
		"tsig_keys":            a.secondaryTSIGKeyNames(),
		"filter_seed_url":      config.FilterSeedURL(),
		"note":                 note,
	}
}

func (a *API) axfrFeedSnapshot() map[string]rpz.FeedState {
	if eng := a.srv.RPZ(); eng != nil {
		feeds, _ := eng.AxfrStatus()
		return feeds
	}
	return map[string]rpz.FeedState{}
}

func feedSyncFailed(feeds map[string]rpz.FeedState) bool {
	for _, st := range feeds {
		if st.LastMode == "failed" || (st.OK == false && st.LastError != "") {
			return true
		}
	}
	return false
}

func normalizeRPZPolicies(in []config.RPZPolicyTOML) ([]config.RPZPolicyTOML, error) {
	if in == nil {
		in = []config.RPZPolicyTOML{}
	}
	seen := map[string]bool{}
	out := make([]config.RPZPolicyTOML, 0, len(in))
	for _, p := range in {
		p.Name = strings.TrimSpace(p.Name)
		p.Source = strings.TrimSpace(p.Source)
		p.Format = strings.TrimSpace(strings.ToLower(p.Format))
		p.Action = strings.TrimSpace(strings.ToLower(p.Action))
		p.Zone = strings.TrimSpace(p.Zone)
		if p.Name == "" {
			return nil, errRPZ("policy name required")
		}
		if seen[p.Name] {
			return nil, errRPZ("duplicate policy name: " + p.Name)
		}
		seen[p.Name] = true
		if p.Format == "" {
			p.Format = "hosts"
		}
		switch p.Format {
		case "hosts":
			if p.Source == "" {
				return nil, errRPZ("policy source required for " + p.Name)
			}
			p.Zone = ""
			p.Masters = nil
		case "axfr":
			if p.Zone == "" {
				return nil, errRPZ("axfr policy requires zone for " + p.Name)
			}
			p.Zone = config.NormalizeName(p.Zone)
			masters, err := config.NormalizeForwarders(p.Masters)
			if err != nil {
				return nil, errRPZ("axfr masters for " + p.Name + ": " + err.Error())
			}
			if len(masters) == 0 {
				return nil, errRPZ("axfr policy requires at least one master for " + p.Name)
			}
			p.Masters = masters
			p.TSIGKey = strings.TrimSpace(p.TSIGKey)
			// Keep Source aligned with zone for display/fingerprint stability.
			if p.Source == "" {
				p.Source = p.Zone
			}
		default:
			return nil, errRPZ("unsupported format (use hosts or axfr): " + p.Format)
		}
		if p.Action == "" {
			p.Action = "nxdomain"
		}
		switch p.Action {
		case "nxdomain", "nodata", "pass":
			p.Target = ""
		case "redirect":
			p.Target = strings.TrimSpace(p.Target)
			if net.ParseIP(p.Target) == nil {
				return nil, errRPZ("redirect requires a valid IP target for " + p.Name)
			}
		case "cname":
			p.Target = strings.TrimSpace(p.Target)
			if p.Target == "" || net.ParseIP(p.Target) != nil {
				return nil, errRPZ("cname requires a hostname target for " + p.Name)
			}
			p.Target = strings.TrimSuffix(strings.ToLower(p.Target), ".")
		default:
			return nil, errRPZ("unsupported action: " + p.Action)
		}
		out = append(out, p)
	}
	return out, nil
}

func (a *API) rpzPolicyConfigs(pols []config.RPZPolicyTOML) []rpz.PolicyConfig {
	var tsigStore interface {
		Get(name string) (string, string, bool)
	}
	if a != nil && a.srv != nil {
		if ts := a.srv.TSIG(); ts != nil {
			tsigStore = ts
		}
	}
	out := make([]rpz.PolicyConfig, 0, len(pols))
	for _, p := range pols {
		pc := rpz.PolicyConfig{
			Name:    p.Name,
			Source:  p.Source,
			Format:  p.Format,
			Action:  rpz.Action(p.Action),
			Target:  p.Target,
			Zone:    p.Zone,
			Masters: append([]string(nil), p.Masters...),
			TSIGKey: strings.TrimSpace(p.TSIGKey),
			Enabled: p.Enabled,
		}
		if pc.TSIGKey != "" && tsigStore != nil {
			if fqdn, sec, ok := tsigStore.Get(pc.TSIGKey); ok {
				pc.TSIGKey = fqdn
				pc.TSIGSecret = sec
			}
		}
		out = append(out, pc)
	}
	return out
}

type rpzError string

func (e rpzError) Error() string { return string(e) }
func errRPZ(s string) error      { return rpzError(s) }

// hostsFullReloadDaytime is true during 06:00–22:00 local — full hosts rebuild is expensive.
func hostsFullReloadDaytime(now time.Time) bool {
	h := now.Hour()
	return h >= 6 && h < 22
}

func (a *API) startRPZReload(sync bool) error {
	return a.startDNSDistCDBRefresh(sync)
}

func (a *API) startRPZAXFRRefresh(sync bool) error {
	return a.startDNSDistCDBRefresh(sync)
}

func notifyMasterMatch(clientIP string, masters []string) bool {
	ipStr := strings.TrimSpace(clientIP)
	if ipStr == "" {
		return false
	}
	if h, _, err := net.SplitHostPort(ipStr); err == nil {
		ipStr = h
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	for _, m := range masters {
		h := strings.TrimSpace(m)
		if host, _, err := net.SplitHostPort(h); err == nil {
			h = host
		}
		if mip := net.ParseIP(h); mip != nil && mip.Equal(ip) {
			return true
		}
	}
	return false
}

// HandleRPZNotify returns true when zone matches an enabled axfr RPZ feed from an authorized master (or valid TSIG) and kicks an AXFR/IXFR refresh.
func (a *API) HandleRPZNotify(zone, clientIP string, tsigValid bool) bool {
	if a == nil || a.cfg == nil {
		return false
	}
	zone = config.NormalizeName(zone)
	match := false
	authorized := false
	for _, p := range a.cfg.RPZ.Policies {
		if !strings.EqualFold(strings.TrimSpace(p.Format), "axfr") || config.NormalizeName(p.Zone) != zone {
			continue
		}
		if p.Enabled != nil && !*p.Enabled {
			continue
		}
		match = true
		if tsigValid || notifyMasterMatch(clientIP, p.Masters) {
			authorized = true
			break
		}
	}
	if !match {
		return false
	}
	if !authorized {
		if a.log != nil {
			a.log.Warn("rejected unauthorized NOTIFY for RPZ feed", "zone", zone, "client", clientIP)
		}
		return false
	}
	if err := a.startRPZAXFRRefresh(false); err != nil {
		a.log.Debug("rpz notify reload skip", "zone", zone, "err", err)
	} else {
		a.log.Info("rpz axfr notify reload started", "zone", zone, "client", clientIP)
	}
	return true
}

// StartRPZAutoUpdate runs separate schedules for hosts and AXFR feeds.
// Hosts: when update_at (HH:MM) is set, fires at that local wall clock daily;
// otherwise uses update_interval as a plain ticker from process start.
func (a *API) StartRPZAutoUpdate() {
	a.rpzAutoMu.Lock()
	defer a.rpzAutoMu.Unlock()
	if a.rpzAutoStop != nil {
		close(a.rpzAutoStop)
		a.rpzAutoStop = nil
	}
	hostsSec := a.cfg.RPZ.UpdateInterval
	axfrSec := a.cfg.RPZ.AxfrUpdateInterval
	hostsAt := strings.TrimSpace(a.cfg.RPZ.UpdateAt)
	if hostsAt != "" {
		if _, _, ok, err := config.ParseHHMM(hostsAt); err != nil || !ok {
			a.log.Warn("rpz update_at invalid; using interval ticker", "update_at", hostsAt, "err", err)
			hostsAt = ""
		}
	}
	if hostsSec <= 0 && axfrSec <= 0 {
		a.log.Info("rpz auto-update disabled")
		return
	}
	stop := make(chan struct{})
	a.rpzAutoStop = stop
	a.log.Info("rpz auto-update enabled",
		"hosts_interval_sec", hostsSec, "hosts_update_at", hostsAt, "axfr_interval_sec", axfrSec)
	go func() {
		var hostsTimer, axfrTimer *time.Timer
		var hostsTick, axfrTick <-chan time.Time

		armHosts := func() {
			hostsTick = nil
			if hostsTimer != nil {
				hostsTimer.Stop()
				hostsTimer = nil
			}
			if hostsSec <= 0 {
				return
			}
			var d time.Duration
			if hostsAt != "" {
				next, err := config.NextDailyAt(time.Now(), hostsAt)
				if err != nil {
					a.log.Warn("rpz hosts schedule", "err", err)
					d = time.Duration(hostsSec) * time.Second
				} else {
					d = time.Until(next)
					if d < time.Second {
						d = time.Second
					}
					a.log.Info("rpz hosts next run", "at", next.Format(time.RFC3339))
				}
			} else {
				d = time.Duration(hostsSec) * time.Second
			}
			hostsTimer = time.NewTimer(d)
			hostsTick = hostsTimer.C
		}
		armAxfr := func() {
			axfrTick = nil
			if axfrTimer != nil {
				axfrTimer.Stop()
				axfrTimer = nil
			}
			if axfrSec <= 0 {
				return
			}
			axfrTimer = time.NewTimer(time.Duration(axfrSec) * time.Second)
			axfrTick = axfrTimer.C
		}
		armHosts()
		armAxfr()
		defer func() {
			if hostsTimer != nil {
				hostsTimer.Stop()
			}
			if axfrTimer != nil {
				axfrTimer.Stop()
			}
		}()

		for {
			select {
			case <-stop:
				return
			case <-hostsTick:
				if a.srv.RPZ() != nil && a.srv.RPZ().LoadStatus().Loading {
					armHosts()
					continue
				}
				if err := a.startRPZReload(false); err != nil {
					a.log.Debug("rpz hosts auto-update skip", "err", err)
				} else {
					a.log.Info("rpz hosts auto-update started")
				}
				armHosts()
			case <-axfrTick:
				if a.srv.RPZ() != nil && a.srv.RPZ().LoadStatus().Loading {
					armAxfr()
					continue
				}
				if err := a.startRPZAXFRRefresh(false); err != nil {
					a.log.Debug("rpz axfr auto-update skip", "err", err)
				} else {
					a.log.Info("rpz axfr auto-update started")
				}
				armAxfr()
			}
		}
	}()
}

func (a *API) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	limit := 100
	if a.events == nil {
		writeJSON(w, http.StatusOK, map[string]any{"events": []eventlog.Event{}})
		return
	}
	evs := a.events.Recent(limit)
	if evs == nil {
		evs = []eventlog.Event{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": evs})
}

func (a *API) handleAnalytics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	col := a.srv.Analytics()
	if col == nil {
		writeJSON(w, http.StatusOK, map[string]any{"top_names": []any{}, "rcodes": []any{}})
		return
	}
	names, rcodes := col.Snapshot(25)
	writeJSON(w, http.StatusOK, map[string]any{"top_names": names, "rcodes": rcodes})
}

func (a *API) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.audit == nil {
		writeJSON(w, http.StatusOK, map[string]any{"events": []any{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": a.audit.Recent(200)})
}

func (a *API) handleAnomaly(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	det := a.srv.Anomaly()
	if det == nil {
		writeJSON(w, http.StatusOK, map[string]any{"alerts": []any{}, "warm": 0})
		return
	}
	writeJSON(w, http.StatusOK, det.Snapshot())
}

// queryHistoryUnavailable is shown when no database is configured. The live query
// stream does not need a database and keeps working.
const queryHistoryUnavailable = "Query history is unavailable: it needs the Observability Profile (Postgres). The live query stream still works."

func (a *API) handleQueryLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if a.db == nil || !a.cfg.Database.Enabled {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error":     "query_history_unavailable",
			"available": false,
			"message":   queryHistoryUnavailable,
			"logs":      []any{}, "total": 0, "limit": 50, "offset": 0,
			"enabled": a.cfg.Logging.QueryLogEnabled,
		})
		return
	}
	q := r.URL.Query()
	limit := 50
	offset := 0
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	if v := q.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			offset = n
		}
	}
	clientIP := strings.TrimSpace(q.Get("client_ip"))
	if clientIP != "" {
		if ip := net.ParseIP(clientIP); ip == nil {
			http.Error(w, "client_ip must be a valid IP", http.StatusBadRequest)
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	rows, total, err := a.db.ListQueryLogs(ctx, database.QueryLogFilter{
		ClientIP: clientIP, Limit: limit, Offset: offset,
	})
	if err != nil {
		// Invalid inet cast etc.
		if clientIP != "" && strings.Contains(err.Error(), "invalid") {
			http.Error(w, "client_ip must be a valid IP", http.StatusBadRequest)
			return
		}
		a.log.Warn("query logs list failed", "err", err)
		http.Error(w, "query logs temporarily unavailable (database busy or table too large)", http.StatusServiceUnavailable)
		return
	}
	if rows == nil {
		rows = []database.QueryLogRow{}
	}
	out := map[string]any{
		"logs":          rows,
		"total":         total,
		"limit":         limit,
		"offset":        offset,
		"client_ip":     clientIP,
		"enabled":       a.cfg.Logging.QueryLogEnabled,
		"dns_dataplane": config.DNSDataplane(),
		"sample_rate":   a.cfg.Logging.QueryLogSampleRate,
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) handleACME(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if a.acmeMgr == nil {
			writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
			return
		}
		writeJSON(w, http.StatusOK, a.acmeMgr.Status())
	case http.MethodPost:
		if a.acmeMgr == nil || !a.cfg.ACME.Enabled {
			http.Error(w, "acme disabled", http.StatusBadRequest)
			return
		}
		if err := a.acmeMgr.Obtain(); err != nil {
			if a.events != nil {
				a.events.Emit("error", "acme", "certificate obtain failed", map[string]string{"err": err.Error()})
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, a.acmeMgr.Status())
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *API) handleBackup(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		zones := a.auth.ListZones()
		out := make([]map[string]any, 0, len(zones))
		for _, z := range zones {
			recs, _ := a.auth.GetRecords(z.Name)
			entry := map[string]any{"name": z.Name, "records": recordsDTO(recs)}
			if meta, ok := a.auth.GetZoneMeta(z.Name); ok {
				entry["meta"] = zoneMetaPayload(z.Name, meta)
			}
			if sig := a.srv.Signer(); sig != nil && sig.Enabled(z.Name) {
				entry["dnssec_signing"] = true
				if ds, err := sig.DS(z.Name); err == nil && ds != nil {
					entry["ds"] = ds.String()
				}
			}
			out = append(out, entry)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"version": apiBackupVersion,
			"zones":   out,
		})
	case http.MethodPost:
		var body struct {
			Zones []struct {
				Name    string      `json:"name"`
				Records []recordDTO `json:"records"`
			} `json:"zones"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		imported := 0
		for _, z := range body.Zones {
			if z.Name == "" {
				continue
			}
			a.auth.CreateZone(z.Name)
			recs := make([]authoritative.Record, 0, len(z.Records))
			for _, rec := range z.Records {
				recs = append(recs, rec.toRecord())
			}
			a.auth.AddRecords(z.Name, recs)
			if a.persistFailed(w) {
				return
			}
			imported++
		}
		writeJSON(w, http.StatusOK, map[string]any{"imported_zones": imported})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

const apiBackupVersion = 1

func (a *API) handleEventStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok || a.events == nil {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ctx := r.Context()
	ch := a.events.Subscribe(ctx, 64)
	// seed with recent so UI isn't empty on connect
	for _, ev := range a.events.Recent(50) {
		if err := writeSSE(w, ev); err != nil {
			return
		}
	}
	flusher.Flush()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = w.Write([]byte(": ping\n\n"))
			flusher.Flush()
		case ev, ok := <-ch:
			if !ok {
				return
			}
			if err := writeSSE(w, ev); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func writeSSE(w http.ResponseWriter, ev eventlog.Event) error {
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	_, err = w.Write([]byte("event: log\ndata: " + string(b) + "\n\n"))
	return err
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// LoadWebDir tries dist path for SPA assets.
func LoadWebDir(dir string) (fs.FS, error) {
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		return nil, err
	}
	return os.DirFS(dir), nil
}

// persistFailed answers 500 when the last zone file write failed.
func (a *API) persistFailed(w http.ResponseWriter) bool {
	if err := a.auth.PersistError(); err != nil {
		http.Error(w, "zone file write failed: "+err.Error(), http.StatusInternalServerError)
		return true
	}
	return false
}

func zoneMetaPayload(zone string, m authoritative.ZoneMeta) map[string]any {
	return map[string]any{
		"name": config.NormalizeName(zone), "type": m.Type, "dnssec_enabled": m.DNSSECEnabled,
		"soa_serial": m.SOASerial, "soa_refresh": m.SOARefresh, "soa_retry": m.SOARetry,
		"soa_expire": m.SOAExpire, "soa_minimum": m.SOAMinimum,
	}
}

func validateMetaPatch(serial *int64, refresh, retry, expire, minimum *int) string {
	if serial != nil && (*serial < 0 || *serial > 4294967295) {
		return "soa_serial out of range"
	}
	for _, v := range []*int{refresh, retry, expire, minimum} {
		if v != nil && (*v < 0 || *v > 2147483647) {
			return "soa timer out of range"
		}
	}
	return ""
}
