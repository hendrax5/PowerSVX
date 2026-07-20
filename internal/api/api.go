package api

import (
	"context"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/acme"
	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/cache"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/database"
	"github.com/powersvx/powersvx/internal/eventlog"
	"github.com/powersvx/powersvx/internal/rpz"
	"github.com/powersvx/powersvx/internal/server"
)

const Version = "1.0.0-phase4"

type API struct {
	cfg      *config.Config
	srv      *server.Server
	db       *database.DB
	cache    *cache.Tier
	auth     *authoritative.Store
	events   *eventlog.Bus
	acmeMgr  *acme.Manager
	log      *slog.Logger
	http     *http.Server
	start    time.Time
	webFS    fs.FS
	reloadFn func() error

	rpzAutoMu   sync.Mutex
	rpzAutoStop chan struct{}
}

func New(cfg *config.Config, srv *server.Server, db *database.DB, tier *cache.Tier, auth *authoritative.Store, log *slog.Logger) *API {
	return &API{cfg: cfg, srv: srv, db: db, cache: tier, auth: auth, log: log, start: time.Now()}
}

func (a *API) SetWebFS(fsys fs.FS) { a.webFS = fsys }
func (a *API) SetReloadZones(fn func() error) { a.reloadFn = fn }
func (a *API) SetEvents(bus *eventlog.Bus) { a.events = bus }
func (a *API) SetACME(m *acme.Manager) { a.acmeMgr = m }

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
	mux.HandleFunc("/api/v1/zones/", a.withAuth(a.handleZoneSub))
	mux.HandleFunc("/api/v1/settings", a.withAuth(a.handleSettings))
	mux.HandleFunc("/api/v1/rpz", a.withAuth(a.handleRPZ))
	mux.HandleFunc("/api/v1/tools/lookup", a.withAuth(a.handleLookup))
	mux.HandleFunc("/api/v1/events", a.withAuth(a.handleEvents))
	mux.HandleFunc("/api/v1/events/stream", a.withAuth(a.handleEventStream))
	mux.HandleFunc("/api/v1/analytics", a.withAuth(a.handleAnalytics))
	mux.HandleFunc("/api/v1/acme", a.withAuth(a.handleACME))
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
		if a.cfg.API.AuthType == "token" && a.cfg.API.APIToken != "" {
			h := r.Header.Get("Authorization")
			if h != "Bearer "+a.cfg.API.APIToken && r.URL.Query().Get("token") != a.cfg.API.APIToken {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next(w, r)
	}
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
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
		if _, err := fs.Stat(a.webFS, p); err != nil {
			r.URL.Path = "/"
			fileServer.ServeHTTP(w, r)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
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

func (a *API) statusPayload() map[string]any {
	queries, uptime := a.srv.Stats()
	hits, misses, size := a.cache.L1.Stats()
	zones := 0
	if a.auth != nil {
		zones = a.auth.ZoneCount()
	}
	flags := a.srv.RuntimeFlags()
	return map[string]any{
		"version": Version, "uptime_seconds": int(uptime.Seconds()),
		"mode": a.cfg.Resolver.Mode, "dnssec_mode": a.srv.DNSSECMode(),
		"dot_enabled": a.srv.DoTEnabled(), "doh_enabled": a.srv.DoHEnabled(), "doq_enabled": a.srv.DoQEnabled(),
		"dot_addr": a.srv.DoTAddr(), "doh_addr": a.srv.DoHAddr(), "doq_addr": a.srv.DoQAddr(),
		"queries_total": queries, "rate_limited": a.srv.Blocked(),
		"cache_hits": hits, "cache_misses": misses, "cache_l1_size": size,
		"rpz_entries": a.srv.RPZCount(), "zones": zones, "udp_addr": a.srv.UDPAddr(),
		"ratelimit_enabled": flags.RateLimit, "rpz_enabled": flags.RPZ,
		"ecs_enabled": flags.ECS,
		"geodns_enabled": flags.GeoDNS,
		"split_horizon_enabled": flags.SplitHorizon,
	}
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
		if a.db != nil && a.cfg.Database.Enabled {
			if _, err := a.db.CreateZone(r.Context(), body.Name); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = a.reloadZones()
		} else {
			a.auth.UpsertZone(body.Name)
		}
		writeJSON(w, http.StatusCreated, map[string]any{"name": config.NormalizeName(body.Name)})
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
			writeJSON(w, http.StatusOK, map[string]any{"name": config.NormalizeName(zone), "records": recordsDTO(recs)})
		case http.MethodDelete:
			if a.db != nil && a.cfg.Database.Enabled {
				if err := a.db.DeleteZone(r.Context(), zone); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				_ = a.reloadZones()
			} else if !a.auth.DeleteZone(zone) {
				http.Error(w, "zone not found", http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusNoContent)
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
		if a.db != nil && a.cfg.Database.Enabled {
			if err := a.db.AddRecord(r.Context(), zone, rec); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = a.reloadZones()
		} else {
			a.auth.UpsertZone(zone)
			a.auth.AddRecord(zone, rec)
		}
		writeJSON(w, http.StatusCreated, body)
	case http.MethodDelete:
		name := r.URL.Query().Get("name")
		typ := r.URL.Query().Get("type")
		if name == "" {
			http.Error(w, "name required", http.StatusBadRequest)
			return
		}
		if a.db != nil && a.cfg.Database.Enabled {
			if err := a.db.DeleteRecord(r.Context(), zone, name, typ); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = a.reloadZones()
		} else {
			qt := authoritative.TypeFromString(typ)
			a.auth.DeleteRecord(zone, name, qt)
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
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
			GeoDNS       *bool `json:"geodns"`
			RPZ          *bool `json:"rpz_enabled"`
			RateLimit    *bool `json:"rate_limit"`
			ECS          *bool `json:"ecs_enabled"`
			SplitHorizon *bool `json:"split_horizon"`
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
		a.srv.ApplyRuntimeFlags(cur)
		_ = config.SaveRuntimeSettings(config.RuntimeSettingsPath("./data"), config.RuntimeSettings{
			GeoDNS: &cur.GeoDNS, RPZ: &cur.RPZ, RateLimit: &cur.RateLimit,
			ECS: &cur.ECS, SplitHorizon: &cur.SplitHorizon,
		})
		writeJSON(w, http.StatusOK, a.settingsPayload())
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *API) settingsPayload() map[string]any {
	f := a.srv.RuntimeFlags()
	return map[string]any{
		"resolver_mode": a.cfg.Resolver.Mode,
		"forwarders":    a.cfg.Resolver.Forwarders,
		"dnssec_mode":   a.cfg.Resolver.DNSSECMode,
		"ecs_enabled":   f.ECS,
		"rpz_enabled":   f.RPZ,
		"geodns":        f.GeoDNS,
		"split_horizon": f.SplitHorizon,
		"rate_limit":    f.RateLimit,
		"udp_addr":      a.srv.UDPAddr(),
		"geodns_db":     a.cfg.GeoDNS.DatabasePath,
		"editable":      []string{"geodns", "rpz_enabled", "rate_limit", "ecs_enabled", "split_horizon"},
		"note":          "Edit toggles, then Save to apply and persist (data/runtime-settings.json). No restart required.",
	}
}

func (a *API) handleRPZ(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, a.rpzPayload())
	case http.MethodPut:
		var body struct {
			Policies       []config.RPZPolicyTOML `json:"policies"`
			UpdateInterval *int                   `json:"update_interval"`
			Sync           *bool                  `json:"sync"`
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
		interval := a.cfg.RPZ.UpdateInterval
		if body.UpdateInterval != nil {
			if *body.UpdateInterval < 0 {
				http.Error(w, "update_interval must be >= 0", http.StatusBadRequest)
				return
			}
			interval = *body.UpdateInterval
		}
		eng := a.srv.RPZ()
		if eng != nil && eng.LoadStatus().Loading {
			http.Error(w, "rpz sync already in progress", http.StatusConflict)
			return
		}
		path := config.RPZPoliciesPath("./data")
		if err := config.SaveRPZPoliciesFile(path, config.RPZPoliciesFile{
			Policies: pols, UpdateInterval: interval,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		a.cfg.RPZ.Policies = pols
		a.cfg.RPZ.UpdateInterval = interval
		a.StartRPZAutoUpdate()
		sync := body.Sync != nil && *body.Sync
		if err := a.startRPZReload(sync); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		writeJSON(w, http.StatusOK, a.rpzPayload())
	case http.MethodPost:
		if a.srv.RPZ() != nil && a.srv.RPZ().LoadStatus().Loading {
			http.Error(w, "rpz sync already in progress", http.StatusConflict)
			return
		}
		if err := a.startRPZReload(false); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		writeJSON(w, http.StatusAccepted, a.rpzPayload())
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *API) rpzPayload() map[string]any {
	st := rpz.LoadStatus{}
	if eng := a.srv.RPZ(); eng != nil {
		st = eng.LoadStatus()
	}
	pols := a.cfg.RPZ.Policies
	if pols == nil {
		pols = []config.RPZPolicyTOML{}
	}
	return map[string]any{
		"enabled":         a.srv.RuntimeFlags().RPZ,
		"entries":         a.srv.RPZCount(),
		"policies":        pols,
		"update_interval": a.cfg.RPZ.UpdateInterval,
		"loading":         st.Loading,
		"error":           st.Error,
		"last_loaded":     st.LastLoaded,
		"from_disk":       st.FromDisk,
		"note":            "PUT policies + update_interval. Large feeds sync in background; radix+Badger snapshot skips re-download on restart.",
	}
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
		if p.Name == "" {
			return nil, errRPZ("policy name required")
		}
		if p.Source == "" {
			return nil, errRPZ("policy source required for " + p.Name)
		}
		if seen[p.Name] {
			return nil, errRPZ("duplicate policy name: " + p.Name)
		}
		seen[p.Name] = true
		if p.Format == "" {
			p.Format = "hosts"
		}
		if p.Format != "hosts" {
			return nil, errRPZ("unsupported format (use hosts): " + p.Format)
		}
		if p.Action == "" {
			p.Action = "nxdomain"
		}
		switch p.Action {
		case "nxdomain", "nodata", "pass":
		default:
			return nil, errRPZ("unsupported action: " + p.Action)
		}
		out = append(out, p)
	}
	return out, nil
}

type rpzError string

func (e rpzError) Error() string { return string(e) }
func errRPZ(s string) error      { return rpzError(s) }

func (a *API) startRPZReload(sync bool) error {
	eng := a.srv.RPZ()
	if eng == nil {
		return nil
	}
	if !eng.TryBeginLoad() {
		return errRPZ("rpz sync already in progress")
	}
	var policies []rpz.PolicyConfig
	for _, p := range a.cfg.RPZ.Policies {
		policies = append(policies, rpz.PolicyConfig{
			Name: p.Name, Source: p.Source, Format: p.Format, Action: rpz.Action(p.Action),
		})
	}
	run := func() {
		n, err := a.srv.ReloadRPZ(policies, 15*time.Minute)
		eng.EndLoad(err)
		if err != nil {
			a.log.Warn("rpz reload failed", "err", err)
			return
		}
		a.log.Info("rpz reloaded", "entries", n)
	}
	if sync {
		run()
		return nil
	}
	go run()
	return nil
}

// StartRPZAutoUpdate reloads feeds on update_interval (seconds). 0 disables.
func (a *API) StartRPZAutoUpdate() {
	a.rpzAutoMu.Lock()
	defer a.rpzAutoMu.Unlock()
	if a.rpzAutoStop != nil {
		close(a.rpzAutoStop)
		a.rpzAutoStop = nil
	}
	sec := a.cfg.RPZ.UpdateInterval
	if sec <= 0 {
		a.log.Info("rpz auto-update disabled")
		return
	}
	stop := make(chan struct{})
	a.rpzAutoStop = stop
	interval := time.Duration(sec) * time.Second
	a.log.Info("rpz auto-update enabled", "interval_sec", sec)
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				if a.srv.RPZ() != nil && a.srv.RPZ().LoadStatus().Loading {
					continue
				}
				if err := a.startRPZReload(false); err != nil {
					a.log.Debug("rpz auto-update skip", "err", err)
				} else {
					a.log.Info("rpz auto-update started")
				}
			}
		}
	}()
}

func (a *API) handleLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}
	qtype := dns.TypeA
	if body.Type != "" {
		if t, ok := dns.StringToType[strings.ToUpper(body.Type)]; ok {
			qtype = t
		}
	}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(body.Name), qtype)
	msg.RecursionDesired = true
	resp, _, err := a.srv.ServeDNSMsg(msg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	answers := make([]string, 0, len(resp.Answer))
	for _, rr := range resp.Answer {
		answers = append(answers, rr.String())
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"rcode": dns.RcodeToString[resp.Rcode], "answers": answers, "ad": resp.AuthenticatedData,
	})
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

func (a *API) reloadZones() error {
	if a.reloadFn != nil {
		return a.reloadFn()
	}
	if a.db == nil || !a.cfg.Database.Enabled {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	zones, err := a.db.LoadZones(ctx)
	if err != nil {
		return err
	}
	a.auth.Replace(zones)
	return nil
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