package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/powersvx/powersvx/internal/acme"
	"github.com/powersvx/powersvx/internal/allowlist"
	"github.com/powersvx/powersvx/internal/denylist"
	"github.com/powersvx/powersvx/internal/analytics"
	"github.com/powersvx/powersvx/internal/anomaly"
	"github.com/powersvx/powersvx/internal/api"
	"github.com/powersvx/powersvx/internal/apiauth"
	"github.com/powersvx/powersvx/internal/audit"
	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/blockcdb"
	"github.com/powersvx/powersvx/internal/cache"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/database"
	"github.com/powersvx/powersvx/internal/dnssec"
	"github.com/powersvx/powersvx/internal/eventlog"
	"github.com/powersvx/powersvx/internal/geo"
	"github.com/powersvx/powersvx/internal/grpcapi"
	"github.com/powersvx/powersvx/internal/kominfo"
	"github.com/powersvx/powersvx/internal/metrics"
	"github.com/powersvx/powersvx/internal/monitor"
	"github.com/powersvx/powersvx/internal/otelx"
	"github.com/powersvx/powersvx/internal/plugin"
	"github.com/powersvx/powersvx/internal/ratelimit"
	"github.com/powersvx/powersvx/internal/resolver"
	"github.com/powersvx/powersvx/internal/rpz"
	"github.com/powersvx/powersvx/internal/secondary"
	"github.com/powersvx/powersvx/internal/server"
	"github.com/powersvx/powersvx/internal/tlsutil"
	"github.com/powersvx/powersvx/internal/tsig"
	"github.com/powersvx/powersvx/internal/unboundlog"
	"github.com/powersvx/powersvx/internal/unboundrpz"
	"github.com/powersvx/powersvx/internal/view"
	"github.com/powersvx/powersvx/internal/watchdog"
)

func main() {
	cfgPath := flag.String("config", "configs/powersvx.toml", "path to TOML config")
	dataDir := flag.String("data-dir", "./data", "directory for runtime settings, DNSSEC keys, RPZ store")
	flag.Parse()

	bus := eventlog.New(200)
	log := slog.New(eventlog.NewHandler(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}), bus))

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Error("config load failed", "err", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(*dataDir, 0o755); err != nil {
		log.Error("data-dir create failed", "dir", *dataDir, "err", err)
		os.Exit(1)
	}
	rsPath := config.RuntimeSettingsPath(*dataDir)
	if rs, err := config.LoadRuntimeSettings(rsPath); err == nil {
		cfg.ApplyRuntimeSettings(rs)
		log.Info("runtime settings loaded", "path", rsPath)
	}
	config.ApplyQueryLogGuard(cfg)
	watchdog.Start(log)
	if config.UnboundDataplane() {
		cfg.Server.TProxy = false
		dir := unboundrpz.Dir(*dataDir)
		_ = unboundrpz.EnsureEmptyZones(dir)
		_ = unboundrpz.WriteBankPassthru(filepath.Join(dir, unboundrpz.BankFile))
		_ = unboundrpz.WriteAccessControl(filepath.Join(dir, "access-control.conf"), cfg.ACL.AllowQuery)
		log.Info("dns dataplane unbound — PowerSVX is control-plane",
			"auth_udp", cfg.Server.UDPPort, "api", cfg.API.RESTBind)
	}
	if config.DNSDistDataplane() {
		cfg.Server.TProxy = false
		_ = blockcdb.EnsureEmpty(*dataDir)
		_, _ = blockcdb.WriteBanksWhitelist(*dataDir)
		_ = unboundrpz.EnsureEmptyZones(unboundrpz.Dir(*dataDir))
		log.Info("dns dataplane dnsdist+CDB — PowerSVX is control-plane",
			"auth_udp", cfg.Server.UDPPort, "api", cfg.API.RESTBind, "blocklist", blockcdb.Dir(*dataDir))
	}
	cacheMB, inflight, memMB, cpus := cfg.Autosize()
	log.Info("autosize",
		"cache_max_size_mb", cacheMB,
		"max_inflight", inflight,
		"host_mem_mb", memMB,
		"cpus", cpus,
	)

	l1Max := cfg.Cache.MaxSizeMB * 1024
	if l1Max <= 0 {
		l1Max = 100_000
	}
	l1 := cache.NewL1(l1Max)
	var l2 *cache.L2
	l2, err = cache.NewL2(cfg.Cache.Path)
	if err != nil {
		log.Warn("L2 BadgerDB unavailable, continuing with L1 only", "err", err)
	}
	tier := cache.NewTier(l1, l2,
		time.Duration(cfg.Cache.TTLSeconds)*time.Second,
		time.Duration(cfg.Cache.NegativeTTL)*time.Second,
	)
	if cfg.Cache.MinTTL > 0 {
		tier.MinTTL = time.Duration(cfg.Cache.MinTTL) * time.Second
	}
	tier.ServeStale = cfg.Cache.ServeStale
	if cfg.Cache.StaleTTL > 0 {
		tier.StaleTTL = time.Duration(cfg.Cache.StaleTTL) * time.Second
	} else if tier.ServeStale {
		tier.StaleTTL = time.Minute
	}
	tier.PrefetchPct = cfg.Cache.PrefetchPct
	defer func() { _ = tier.Close() }()

	auth := authoritative.NewStore()
	var db *database.DB
	if cfg.Database.Enabled {
		db, err = database.Connect(cfg.Database, log)
		if err != nil {
			log.Error("database connect failed", "err", err)
			os.Exit(1)
		}
		defer func() { _ = db.Close() }()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		if err := db.Migrate(ctx); err != nil {
			cancel()
			log.Error("migrate failed", "err", err)
			os.Exit(1)
		}
		zones, err := db.LoadZones(ctx)
		cancel()
		if err != nil {
			log.Warn("zone load failed", "err", err)
		} else {
			auth.Replace(zones)
			log.Info("zones loaded", "count", len(zones))
		}
	}

	sec := dnssec.New(dnssec.ParseMode(cfg.Resolver.DNSSECMode, cfg.Resolver.DNSSECValidation))
	signer := dnssec.NewSigner(filepath.Join(*dataDir, "dnssec"))
	if cfg.API.AuthType == "token" && cfg.API.APIToken == "" && len(cfg.API.Tokens) == 0 {
		log.Error("api auth_type=token requires api_token (set API_TOKEN or config)")
		os.Exit(1)
	}
	var userStore *apiauth.UserStore
	var sessStore *apiauth.SessionStore
	if strings.EqualFold(cfg.API.AuthType, "local") {
		var err error
		userStore, err = apiauth.NewUserStore(*dataDir, cfg.API.Users)
		if err != nil {
			log.Error("user store", "err", err)
			os.Exit(1)
		}
		adminPW := apiauth.NormalizePassword(os.Getenv("ADMIN_PASSWORD"))
		if created, err := userStore.EnsureBootstrap(adminPW); err != nil {
			log.Warn("users.json persist failed; ADMIN_PASSWORD still used for login", "err", err)
		} else if created {
			log.Info("bootstrapped local admin user from ADMIN_PASSWORD")
		}
		if userStore.Count() == 0 {
			log.Error("auth_type=local requires [[api.users]] or ADMIN_PASSWORD in environment")
			os.Exit(1)
		}
		log.Info("local auth ready",
			"users", userStore.Count(),
			"admin_password_from_env", userStore.EnvAdminPasswordSet(),
		)
		// Session cookies: Secure only when the browser uses HTTPS (see SetCookie).
		// Do not tie this to DoT/DoH TLS — UI is usually plain HTTP :5380.
		sessStore = apiauth.NewSessionStore(*dataDir, apiauth.DefaultTTL, false)
	}
	limiter := ratelimit.New(cfg.RateLimit.Enabled, cfg.RateLimit.DefaultQPS, cfg.RateLimit.DefaultBurst, cfg.RateLimit.BlockDuration, cfg.RateLimit.Whitelist)
	limiter.ConfigureGlobal(cfg.RateLimit.GlobalQPS, cfg.RateLimit.GlobalBurst)

	rpzPath := config.RPZPoliciesPath(*dataDir)
	if file, err := config.LoadRPZPoliciesFile(rpzPath); err == nil {
		// Empty policies in the JSON overlay must not silently wipe TOML feeds
		// (that caused fleet hosts to run with rpz_enabled=true and 0 entries).
		if len(file.Policies) == 0 && len(cfg.RPZ.Policies) > 0 {
			log.Warn("rpz-policies.json has empty policies; keeping TOML policies",
				"path", rpzPath, "toml_count", len(cfg.RPZ.Policies))
		} else {
			cfg.RPZ.Policies = file.Policies
		}
		if file.UpdateInterval > 0 {
			cfg.RPZ.UpdateInterval = file.UpdateInterval
		}
		if strings.TrimSpace(file.UpdateAt) != "" {
			cfg.RPZ.UpdateAt = strings.TrimSpace(file.UpdateAt)
		}
		if file.AxfrUpdateInterval != nil {
			cfg.RPZ.AxfrUpdateInterval = *file.AxfrUpdateInterval
		} else if cfg.RPZ.AxfrUpdateInterval <= 0 {
			cfg.RPZ.AxfrUpdateInterval = config.DefaultAxfrUpdateInterval
		}
		log.Info("rpz policies loaded", "path", rpzPath, "count", len(cfg.RPZ.Policies),
			"update_interval", cfg.RPZ.UpdateInterval, "update_at", cfg.RPZ.UpdateAt,
			"axfr_update_interval", cfg.RPZ.AxfrUpdateInterval)
	}

	rpzEng := rpz.New(cfg.RPZ.Enabled)
	if cfg.RPZ.HotCacheMax > 0 {
		rpzEng.SetHotCacheSize(cfg.RPZ.HotCacheMax)
	}
	if err := rpzEng.OpenDisk(filepath.Join(*dataDir, "rpz-store")); err != nil {
		log.Warn("rpz disk store unavailable", "err", err)
	}
	rpzEng.SetAxfrState(rpz.LoadAxfrState(rpz.AxfrStatePath(*dataDir)))
	defer func() { _ = rpzEng.Close() }()

	wl := allowlist.New(allowlist.DefaultPath(*dataDir))
	if err := wl.Load(); err != nil {
		log.Warn("whitelist load failed", "err", err)
	} else {
		log.Info("whitelist ready", "entries", wl.Count())
	}
	bl := denylist.New(denylist.DefaultPath(*dataDir))
	if err := bl.Load(); err != nil {
		log.Warn("blacklist load failed", "err", err)
	} else {
		log.Info("blacklist ready", "entries", bl.Count())
	}
	var policies []rpz.PolicyConfig
	for _, p := range cfg.RPZ.Policies {
		policies = append(policies, rpz.PolicyConfig{
			Name: p.Name, Source: p.Source, Format: p.Format, Action: rpz.Action(p.Action), Target: p.Target,
			Zone: p.Zone, Masters: append([]string(nil), p.Masters...),
		})
	}
	if len(policies) > 0 {
		if config.UnboundDataplane() {
			// Control-plane: do not load 9.5M into Go Badger — sync Unbound RPZ zonefiles.
			go func() {
				n, err := unboundrpz.SyncFromConfigPolicies(*dataDir, cfg.RPZ.Policies, 15*time.Minute)
				if err != nil {
					log.Warn("unbound rpz initial sync failed", "err", err)
					return
				}
				if err := unboundrpz.TryReload(); err != nil {
					log.Warn("unbound reload after initial rpz sync", "err", err, "entries", n)
				} else {
					log.Info("unbound rpz initial sync ok", "entries", n)
				}
			}()
		} else if config.DNSDistDataplane() {
			// CDB sync kicked after API starts (StartRPZAutoUpdate / explicit refresh).
			log.Info("dnsdist dataplane: block CDB sync deferred to API start")
		} else if rpzEng.TryBeginLoad() {
			// Disk snapshots and large HTTP feeds must not block API/DNS bind.
			go func() {
				if ok, n, err := rpzEng.TryLoadDisk(policies); err != nil {
					log.Warn("rpz disk load failed", "err", err)
				} else if ok {
					rpzEng.EndLoad(nil)
					log.Info("rpz loaded from disk", "entries", n)
					seedPath := filepath.Join(*dataDir, rpz.HotSeedPath)
					if names, err := rpz.ReadHotSeed(seedPath); err == nil && len(names) > 0 {
						s := rpzEng.SeedHot(names)
						log.Info("rpz hot-seed from disk file", "names", len(names), "seeded", s)
					}
					return
				}
				n, err := rpzEng.LoadPolicies(policies, 15*time.Minute)
				rpzEng.EndLoad(err)
				if err != nil {
					log.Warn("rpz load failed", "err", err)
					return
				}
				log.Info("rpz loaded", "entries", n)
				seedPath := filepath.Join(*dataDir, rpz.HotSeedPath)
				if names, err := rpz.ReadHotSeed(seedPath); err == nil && len(names) > 0 {
					s := rpzEng.SeedHot(names)
					log.Info("rpz hot-seed from disk file", "names", len(names), "seeded", s)
				}
			}()
		}
	}

	tsigStore := tsig.New()
	if cfg.TSIG.Enabled {
		for _, k := range cfg.TSIG.Keys {
			if err := tsigStore.Set(k.Name, k.Secret); err != nil {
				log.Warn("tsig key", "name", k.Name, "err", err)
			}
		}
		log.Info("tsig keys loaded", "count", tsigStore.Len())
	}

	viewMap := map[string][]string{}
	for _, v := range cfg.SplitHorizon.Views {
		viewMap[v.Name] = v.Networks
	}
	views := view.FromConfig(cfg.SplitHorizon.Enabled, "default", viewMap)

	geoRes, err := geo.New(cfg.GeoDNS.Enabled, cfg.GeoDNS.DatabasePath, cfg.GeoDNS.DefaultTag)
	if err != nil {
		log.Warn("geodns mmdb unavailable, using overrides/default", "err", err)
	}
	if geoRes != nil {
		for _, o := range cfg.GeoDNS.Overrides {
			geoRes.SetOverride(o.IP, geo.Info{Country: o.Country, Continent: o.Continent, Tag: o.Tag})
		}
		defer func() { _ = geoRes.Close() }()
	}

	var tlsCfg *tls.Config
	if cfg.TLSEnabled() {
		tlsCfg, err = tlsutil.LoadServerTLS(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
		if err != nil {
			// Do not abort DNS UDP/TCP — empty ./certs bind-mounts are a common deploy footgun.
			log.Error("tls load failed; continuing without DoT/DoH/DoQ", "err", err,
				"cert", cfg.Server.TLS.CertFile, "key", cfg.Server.TLS.KeyFile)
			tlsCfg = nil
		} else {
			log.Info("TLS enabled", "cert", cfg.Server.TLS.CertFile)
		}
	}

	if cfg.Metrics.PrometheusEnabled {
		bind := cfg.Metrics.PrometheusBind
		if bind == "" {
			bind = "0.0.0.0:9100"
		}
		go func() {
			mux := http.NewServeMux()
			mux.Handle("/metrics", metrics.Handler())
			log.Info("Prometheus metrics", "addr", bind)
			if err := http.ListenAndServe(bind, mux); err != nil {
				log.Error("metrics server", "err", err)
			}
		}()
	}

	otelShutdown, err := otelx.Init(context.Background(), "powersvx", cfg.Metrics.OTelEnabled)
	if err != nil {
		log.Warn("otel init failed", "err", err)
		otelShutdown = func(context.Context) error { return nil }
	} else if cfg.Metrics.OTelEnabled || os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "" {
		log.Info("OpenTelemetry tracing enabled")
	}
	defer func() { _ = otelShutdown(context.Background()) }()

	res := resolver.New(cfg.Resolver)
	acmeStore := acme.NewChallengeStore()
	acmeMgr := acme.NewManager(cfg.ACME, acmeStore, log)
	stats := analytics.New(200)
	anom := anomaly.New(50)
	mon := monitor.New()
	res.OnForwarder = func(addr string, ok bool, latencyMS int64, errMsg string) {
		mon.RecordForwarder(addr, ok, latencyMS, errMsg)
		if ok {
			metrics.ForwarderAttempts.WithLabelValues(addr, "ok").Inc()
		} else {
			metrics.ForwarderAttempts.WithLabelValues(addr, "fail").Inc()
		}
	}
	qlog := database.NewQueryLogger(db, cfg.Logging.QueryLogEnabled, log)
	defer qlog.Close()
	var plugins *plugin.Registry
	if cfg.Plugins.Enabled {
		var err error
		plugins, err = plugin.LoadDir(cfg.Plugins.Dir)
		if err != nil {
			log.Warn("plugins load failed", "err", err)
			plugins = plugin.NewRegistry()
		} else {
			log.Info("plugins loaded", "dir", cfg.Plugins.Dir, "count", plugins.Len())
		}
	}
	dnsSrv := server.New(cfg, server.Deps{
		Cache: tier, Res: res, Auth: auth, DNSSEC: sec, Signer: signer,
		Limiter: limiter, RPZ: rpzEng, Allow: wl, Deny: bl, TSIG: tsigStore,
		Views: views, Geo: geoRes, TLS: tlsCfg, Events: bus,
		ACME: acmeStore, Stats: stats, Anomaly: anom, Monitor: mon, Plugins: plugins, QLog: qlog,
	}, log)

	secMgr := secondary.New(secondary.DefaultPath(*dataDir), auth, log)
	if err := secMgr.Load(); err != nil {
		log.Warn("secondary zones load failed", "err", err)
	} else {
		dnsSrv.SetSecondary(secMgr)
		secMgr.Start(context.Background())
		defer secMgr.Stop()
		log.Info("secondary manager ready", "zones", len(secMgr.List()))
	}
	kominfoMgr := kominfo.New(auth, log, cfg.KominfoSync.Targets)
	kominfoMgr.SetEnabled(cfg.KominfoSync.Enabled)
	dnsSrv.SetKominfo(kominfoMgr)
	log.Info("axfr sync ready", "enabled", kominfoMgr.Enabled(), "targets", kominfoMgr.Targets())

	rest := api.New(cfg, dnsSrv, db, tier, auth, log)
	rest.SetDataDir(*dataDir)
	rest.SetEvents(bus)
	rest.SetACME(acmeMgr)
	dnsSrv.SetRPZNotifyHandler(rest.HandleRPZNotify)
	auditLog := audit.New(500, log)
	rest.SetAudit(auditLog)
	if userStore != nil {
		rest.SetUserStore(userStore)
	}
	if sessStore != nil {
		rest.SetSessionStore(sessStore)
	}
	rest.StartRPZAutoUpdate()
	if config.DNSDistDataplane() {
		rest.RefreshUnboundEntryCount()
		rest.StartDNSDistStatsBridge()
		rest.StartUnboundStatsBridge() // backend Unbound :5353 (Prometheus only; UI QPS from dnsdist)
		if err := rest.TriggerDNSDistCDBSync(); err != nil {
			log.Warn("dnsdist cdb initial sync not started", "err", err)
		}
	}
	if config.UnboundDataplane() {
		rest.RefreshUnboundEntryCount()
		rest.StartUnboundStatsBridge()
		if config.UnboundQueryLogAllowed() && qlog != nil {
			samp := unboundlog.NewSampler(unboundlog.DefaultPath(), qlog, cfg, log)
			samp.Start()
			defer samp.Stop()
		}
	}
	if n := cfg.RPZ.HotSeedTopN; n > 0 && !config.UnboundDataplane() && !config.DNSDistDataplane() {
		seedPath := filepath.Join(*dataDir, rpz.HotSeedPath)
		go func() {
			// Warm shortly after start, then refresh from live top-blocked.
			t := time.NewTicker(5 * time.Minute)
			defer t.Stop()
			run := func() {
				top := mon.TopBlockedNames(n)
				if len(top) == 0 {
					return
				}
				names := make([]string, 0, len(top))
				for _, c := range top {
					names = append(names, c.Key)
				}
				_ = rpz.WriteHotSeed(seedPath, names)
				s := rpzEng.SeedHot(names)
				log.Info("rpz hot-seed refreshed", "top_n", n, "names", len(names), "seeded", s)
			}
			time.Sleep(30 * time.Second)
			run()
			for range t.C {
				run()
			}
		}()
		log.Info("rpz hot-seed loop enabled", "top_n", n, "path", seedPath)
	}
	if db != nil {
		retCtx, retCancel := context.WithCancel(context.Background())
		defer retCancel()
		db.StartRetentionLoop(retCtx, cfg.Logging.QueryLogRetentionDays, cfg.Logging.QueryLogMaxSizeMB, time.Hour)
		log.Info("query log retention enabled",
			"days", cfg.Logging.QueryLogRetentionDays,
			"max_size_mb", cfg.Logging.QueryLogMaxSizeMB,
			"mask_ip", cfg.Logging.QueryLogMaskIP,
		)
	}
	webDirs := []string{"./web/dist", "/usr/share/PowerSVX/web"}
	for _, dir := range webDirs {
		if webFS, err := api.LoadWebDir(dir); err == nil {
			rest.SetWebFS(webFS)
			log.Info("web UI mounted", "dir", dir)
			break
		}
	}
	if db != nil && cfg.Database.Enabled {
		rest.SetReloadZones(func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			zones, err := db.LoadZones(ctx)
			if err != nil {
				return err
			}
			auth.Replace(zones)
			return nil
		})
	}
	if err := rest.Start(); err != nil {
		log.Error("api start failed", "err", err)
		os.Exit(1)
	}

	var grpcSrv *grpcapi.Server
	if cfg.API.GRPCEnabled {
		tok := ""
		if cfg.API.AuthType == "token" {
			tok = cfg.API.APIToken
		}
		grpcSrv, err = grpcapi.Start(cfg.API.GRPCBind, dnsSrv, log, tok)
		if err != nil {
			log.Error("grpc start failed", "err", err)
			os.Exit(1)
		}
	}

	go func() {
		if err := dnsSrv.ListenAndServe(); err != nil {
			log.Error("dns server stopped", "err", err)
			os.Exit(1)
		}
	}()

	if err := api.SyncTProxyOnStartup(*dataDir); err != nil {
		log.Warn("tproxy intercept apply on startup failed", "err", err)
	} else {
		log.Info("tproxy listen", "enabled", cfg.Server.TProxy)
	}
	if err := api.SyncConntrackOnStartup(*dataDir); err != nil {
		log.Warn("conntrack apply on startup failed", "err", err)
	}

	log.Info("PowerSVX started",
		"version", api.Version,
		"git", api.GitCommit,
		"build_id", api.BuildID(),
		"udp", cfg.ListenAddr(cfg.Server.UDPPort),
		"mode", cfg.Resolver.Mode,
		"dnssec", cfg.Resolver.DNSSECMode,
		"rpz", cfg.RPZ.Enabled,
		"ratelimit", cfg.RateLimit.Enabled,
		"ecs", cfg.Resolver.ECSEnabled,
		"geodns", cfg.GeoDNS.Enabled,
		"split_horizon", cfg.SplitHorizon.Enabled,
		"tls", cfg.TLSEnabled(),
		"acme", cfg.ACME.Enabled,
		"query_log", cfg.Logging.QueryLogEnabled,
		"api", cfg.API.RESTBind,
		"grpc", cfg.API.GRPCEnabled,
	)

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for sig := range ch {
		if sig == syscall.SIGHUP {
			log.Info("SIGHUP: reloading runtime settings and plugins")
			if rs, err := config.LoadRuntimeSettings(config.RuntimeSettingsPath(*dataDir)); err == nil {
				cfg.ApplyRuntimeSettings(rs)
				config.ApplyQueryLogGuard(cfg)
				dnsSrv.ApplyRuntimeFlags(server.RuntimeFlags{
					GeoDNS: cfg.GeoDNS.Enabled, RPZ: cfg.RPZ.Enabled,
					RateLimit: cfg.RateLimit.Enabled, ECS: cfg.Resolver.ECSEnabled,
					SplitHorizon: cfg.SplitHorizon.Enabled,
					ResolverMode: cfg.Resolver.Mode, ForwardOnFail: cfg.Resolver.ForwardOnFail,
					QueryLog: cfg.Logging.QueryLogEnabled, Forwarders: cfg.Resolver.Forwarders,
					ForwardZones: cfg.Resolver.ForwardZones,
					KominfoSync:  cfg.KominfoSync.Enabled,
				})
				if k := dnsSrv.Kominfo(); k != nil {
					_ = k.SetTargets(cfg.KominfoSync.Targets)
				}
				if err := dnsSrv.SetQueryACL(cfg.ACL.AllowQuery, cfg.ACL.DenyQuery); err != nil {
					log.Warn("acl reload failed", "err", err)
				}
				if db != nil {
					db.SetQueryLogLimits(cfg.Logging.QueryLogRetentionDays, cfg.Logging.QueryLogMaxSizeMB)
				}
			}
			if cfg.Plugins.Enabled && plugins != nil {
				if err := plugins.Reload(cfg.Plugins.Dir); err != nil {
					log.Warn("plugin reload failed", "err", err)
				} else {
					log.Info("plugins reloaded", "count", plugins.Len())
				}
			}
			continue
		}
		log.Info("shutting down")
		break
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = rest.Shutdown(ctx)
	if grpcSrv != nil {
		grpcSrv.Stop()
	}
	_ = dnsSrv.Shutdown()
}
