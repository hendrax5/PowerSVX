package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/powersvx/powersvx/internal/acme"
	"github.com/powersvx/powersvx/internal/analytics"
	"github.com/powersvx/powersvx/internal/anomaly"
	"github.com/powersvx/powersvx/internal/api"
	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/cache"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/database"
	"github.com/powersvx/powersvx/internal/dnssec"
	"github.com/powersvx/powersvx/internal/eventlog"
	"github.com/powersvx/powersvx/internal/geo"
	"github.com/powersvx/powersvx/internal/grpcapi"
	"github.com/powersvx/powersvx/internal/metrics"
	"github.com/powersvx/powersvx/internal/otelx"
	"github.com/powersvx/powersvx/internal/plugin"
	"github.com/powersvx/powersvx/internal/ratelimit"
	"github.com/powersvx/powersvx/internal/resolver"
	"github.com/powersvx/powersvx/internal/rpz"
	"github.com/powersvx/powersvx/internal/server"
	"github.com/powersvx/powersvx/internal/tlsutil"
	"github.com/powersvx/powersvx/internal/tsig"
	"github.com/powersvx/powersvx/internal/view"
)

func main() {
	cfgPath := flag.String("config", "configs/powersvx.toml", "path to TOML config")
	flag.Parse()

	bus := eventlog.New(200)
	log := slog.New(eventlog.NewHandler(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}), bus))

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Error("config load failed", "err", err)
		os.Exit(1)
	}
	if rs, err := config.LoadRuntimeSettings(config.RuntimeSettingsPath("./data")); err == nil {
		cfg.ApplyRuntimeSettings(rs)
		log.Info("runtime settings loaded", "path", config.RuntimeSettingsPath("./data"))
	}

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
	signer := dnssec.NewSigner("./data/dnssec")
	if cfg.API.AuthType == "token" && cfg.API.APIToken == "" {
		log.Error("api auth_type=token requires api_token (set API_TOKEN or config)")
		os.Exit(1)
	}
	limiter := ratelimit.New(cfg.RateLimit.Enabled, cfg.RateLimit.DefaultQPS, cfg.RateLimit.DefaultBurst, cfg.RateLimit.BlockDuration, cfg.RateLimit.Whitelist)

	rpzPath := config.RPZPoliciesPath("./data")
	if file, err := config.LoadRPZPoliciesFile(rpzPath); err == nil {
		cfg.RPZ.Policies = file.Policies
		if file.UpdateInterval > 0 {
			cfg.RPZ.UpdateInterval = file.UpdateInterval
		}
		log.Info("rpz policies loaded", "path", rpzPath, "count", len(file.Policies), "update_interval", cfg.RPZ.UpdateInterval)
	}

	rpzEng := rpz.New(cfg.RPZ.Enabled)
	if err := rpzEng.OpenDisk("./data/rpz-store"); err != nil {
		log.Warn("rpz disk store unavailable", "err", err)
	}
	defer func() { _ = rpzEng.Close() }()

	var policies []rpz.PolicyConfig
	for _, p := range cfg.RPZ.Policies {
		policies = append(policies, rpz.PolicyConfig{
			Name: p.Name, Source: p.Source, Format: p.Format, Action: rpz.Action(p.Action),
		})
	}
	if len(policies) > 0 {
		if ok, n, err := rpzEng.TryLoadDisk(policies); err != nil {
			log.Warn("rpz disk load failed", "err", err)
		} else if ok {
			log.Info("rpz loaded from disk", "entries", n)
		} else if rpzEng.TryBeginLoad() {
			// Large HTTP feeds must not block API/DNS bind.
			go func() {
				n, err := rpzEng.LoadPolicies(policies, 15*time.Minute)
				rpzEng.EndLoad(err)
				if err != nil {
					log.Warn("rpz load failed", "err", err)
					return
				}
				log.Info("rpz loaded", "entries", n)
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
			log.Error("tls load failed", "err", err)
			os.Exit(1)
		}
		log.Info("TLS enabled", "cert", cfg.Server.TLS.CertFile)
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
		Limiter: limiter, RPZ: rpzEng, TSIG: tsigStore,
		Views: views, Geo: geoRes, TLS: tlsCfg, Events: bus,
		ACME: acmeStore, Stats: stats, Anomaly: anom, Plugins: plugins, QLog: qlog,
	}, log)

	rest := api.New(cfg, dnsSrv, db, tier, auth, log)
	rest.SetEvents(bus)
	rest.SetACME(acmeMgr)
	rest.StartRPZAutoUpdate()
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
		grpcSrv, err = grpcapi.Start(cfg.API.GRPCBind, dnsSrv, log)
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

	log.Info("PowerSVX started",
		"version", api.Version,
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
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	log.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = rest.Shutdown(ctx)
	if grpcSrv != nil {
		grpcSrv.Stop()
	}
	_ = dnsSrv.Shutdown()
}
