package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/powersvx/powersvx/internal/api"
	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/cache"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/database"
	"github.com/powersvx/powersvx/internal/dnssec"
	"github.com/powersvx/powersvx/internal/resolver"
	"github.com/powersvx/powersvx/internal/server"
	"github.com/powersvx/powersvx/internal/tlsutil"
)

func main() {
	cfgPath := flag.String("config", "configs/powersvx.toml", "path to TOML config")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Error("config load failed", "err", err)
		os.Exit(1)
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
	tier := cache.NewTier(
		l1, l2,
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

	secMode := dnssec.ParseMode(cfg.Resolver.DNSSECMode, cfg.Resolver.DNSSECValidation)
	sec := dnssec.New(secMode)

	var tlsCfg *tls.Config
	if cfg.TLSEnabled() {
		tlsCfg, err = tlsutil.LoadServerTLS(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
		if err != nil {
			log.Error("tls load failed", "err", err)
			os.Exit(1)
		}
		log.Info("TLS enabled for DoT/DoH", "cert", cfg.Server.TLS.CertFile)
	}

	res := resolver.New(cfg.Resolver)
	dnsSrv := server.New(cfg, tier, res, auth, sec, tlsCfg, log)
	rest := api.New(cfg, dnsSrv, db, tier, auth, log)
	if err := rest.Start(); err != nil {
		log.Error("api start failed", "err", err)
		os.Exit(1)
	}

	go func() {
		if err := dnsSrv.ListenAndServe(); err != nil {
			log.Error("dns server stopped", "err", err)
			os.Exit(1)
		}
	}()

	log.Info("PowerSVX Phase 2 started",
		"udp", cfg.ListenAddr(cfg.Server.UDPPort),
		"mode", cfg.Resolver.Mode,
		"dnssec", string(secMode),
		"dot", cfg.TLSEnabled(),
		"doh", cfg.TLSEnabled(),
		"api", cfg.API.RESTBind,
	)

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	log.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = rest.Shutdown(ctx)
	_ = dnsSrv.Shutdown()
}
