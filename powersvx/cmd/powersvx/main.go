// Command powersvx is the hardened DNS resolver entrypoint.
//
// Performance Mode wires: SO_REUSEPORT UDP workers -> RPZ (immutable) -> sharded
// cache -> singleflight upstream forwarding, with low-cardinality metrics and
// async sampled logging. pprof (CPU/alloc/mutex/block) is available when
// profiling is enabled (Phase 1 baseline/isolation).
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"powersvx/internal/cache"
	"powersvx/internal/config"
	"powersvx/internal/logx"
	"powersvx/internal/metrics"
	"powersvx/internal/resolver"
	"powersvx/internal/rpz"
	"powersvx/internal/server"
)

func main() {
	cfgPath := flag.String("config", "config/performance.yaml", "path to config YAML")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	if cfg.GOMAXPROCS > 0 {
		runtime.GOMAXPROCS(cfg.GOMAXPROCS)
	}
	log.Printf("powersvx starting mode=%s addr=%s workers=%d gomaxprocs=%d dnssec=%v",
		cfg.Mode, cfg.Addr(), cfg.Workers, runtime.GOMAXPROCS(0), cfg.DNSSEC)

	// --- RPZ matcher (immutable + atomic swap on SIGHUP) ---
	matcher := rpz.NewMatcher()
	rpzAction := rpz.ParseAction(cfg.RPZ.Action)
	if cfg.RPZ.Enabled && len(cfg.RPZ.Files) > 0 {
		if err := reloadRPZ(matcher, cfg, rpzAction); err != nil {
			log.Printf("rpz load warning: %v", err)
		}
	}

	c := cache.New(cfg.Cache.Shards, cfg.Cache.PerShardCap, cfg.Cache.PositiveTTLMax, cfg.Cache.NegativeTTLMax)
	m := metrics.New(cfg.Metrics.Enabled)
	lg := logx.New(cfg.Logging.Enabled, cfg.Logging.SampleRate, cfg.Logging.BufferSize)
	m.BindLogsDropped(lg.Dropped)

	res := resolver.New(resolver.Options{
		Cache:     c,
		RPZ:       matcher,
		RPZOn:     cfg.RPZ.Enabled,
		Upstreams: cfg.Upstreams,
		Metrics:   m,
		Logger:    lg,
		DNSSEC:    cfg.DNSSEC,
		Timeout:   2 * time.Second,
	})

	// --- Observability endpoints (kept OFF the DNS hot path) ---
	if cfg.Metrics.Enabled {
		mux := http.NewServeMux()
		mux.Handle("/metrics", m.Handler())
		go func() { log.Println("metrics:", http.ListenAndServe(cfg.Metrics.Listen, mux)) }()
	}
	if cfg.Profiling.Enabled {
		// Enable mutex/block profiling so Phase 1 can attribute contention.
		runtime.SetMutexProfileFraction(5)
		runtime.SetBlockProfileRate(1000000) // ~1 sample/ms of blocking
		go func() { log.Println("pprof:", http.ListenAndServe(cfg.Profiling.Listen, nil)) }()
		log.Printf("pprof enabled at http://%s/debug/pprof/", cfg.Profiling.Listen)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv := server.New(cfg, res.Handle, lg)
	if err := srv.Start(ctx); err != nil {
		log.Fatalf("server start: %v", err)
	}
	log.Printf("powersvx ready; rpz_rules=%d cache_shards=%d", matcher.Count(), cfg.Cache.Shards)

	// SIGHUP => rebuild RPZ off-path and atomic-swap.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			log.Println("SIGHUP: rebuilding RPZ snapshot...")
			if err := reloadRPZ(matcher, cfg, rpzAction); err != nil {
				log.Printf("rpz reload failed (keeping old zone): %v", err)
			} else {
				log.Printf("rpz reloaded; rules=%d", matcher.Count())
			}
		}
	}()

	<-ctx.Done()
	log.Println("shutting down...")
	srv.Close()
	lg.Close()
}

// reloadRPZ builds a fresh immutable Zone and atomically swaps it in. The active
// zone keeps serving until the swap completes, so daily updates never mutate a
// structure that is in use (Phase 3 design decision).
func reloadRPZ(m *rpz.Matcher, cfg *config.Config, action rpz.Action) error {
	start := time.Now()
	z, err := rpz.LoadFiles(cfg.RPZ.Files, action)
	if err != nil {
		return err
	}
	m.Swap(z)
	log.Printf("rpz build: %d rules in %s", z.Count(), time.Since(start))
	return nil
}
