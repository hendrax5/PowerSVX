// Command powersvx is the hardened DNS resolver entrypoint.
//
// Performance Mode wires: SO_REUSEPORT UDP workers (recvmmsg/sendmmsg batch,
// IPv4+IPv6) -> RPZ (immutable) -> sharded cache (+prefetch) -> resolve via a
// health-checked upstream pool OR the built-in recursive engine, with
// low-cardinality metrics + latency histogram and async sampled logging.
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"powersvx/internal/cache"
	"powersvx/internal/config"
	"powersvx/internal/logx"
	"powersvx/internal/metrics"
	"powersvx/internal/recursive"
	"powersvx/internal/resolver"
	"powersvx/internal/rpz"
	"powersvx/internal/server"
	"powersvx/internal/upstream"
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
	backend := "forward"
	if cfg.Recursion {
		backend = "recursive"
	}
	log.Printf("powersvx starting mode=%s addr=%s workers=%d gomaxprocs=%d backend=%s dnssec=%v",
		cfg.Mode, cfg.Addr(), cfg.Workers, runtime.GOMAXPROCS(0), backend, cfg.DNSSEC)

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

	// Resolve backend: recursive (root hints) OR health-checked forwarding pool.
	var pool *upstream.Pool
	var rec *recursive.Recursive
	if cfg.Recursion {
		rec = recursive.New(3*time.Second, cfg.RecursionIPv6, m, cfg.DNSSECValidate)
		log.Printf("recursive engine enabled (ipv6=%v dnssec_validate=%v)", cfg.RecursionIPv6, cfg.DNSSECValidate)
	} else {
		if cfg.DNSSECValidate {
			log.Printf("WARNING: dnssec_validate requires recursion=true; ignoring in forward mode")
		}
		pool = upstream.New(cfg.Upstreams, 2*time.Second, cfg.Health.MaxFails,
			time.Duration(cfg.Health.ProbeIntervalSeconds)*time.Second, m)
		m.BindUpstreams(pool.Stats)
		log.Printf("forwarding pool: %v (max_fails=%d probe=%ds)",
			cfg.Upstreams, cfg.Health.MaxFails, cfg.Health.ProbeIntervalSeconds)
	}

	res := resolver.New(resolver.Options{
		Cache:      c,
		RPZ:        matcher,
		RPZOn:      cfg.RPZ.Enabled,
		Pool:       pool,
		Recursive:  rec,
		Metrics:    m,
		Logger:     lg,
		DNSSEC:     cfg.DNSSEC,
		ServeStale: cfg.Cache.ServeStale,
		ECSEnabled: cfg.ECS.Enabled,
		ECSV4:      uint8(cfg.ECS.V4Prefix),
		ECSV6:      uint8(cfg.ECS.V6Prefix),
	})
	if cfg.ECS.Enabled {
		log.Printf("EDNS Client Subnet enabled: v4/%d v6/%d", cfg.ECS.V4Prefix, cfg.ECS.V6Prefix)
	}

	if cfg.Cache.ServeStale {
		c.EnableServeStale(cfg.Cache.ServeStaleMaxSeconds, cfg.Cache.ServeStaleTTL)
		log.Printf("serve-stale enabled: max=%ds ttl=%ds", cfg.Cache.ServeStaleMaxSeconds, cfg.Cache.ServeStaleTTL)
	}

	if cfg.Cache.Prefetch {
		c.EnablePrefetch(cfg.Cache.PrefetchWindow, cfg.Cache.PrefetchMinHits, cfg.Cache.PrefetchWorkers, res.Prefetch)
		log.Printf("cache prefetch enabled: window=%ds min_hits=%d workers=%d",
			cfg.Cache.PrefetchWindow, cfg.Cache.PrefetchMinHits, cfg.Cache.PrefetchWorkers)
	}

	// Handler with optional latency observation (off the DNS wire path itself,
	// just a timestamp diff around the resolve).
	handler := res.Handle
	if cfg.Metrics.Enabled {
		inner := res.Handle
		handler = func(req *dns.Msg, ip net.IP) *dns.Msg {
			t0 := time.Now()
			resp := inner(req, ip)
			m.ObserveLatency(time.Since(t0))
			return resp
		}
	}

	if cfg.Metrics.Enabled {
		mux := http.NewServeMux()
		mux.Handle("/metrics", m.Handler())
		go func() { log.Println("metrics:", http.ListenAndServe(cfg.Metrics.Listen, mux)) }()
	}
	if cfg.Profiling.Enabled {
		runtime.SetMutexProfileFraction(5)
		runtime.SetBlockProfileRate(1000000)
		go func() { log.Println("pprof:", http.ListenAndServe(cfg.Profiling.Listen, nil)) }()
		log.Printf("pprof enabled at http://%s/debug/pprof/", cfg.Profiling.Listen)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv := server.New(cfg, handler, lg)
	if err := srv.Start(ctx); err != nil {
		log.Fatalf("server start: %v", err)
	}
	log.Printf("powersvx ready; rpz_rules=%d cache_shards=%d batch=%v", matcher.Count(), cfg.Cache.Shards, cfg.Socket.Batch)

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			log.Println("SIGHUP: reloading config + RPZ...")
			if err := reloadRPZ(matcher, cfg, rpzAction); err != nil {
				log.Printf("rpz reload failed (keeping old zone): %v", err)
			} else {
				log.Printf("rpz reloaded; rules=%d", matcher.Count())
			}
			// Hot-swap upstreams + TTL/serve-stale without a restart.
			if nc, err := config.Load(*cfgPath); err != nil {
				log.Printf("config reload failed: %v", err)
			} else {
				c.SetTTLCaps(nc.Cache.PositiveTTLMax, nc.Cache.NegativeTTLMax)
				if nc.Cache.ServeStale {
					c.EnableServeStale(nc.Cache.ServeStaleMaxSeconds, nc.Cache.ServeStaleTTL)
				}
				if pool != nil {
					pool.SetServers(nc.Upstreams)
					log.Printf("reloaded upstreams: %v", nc.Upstreams)
				}
				log.Printf("reloaded ttl caps: pos=%d neg=%d serve_stale=%v",
					nc.Cache.PositiveTTLMax, nc.Cache.NegativeTTLMax, nc.Cache.ServeStale)
			}
		}
	}()

	<-ctx.Done()
	log.Println("shutting down...")
	srv.Close()
	if pool != nil {
		pool.Close()
	}
	lg.Close()
}

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
