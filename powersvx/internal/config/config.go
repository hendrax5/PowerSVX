package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level runtime configuration. Performance Mode and General
// Mode share this struct but ship different YAML files (see config/*.yaml).
type Config struct {
	Mode       string          `yaml:"mode"` // "performance" | "general"
	Listen     string          `yaml:"listen"`
	Port       int             `yaml:"port"`
	Workers    int             `yaml:"workers"`     // UDP reuseport worker sockets
	GOMAXPROCS int             `yaml:"gomaxprocs"`  // 0 => runtime default (real cores)
	Upstreams  []string        `yaml:"upstreams"`
	Recursion  bool            `yaml:"recursion"`      // use built-in recursive engine instead of forwarding
	RecursionIPv6 bool         `yaml:"recursion_ipv6"` // allow IPv6 glue/roots in recursive mode
	DNSSECValidate bool        `yaml:"dnssec_validate"` // heavier mode: validate answers (recursive only)
	ECS        ECSConfig       `yaml:"ecs"`
	Health     HealthConfig    `yaml:"health"`
	Cache      CacheConfig     `yaml:"cache"`
	RPZ        RPZConfig       `yaml:"rpz"`
	Logging    LoggingConfig   `yaml:"logging"`
	Metrics    MetricsConfig   `yaml:"metrics"`
	DNSSEC     bool            `yaml:"dnssec"` // OFF in performance mode by design
	Socket     SocketConfig    `yaml:"socket"`
	Profiling  ProfilingConfig `yaml:"profiling"`
}

type CacheConfig struct {
	Shards          int  `yaml:"shards"`            // power of two recommended
	PerShardCap     int  `yaml:"per_shard_cap"`     // max entries per shard
	PositiveTTLMax  int  `yaml:"positive_ttl_max"`  // seconds, clamp
	NegativeTTLMax  int  `yaml:"negative_ttl_max"`  // seconds, clamp
	Prefetch        bool `yaml:"prefetch"`          // refresh hot entries before expiry
	PrefetchWindow  int  `yaml:"prefetch_window"`   // seconds-before-expiry to refresh
	PrefetchMinHits int  `yaml:"prefetch_min_hits"` // only prefetch "popular" entries
	PrefetchWorkers int  `yaml:"prefetch_workers"`  // background refresh goroutines
	ServeStale           bool `yaml:"serve_stale"`             // RFC 8767 serve-stale on upstream failure
	ServeStaleMaxSeconds int  `yaml:"serve_stale_max_seconds"` // retain expired entries this long
	ServeStaleTTL        int  `yaml:"serve_stale_ttl"`         // short TTL applied to stale answers
}

type ECSConfig struct {
	Enabled  bool `yaml:"enabled"`   // pass through / synthesize EDNS Client Subnet
	V4Prefix int  `yaml:"v4_prefix"` // source netmask for IPv4 clients (e.g. 24)
	V6Prefix int  `yaml:"v6_prefix"` // source netmask for IPv6 clients (e.g. 56)
}

type HealthConfig struct {
	MaxFails             int `yaml:"max_fails"`              // consecutive fails before marking an upstream down
	ProbeIntervalSeconds int `yaml:"probe_interval_seconds"` // background health-probe cadence
}

type RPZConfig struct {
	Enabled bool     `yaml:"enabled"`
	Files   []string `yaml:"files"`  // hosts-format or plain domain lists
	Action  string   `yaml:"action"` // nxdomain | nodata | drop
}

type LoggingConfig struct {
	Enabled    bool `yaml:"enabled"`     // OFF by default in performance mode
	SampleRate int  `yaml:"sample_rate"` // 1 => log all, N => log 1/N
	BufferSize int  `yaml:"buffer_size"` // bounded async queue; overflow => drop
}

type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"` // e.g. 127.0.0.1:9153, low-cardinality only
}

type SocketConfig struct {
	ReusePort bool `yaml:"reuseport"`
	RcvBuf    int  `yaml:"rcvbuf"`     // SO_RCVBUF bytes, 0 => kernel default
	SndBuf    int  `yaml:"sndbuf"`     // SO_SNDBUF bytes
	Batch     bool `yaml:"batch"`      // use recvmmsg/sendmmsg batch UDP path
	BatchSize int  `yaml:"batch_size"` // messages per syscall when batch=true
}

type ProfilingConfig struct {
	Enabled bool   `yaml:"enabled"` // exposes net/http/pprof (CPU/alloc/mutex/block)
	Listen  string `yaml:"listen"`  // e.g. 127.0.0.1:6060
}

// Load reads YAML and applies safe defaults for any unset fields.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	c := &Config{}
	if err := yaml.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.applyDefaults()
	return c, nil
}

func (c *Config) applyDefaults() {
	if c.Mode == "" {
		c.Mode = "performance"
	}
	if c.Listen == "" {
		c.Listen = "0.0.0.0"
	}
	if c.Port == 0 {
		c.Port = 53
	}
	if c.Workers == 0 {
		c.Workers = 2
	}
	if c.Socket.BatchSize == 0 {
		c.Socket.BatchSize = 16
	}
	if len(c.Upstreams) == 0 {
		c.Upstreams = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	if c.Health.MaxFails == 0 {
		c.Health.MaxFails = 3
	}
	if c.Health.ProbeIntervalSeconds == 0 {
		c.Health.ProbeIntervalSeconds = 10
	}
	if c.ECS.V4Prefix == 0 {
		c.ECS.V4Prefix = 24
	}
	if c.ECS.V6Prefix == 0 {
		c.ECS.V6Prefix = 56
	}
	if c.Cache.Shards == 0 {
		c.Cache.Shards = 256
	}
	if c.Cache.PerShardCap == 0 {
		c.Cache.PerShardCap = 20000
	}
	if c.Cache.PositiveTTLMax == 0 {
		c.Cache.PositiveTTLMax = 86400
	}
	if c.Cache.NegativeTTLMax == 0 {
		c.Cache.NegativeTTLMax = 900
	}
	if c.Cache.PrefetchWindow == 0 {
		c.Cache.PrefetchWindow = 30
	}
	if c.Cache.PrefetchMinHits == 0 {
		c.Cache.PrefetchMinHits = 5
	}
	if c.Cache.PrefetchWorkers == 0 {
		c.Cache.PrefetchWorkers = 2
	}
	if c.Cache.ServeStaleMaxSeconds == 0 {
		c.Cache.ServeStaleMaxSeconds = 86400
	}
	if c.Cache.ServeStaleTTL == 0 {
		c.Cache.ServeStaleTTL = 30
	}
	if c.RPZ.Action == "" {
		c.RPZ.Action = "nxdomain"
	}
	if c.Logging.SampleRate == 0 {
		c.Logging.SampleRate = 1000
	}
	if c.Logging.BufferSize == 0 {
		c.Logging.BufferSize = 8192
	}
	if c.Metrics.Listen == "" {
		c.Metrics.Listen = "127.0.0.1:9153"
	}
	if c.Profiling.Listen == "" {
		c.Profiling.Listen = "127.0.0.1:6060"
	}
}

func (c *Config) Addr() string {
	return fmt.Sprintf("%s:%d", c.Listen, c.Port)
}
