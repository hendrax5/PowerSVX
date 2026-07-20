package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Server       ServerConfig       `toml:"server"`
	Database     DatabaseConfig     `toml:"database"`
	Cache        CacheConfig        `toml:"cache"`
	Resolver     ResolverConfig     `toml:"resolver"`
	API          APIConfig          `toml:"api"`
	Logging      LoggingConfig      `toml:"logging"`
	RateLimit    RateLimitConfig    `toml:"rate_limit"`
	RPZ          RPZConfig          `toml:"rpz"`
	Metrics      MetricsConfig      `toml:"metrics"`
	TSIG         TSIGConfig         `toml:"tsig"`
	GeoDNS       GeoDNSConfig       `toml:"geodns"`
	SplitHorizon SplitHorizonConfig `toml:"split_horizon"`
}

type ServerConfig struct {
	BindAddress string    `toml:"bind_address"`
	UDPPort     int       `toml:"udp_port"`
	TCPPort     int       `toml:"tcp_port"`
	DoTPort     int       `toml:"dot_port"`
	DoHPort     int       `toml:"doh_port"`
	DoQPort     int       `toml:"doq_port"`
	Workers     int       `toml:"workers"`
	TLS         TLSConfig `toml:"tls"`
}

type TLSConfig struct {
	Enabled  bool   `toml:"enabled"`
	CertFile string `toml:"cert_file"`
	KeyFile  string `toml:"key_file"`
}

type DatabaseConfig struct {
	Type           string `toml:"type"`
	Host           string `toml:"host"`
	Port           int    `toml:"port"`
	Database       string `toml:"database"`
	User           string `toml:"user"`
	Password       string `toml:"password"`
	MaxConnections int    `toml:"max_connections"`
	Enabled        bool   `toml:"enabled"`
}

type CacheConfig struct {
	Type        string `toml:"type"`
	Path        string `toml:"path"`
	MaxSizeMB   int    `toml:"max_size_mb"`
	TTLSeconds  int    `toml:"ttl_seconds"`
	NegativeTTL int    `toml:"negative_ttl"`
}

type ResolverConfig struct {
	Mode              string   `toml:"mode"`
	Forwarders        []string `toml:"forwarders"`
	DNSSECValidation  bool     `toml:"dnssec_validation"`
	DNSSECMode        string   `toml:"dnssec_mode"`
	QNameMinimization bool     `toml:"qname_minimization"`
	EDNSBufferSize    uint16   `toml:"edns_buffer_size"`
	TimeoutMS         int      `toml:"timeout_ms"`
	ECSEnabled        bool     `toml:"ecs_enabled"`
	ECSPrefixV4       uint8    `toml:"ecs_prefix_v4"`
	ECSPrefixV6       uint8    `toml:"ecs_prefix_v6"`
}

type APIConfig struct {
	RESTEnabled bool   `toml:"rest_enabled"`
	RESTBind    string `toml:"rest_bind"`
	AuthType    string `toml:"auth_type"`
	APIToken    string `toml:"api_token"`
}

type LoggingConfig struct {
	Level                 string `toml:"level"`
	Format                string `toml:"format"`
	QueryLogEnabled       bool   `toml:"query_log_enabled"`
	QueryLogDestination   string `toml:"query_log_destination"`
	QueryLogRetentionDays int    `toml:"query_log_retention_days"`
}

type RateLimitConfig struct {
	Enabled       bool     `toml:"enabled"`
	DefaultQPS    int      `toml:"default_qps"`
	DefaultBurst  int      `toml:"default_burst"`
	BlockDuration int      `toml:"block_duration"`
	Whitelist     []string `toml:"whitelist"`
}

type RPZPolicyTOML struct {
	Name   string `toml:"name"`
	Source string `toml:"source"`
	Format string `toml:"format"`
	Action string `toml:"action"`
}

type RPZConfig struct {
	Enabled        bool            `toml:"enabled"`
	Policies       []RPZPolicyTOML `toml:"policies"`
	UpdateInterval int             `toml:"update_interval"`
}

type MetricsConfig struct {
	PrometheusEnabled bool   `toml:"prometheus_enabled"`
	PrometheusBind    string `toml:"prometheus_bind"`
}

type TSIGKeyTOML struct {
	Name   string `toml:"name"`
	Secret string `toml:"secret"`
}

type TSIGConfig struct {
	Enabled bool          `toml:"enabled"`
	Keys    []TSIGKeyTOML `toml:"keys"`
}

type GeoOverrideTOML struct {
	IP        string `toml:"ip"`
	Country   string `toml:"country"`
	Continent string `toml:"continent"`
	Tag       string `toml:"tag"`
}

type GeoDNSConfig struct {
	Enabled      bool              `toml:"enabled"`
	DatabasePath string            `toml:"database_path"`
	DefaultTag   string            `toml:"default_tag"`
	Overrides    []GeoOverrideTOML `toml:"overrides"`
}

type SplitViewTOML struct {
	Name     string   `toml:"name"`
	Networks []string `toml:"networks"`
}

type SplitHorizonConfig struct {
	Enabled bool            `toml:"enabled"`
	Views   []SplitViewTOML `toml:"views"`
}

func Default() *Config {
	return &Config{
		Server: ServerConfig{
			BindAddress: "0.0.0.0",
			UDPPort:     5353,
			TCPPort:     5353,
			DoTPort:     853,
			DoHPort:     8443,
			DoQPort:     784,
			Workers:     0,
			TLS: TLSConfig{
				Enabled:  false,
				CertFile: "./certs/fullchain.pem",
				KeyFile:  "./certs/privkey.pem",
			},
		},
		Database: DatabaseConfig{
			Type: "postgres", Host: "localhost", Port: 5432,
			Database: "PowerSVX", User: "PowerSVX", MaxConnections: 20,
		},
		Cache: CacheConfig{
			Type: "badger", Path: "./data/cache", MaxSizeMB: 512,
			TTLSeconds: 300, NegativeTTL: 60,
		},
		Resolver: ResolverConfig{
			Mode: "forward",
			Forwarders: []string{"1.1.1.1:53", "8.8.8.8:53"},
			DNSSECMode: "off", QNameMinimization: true,
			EDNSBufferSize: 1232, TimeoutMS: 3000,
			ECSEnabled: true, ECSPrefixV4: 24, ECSPrefixV6: 56,
		},
		API: APIConfig{RESTEnabled: true, RESTBind: "0.0.0.0:5380", AuthType: "none"},
		Logging: LoggingConfig{Level: "info", Format: "json"},
		RateLimit: RateLimitConfig{
			Enabled: false, DefaultQPS: 100, DefaultBurst: 200, BlockDuration: 300,
			Whitelist: []string{"127.0.0.1/32", "::1/128"},
		},
		RPZ: RPZConfig{Enabled: false, UpdateInterval: 3600},
		Metrics: MetricsConfig{
			PrometheusEnabled: true,
			PrometheusBind:    "0.0.0.0:9100",
		},
		TSIG: TSIGConfig{Enabled: false},
		GeoDNS: GeoDNSConfig{
			Enabled: false, DatabasePath: "./data/GeoLite2-City.mmdb", DefaultTag: "default",
		},
		SplitHorizon: SplitHorizonConfig{Enabled: false},
	}
}

func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	if _, err := toml.DecodeFile(path, cfg); err != nil {
		return nil, fmt.Errorf("load config %s: %w", path, err)
	}
	expandEnv(cfg)
	normalizeDNSSEC(cfg)
	return cfg, nil
}

func expandEnv(cfg *Config) {
	cfg.Database.Password = os.ExpandEnv(cfg.Database.Password)
	cfg.API.APIToken = os.ExpandEnv(cfg.API.APIToken)
	for i := range cfg.TSIG.Keys {
		cfg.TSIG.Keys[i].Secret = os.ExpandEnv(cfg.TSIG.Keys[i].Secret)
	}
}

func normalizeDNSSEC(cfg *Config) {
	mode := strings.ToLower(strings.TrimSpace(cfg.Resolver.DNSSECMode))
	if mode == "" {
		if cfg.Resolver.DNSSECValidation {
			mode = "validate"
		} else {
			mode = "off"
		}
	}
	if cfg.Resolver.DNSSECValidation && mode == "off" {
		mode = "validate"
	}
	cfg.Resolver.DNSSECMode = mode
	cfg.Resolver.DNSSECValidation = mode == "validate" || mode == "opportunistic"
}

func (c *Config) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		c.Database.Host, c.Database.Port, c.Database.User, c.Database.Password, c.Database.Database,
	)
}

func (c *Config) ListenAddr(port int) string {
	host := c.Server.BindAddress
	if host == "" {
		host = "0.0.0.0"
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func (c *Config) TLSEnabled() bool { return c.Server.TLS.Enabled }

func NormalizeName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return "."
	}
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}
