package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Server   ServerConfig   `toml:"server"`
	Database DatabaseConfig `toml:"database"`
	Cache    CacheConfig    `toml:"cache"`
	Resolver ResolverConfig `toml:"resolver"`
	API      APIConfig      `toml:"api"`
	Logging  LoggingConfig  `toml:"logging"`
}

type ServerConfig struct {
	BindAddress string    `toml:"bind_address"`
	UDPPort     int       `toml:"udp_port"`
	TCPPort     int       `toml:"tcp_port"`
	DoTPort     int       `toml:"dot_port"`
	DoHPort     int       `toml:"doh_port"`
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
	Mode              string   `toml:"mode"` // recursive | forward
	Forwarders        []string `toml:"forwarders"`
	DNSSECValidation  bool     `toml:"dnssec_validation"`
	DNSSECMode        string   `toml:"dnssec_mode"` // off | validate | opportunistic
	QNameMinimization bool     `toml:"qname_minimization"`
	EDNSBufferSize    uint16   `toml:"edns_buffer_size"`
	TimeoutMS         int      `toml:"timeout_ms"`
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

func Default() *Config {
	return &Config{
		Server: ServerConfig{
			BindAddress: "0.0.0.0",
			UDPPort:     5353,
			TCPPort:     5353,
			DoTPort:     853,
			DoHPort:     8443,
			Workers:     0,
			TLS: TLSConfig{
				Enabled:  false,
				CertFile: "./certs/fullchain.pem",
				KeyFile:  "./certs/privkey.pem",
			},
		},
		Database: DatabaseConfig{
			Type:           "postgres",
			Host:           "localhost",
			Port:           5432,
			Database:       "PowerSVX",
			User:           "PowerSVX",
			Password:       "",
			MaxConnections: 20,
			Enabled:        false,
		},
		Cache: CacheConfig{
			Type:        "badger",
			Path:        "./data/cache",
			MaxSizeMB:   512,
			TTLSeconds:  300,
			NegativeTTL: 60,
		},
		Resolver: ResolverConfig{
			Mode:              "forward",
			Forwarders:        []string{"1.1.1.1:53", "8.8.8.8:53"},
			DNSSECValidation:  false,
			DNSSECMode:        "off",
			QNameMinimization: true,
			EDNSBufferSize:    1232,
			TimeoutMS:         3000,
		},
		API: APIConfig{
			RESTEnabled: true,
			RESTBind:    "0.0.0.0:5380",
			AuthType:    "none",
		},
		Logging: LoggingConfig{
			Level:                 "info",
			Format:                "json",
			QueryLogEnabled:       false,
			QueryLogDestination:   "postgresql",
			QueryLogRetentionDays: 30,
		},
	}
}

func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	meta, err := toml.DecodeFile(path, cfg)
	if err != nil {
		return nil, fmt.Errorf("load config %s: %w", path, err)
	}
	_ = meta
	expandEnv(cfg)
	normalizeDNSSEC(cfg)
	return cfg, nil
}

func expandEnv(cfg *Config) {
	cfg.Database.Password = os.ExpandEnv(cfg.Database.Password)
	cfg.API.APIToken = os.ExpandEnv(cfg.API.APIToken)
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
	pw := c.Database.Password
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		c.Database.Host, c.Database.Port, c.Database.User, pw, c.Database.Database,
	)
}

func (c *Config) ListenAddr(port int) string {
	host := c.Server.BindAddress
	if host == "" {
		host = "0.0.0.0"
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func (c *Config) TLSEnabled() bool {
	return c.Server.TLS.Enabled
}

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
