package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
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
	Transfer     TransferConfig     `toml:"transfer"`
	ACL          ACLConfig          `toml:"acl"`
	GeoDNS       GeoDNSConfig       `toml:"geodns"`
	SplitHorizon SplitHorizonConfig `toml:"split_horizon"`
	ACME         ACMEConfig         `toml:"acme"`
	Plugins      PluginsConfig      `toml:"plugins"`
}

// ACLConfig controls which clients may send DNS queries.
// Empty AllowQuery = allow all. DenyQuery always wins over allow.
type ACLConfig struct {
	AllowQuery []string `toml:"allow_query" json:"allow_query"`
	DenyQuery  []string `toml:"deny_query" json:"deny_query"`
}

type ServerConfig struct {
	BindAddress string    `toml:"bind_address"`
	UDPPort     int       `toml:"udp_port"`
	TCPPort     int       `toml:"tcp_port"`
	DoTPort     int       `toml:"dot_port"`
	DoHPort     int       `toml:"doh_port"`
	DoQPort     int       `toml:"doq_port"`
	Workers     int       `toml:"workers"`
	// TProxy enables IP_TRANSPARENT on UDP/TCP DNS sockets (Linux only).
	// Needed for nftables/iptables TPROXY where the packet destination stays
	// non-local (e.g. 8.8.8.8). Not required for MikroTik/iptables DNAT.
	TProxy      bool      `toml:"tproxy"`
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
	RootHintsFile     string   `toml:"root_hints_file"`
	// ForwardOnFail: when mode=recursive, fall back to forwarders if root iteration fails.
	ForwardOnFail     bool     `toml:"forward_on_fail"`
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
	GRPCEnabled bool   `toml:"grpc_enabled"`
	GRPCBind    string `toml:"grpc_bind"`
	AuthType    string `toml:"auth_type"` // none | token | local
	APIToken    string `toml:"api_token"`
	// SessionSecret signs/stores local-auth sessions (env SESSION_SECRET).
	SessionSecret string `toml:"session_secret"`
	// Tokens is optional multi-token RBAC: name -> {token, role}.
	// Roles: admin (full), readonly (GET only), operator (no backup restore / no settings write).
	Tokens []APITokenTOML `toml:"tokens"`
	// Users is optional local username/password accounts (auth_type=local).
	Users []APIUserTOML `toml:"users"`
}

type APITokenTOML struct {
	Name  string `toml:"name" json:"name"`
	Token string `toml:"token" json:"token"`
	Role  string `toml:"role" json:"role"` // admin|operator|readonly
}

type APIUserTOML struct {
	Name         string `toml:"name" json:"name"`
	PasswordHash string `toml:"password_hash" json:"password_hash"`
	Role         string `toml:"role" json:"role"` // admin|operator|readonly
}

type TransferConfig struct {
	// AllowAXFR enables zone transfers (AXFR; IXFR falls back to AXFR).
	AllowAXFR bool `toml:"allow_axfr"`
	// RequireTSIG requires a valid TSIG on AXFR/IXFR when true.
	RequireTSIG bool `toml:"require_tsig"`
	// Notify lists secondary addresses (host:port) to NOTIFY after zone changes.
	Notify []string `toml:"notify"`
	// AllowFrom CIDRs allowed to request AXFR (empty = any if AllowAXFR).
	AllowFrom []string `toml:"allow_from"`
}

type LoggingConfig struct {
	Level                 string `toml:"level"`
	Format                string `toml:"format"`
	QueryLogEnabled       bool   `toml:"query_log_enabled"`
	QueryLogDestination   string `toml:"query_log_destination"`
	QueryLogRetentionDays int    `toml:"query_log_retention_days"`
	// QueryLogMaskIP truncates client IPs before storage (/24 IPv4, /48 IPv6).
	QueryLogMaskIP bool `toml:"query_log_mask_ip"`
}

type RateLimitConfig struct {
	Enabled       bool     `toml:"enabled"`
	DefaultQPS    int      `toml:"default_qps"`
	DefaultBurst  int      `toml:"default_burst"`
	BlockDuration int      `toml:"block_duration"`
	Whitelist     []string `toml:"whitelist"`
}

type RPZPolicyTOML struct {
	Name   string `toml:"name" json:"name"`
	Source string `toml:"source" json:"source"`
	Format string `toml:"format" json:"format"`
	Action string `toml:"action" json:"action"`
	// Target: IP for redirect, hostname for cname.
	Target string `toml:"target" json:"target,omitempty"`
}

type RPZConfig struct {
	Enabled        bool            `toml:"enabled"`
	Policies       []RPZPolicyTOML `toml:"policies"`
	UpdateInterval int             `toml:"update_interval"`
}

type MetricsConfig struct {
	PrometheusEnabled bool   `toml:"prometheus_enabled"`
	PrometheusBind    string `toml:"prometheus_bind"`
	OTelEnabled       bool   `toml:"otel_enabled"`
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

type ACMEConfig struct {
	Enabled    bool     `toml:"enabled"`
	Staging    bool     `toml:"staging"`
	Email      string   `toml:"email"`
	Domains    []string `toml:"domains"`
	StorageDir string   `toml:"storage_dir"`
}

type PluginsConfig struct {
	Enabled bool   `toml:"enabled"`
	Dir     string `toml:"dir"`
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
			Mode: "recursive",
			Forwarders: []string{"1.1.1.1:53", "8.8.8.8:53"},
			ForwardOnFail: true,
			DNSSECMode: "off", QNameMinimization: true,
			EDNSBufferSize: 1232, TimeoutMS: 3000,
			ECSEnabled: true, ECSPrefixV4: 24, ECSPrefixV6: 56,
		},
		API: APIConfig{RESTEnabled: true, RESTBind: "0.0.0.0:5380", GRPCEnabled: false, GRPCBind: "0.0.0.0:5381", AuthType: "none"},
		Logging: LoggingConfig{
			Level: "info", Format: "json", QueryLogEnabled: false,
			QueryLogDestination: "postgresql", QueryLogRetentionDays: 30, QueryLogMaskIP: true,
		},
		RateLimit: RateLimitConfig{
			Enabled: false, DefaultQPS: 100, DefaultBurst: 200, BlockDuration: 300,
			Whitelist: []string{"127.0.0.1/32", "::1/128"},
		},
		RPZ: RPZConfig{Enabled: false, UpdateInterval: 3600},
		Metrics: MetricsConfig{
			PrometheusEnabled: true,
			PrometheusBind:    "0.0.0.0:9100",
		},
		TSIG:     TSIGConfig{Enabled: false},
		Transfer: TransferConfig{AllowAXFR: false, RequireTSIG: true},
		ACL:      ACLConfig{},
		GeoDNS: GeoDNSConfig{
			Enabled: false, DatabasePath: "./data/GeoLite2-City.mmdb", DefaultTag: "default",
		},
		SplitHorizon: SplitHorizonConfig{Enabled: false},
		ACME: ACMEConfig{
			Enabled: false, Staging: true, StorageDir: "./certs/acme",
		},
		Plugins: PluginsConfig{Enabled: false, Dir: "./plugins"},
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
	cfg.API.SessionSecret = os.ExpandEnv(cfg.API.SessionSecret)
	for i := range cfg.API.Tokens {
		cfg.API.Tokens[i].Token = os.ExpandEnv(cfg.API.Tokens[i].Token)
	}
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

// NormalizeResolverMode returns "recursive" or "forward".
func NormalizeResolverMode(mode string) string {
	if strings.EqualFold(strings.TrimSpace(mode), "forward") {
		return "forward"
	}
	return "recursive"
}

// NormalizeForwarder accepts "1.1.1.1", "1.1.1.1:53", or "[::1]:53" and returns host:port.
func NormalizeForwarder(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("empty forwarder")
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		host, port = s, "53"
	}
	if port == "" {
		port = "53"
	}
	if _, err := strconv.Atoi(port); err != nil {
		return "", fmt.Errorf("invalid forwarder port %q", port)
	}
	if ip := net.ParseIP(host); ip == nil {
		// allow hostnames
		if host == "" || strings.ContainsAny(host, " \t") {
			return "", fmt.Errorf("invalid forwarder host %q", host)
		}
	}
	return net.JoinHostPort(host, port), nil
}

// NormalizeForwarders validates and normalizes a forwarder list (deduped, order kept).
func NormalizeForwarders(in []string) ([]string, error) {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		addr, err := NormalizeForwarder(raw)
		if err != nil {
			return nil, err
		}
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	return out, nil
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
