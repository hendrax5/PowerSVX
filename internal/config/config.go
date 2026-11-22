package config

import (
	"fmt"
	"net"
	"net/url"
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
	Update       UpdateConfig       `toml:"update"`
	KominfoSync  KominfoSyncConfig  `toml:"kominfo_sync"`
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
	// DenyAutobanThreshold: ACL-deny count per IP within DenyAutobanWindowSec
	// before silent-drop (+ optional nft DROP). 0 = disable autoban.
	DenyAutobanThreshold int `toml:"deny_autoban_threshold" json:"deny_autoban_threshold"`
	DenyAutobanWindowSec int `toml:"deny_autoban_window_sec" json:"deny_autoban_window_sec"`
	DenyAutobanTTLSec    int `toml:"deny_autoban_ttl_sec" json:"deny_autoban_ttl_sec"`
	// DenyAutobanNFT installs nftables set drop for banned sources (needs nft + NET_ADMIN).
	DenyAutobanNFT bool `toml:"deny_autoban_nft" json:"deny_autoban_nft"`
}

type ServerConfig struct {
	BindAddress string `toml:"bind_address"`
	UDPPort     int    `toml:"udp_port"`
	TCPPort     int    `toml:"tcp_port"`
	DoTPort     int    `toml:"dot_port"`
	DoHPort     int    `toml:"doh_port"`
	DoQPort     int    `toml:"doq_port"`
	Workers     int    `toml:"workers"`
	// TProxy enables IP_TRANSPARENT on UDP/TCP DNS sockets (Linux only).
	// Needed for nftables/iptables TPROXY where the packet destination stays
	// non-local (e.g. 8.8.8.8). Not required for MikroTik/iptables DNAT.
	TProxy bool      `toml:"tproxy"`
	TLS    TLSConfig `toml:"tls"`
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
	Type       string `toml:"type"`
	Path       string `toml:"path"`
	MaxSizeMB  int    `toml:"max_size_mb"`
	TTLSeconds int    `toml:"ttl_seconds"`
	// MinTTL floors positive-answer cache lifetime (0 = honor upstream TTL only).
	MinTTL      int `toml:"min_ttl"`
	NegativeTTL int `toml:"negative_ttl"`
	// ServeStale answers briefly past Expiry while a background refresh runs.
	ServeStale bool `toml:"serve_stale"`
	// StaleTTL seconds past Expiry that stale answers may still be served (0 = 60 when ServeStale).
	StaleTTL int `toml:"stale_ttl"`
	// PrefetchPct triggers async refresh when remaining fresh TTL is below this % (0 = off).
	PrefetchPct int `toml:"prefetch_pct"`
}

type ResolverConfig struct {
	Mode       string   `toml:"mode"`
	Forwarders []string `toml:"forwarders"`
	// ForwardZones routes queries for matching domains to specific upstreams
	// (longest-suffix match). Checked before recursion and before global forwarders.
	ForwardZones  []ForwardZoneConfig `toml:"forward_zones"`
	RootHintsFile string              `toml:"root_hints_file"`
	// ForwardOnFail: when mode=recursive, fall back to forwarders if root iteration fails.
	ForwardOnFail     bool   `toml:"forward_on_fail"`
	DNSSECValidation  bool   `toml:"dnssec_validation"`
	DNSSECMode        string `toml:"dnssec_mode"`
	QNameMinimization bool   `toml:"qname_minimization"`
	EDNSBufferSize    uint16 `toml:"edns_buffer_size"`
	TimeoutMS         int    `toml:"timeout_ms"`
	// MaxInflight caps concurrent recursive/forward resolves (0 = Autosize from CPU).
	MaxInflight int `toml:"max_inflight"`
	// FallbackTimeoutMS is the short budget for forward_on_fail after recursive fails (0 = auto ~20% of TimeoutMS, capped 500ms).
	FallbackTimeoutMS int   `toml:"fallback_timeout_ms"`
	ECSEnabled        bool  `toml:"ecs_enabled"`
	ECSPrefixV4       uint8 `toml:"ecs_prefix_v4"`
	ECSPrefixV6       uint8 `toml:"ecs_prefix_v6"`
}

// ForwardZoneConfig is a conditional/stub forwarder for a domain suffix.
type ForwardZoneConfig struct {
	Zone       string   `toml:"zone" json:"zone"`
	Forwarders []string `toml:"forwarders" json:"forwarders"`
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

// KominfoSyncConfig controls automatic NOTIFY/AXFR sync to Kominfo secondaries.
type KominfoSyncConfig struct {
	// Enabled default is false; UI/runtime can turn on without restart.
	Enabled bool `toml:"enabled"`
	// Targets override the built-in Kominfo secondary IPs (host or host:port).
	Targets []string `toml:"targets"`
}

// UpdateConfig controls RFC 2136 dynamic DNS updates.
type UpdateConfig struct {
	// Enabled turns on OpcodeUpdate handling (default false).
	Enabled bool `toml:"enabled"`
	// RequireTSIG requires a valid TSIG on UPDATE when true.
	RequireTSIG bool `toml:"require_tsig"`
	// AllowFrom CIDRs allowed to send UPDATE (empty = any if Enabled).
	AllowFrom []string `toml:"allow_from"`
	// Policies optionally restrict which TSIG key may update which zones.
	// Empty policies = any configured TSIG key may update any zone (when RequireTSIG).
	Policies []UpdatePolicyTOML `toml:"policies"`
}

// UpdatePolicyTOML maps a TSIG key to zones it may update.
type UpdatePolicyTOML struct {
	Key   string   `toml:"key" json:"key"`     // TSIG key name
	Zones []string `toml:"zones" json:"zones"` // empty = all zones
}

type LoggingConfig struct {
	Level                 string `toml:"level"`
	Format                string `toml:"format"`
	QueryLogEnabled       bool   `toml:"query_log_enabled"`
	QueryLogDestination   string `toml:"query_log_destination"`
	QueryLogRetentionDays int    `toml:"query_log_retention_days"`
	// QueryLogMaxSizeMB hard-caps query_logs on-disk size (table+indexes). 0 = no size cap.
	// Oldest rows are deleted first when over the limit. Recommended 1024–5120 on small VPS.
	QueryLogMaxSizeMB int `toml:"query_log_max_size_mb"`
	// QueryLogMaskIP truncates client IPs before storage (/24 IPv4, /48 IPv6).
	QueryLogMaskIP bool `toml:"query_log_mask_ip"`
	// QueryLogSampleRate keeps this fraction of query logs (1.0 = all, 0.05 = 5%). 0 = all when logging enabled.
	QueryLogSampleRate float64 `toml:"query_log_sample_rate"`
}

type RateLimitConfig struct {
	Enabled       bool     `toml:"enabled"`
	DefaultQPS    int      `toml:"default_qps"`
	DefaultBurst  int      `toml:"default_burst"`
	BlockDuration int      `toml:"block_duration"`
	Whitelist     []string `toml:"whitelist"`
	// GlobalQPS soft-caps total accepted QPS across all clients (0 = off).
	GlobalQPS int `toml:"global_qps"`
	// GlobalBurst token burst for the global bucket (0 = same as GlobalQPS).
	GlobalBurst int `toml:"global_burst"`
}

type RPZPolicyTOML struct {
	Name   string `toml:"name" json:"name"`
	Source string `toml:"source" json:"source"`
	Format string `toml:"format" json:"format"` // hosts | axfr
	Action string `toml:"action" json:"action"`
	// Target: IP for redirect, hostname for cname.
	Target string `toml:"target" json:"target,omitempty"`
	// Zone + Masters are used when Format is "axfr" (PowerSVX as slave; names → RPZ).
	Zone    string   `toml:"zone" json:"zone,omitempty"`
	Masters []string `toml:"masters" json:"masters,omitempty"`
	TSIGKey string   `toml:"tsig_key" json:"tsig_key,omitempty"`
	// Enabled: nil/omitted = on (backward compatible); false = skip sync for this feed.
	Enabled *bool `toml:"enabled,omitempty" json:"enabled,omitempty"`
}

type RPZConfig struct {
	Enabled        bool            `toml:"enabled"`
	Policies       []RPZPolicyTOML `toml:"policies"`
	UpdateInterval int             `toml:"update_interval"` // hosts feeds; seconds; 0 = off
	// UpdateAt is local wall clock "HH:MM" for hosts auto-refresh (e.g. "04:00").
	// When set and UpdateInterval > 0, reloads run at that time each day (TZ from process).
	UpdateAt string `toml:"update_at"`
	// AxfrUpdateInterval is the refresh cadence for format=axfr feeds (seconds; 0 = off).
	// Independent of UpdateInterval. Default 86400 (24h).
	AxfrUpdateInterval int `toml:"axfr_update_interval"`
	// HotCacheMax is max exact RPZ hits kept in RAM in cold/disk mode (0 = default 500k).
	HotCacheMax int `toml:"hot_cache_max"`
	// HotSeedTopN periodically seeds the RPZ hot cache from the top blocked qnames (0 = off).
	HotSeedTopN int `toml:"hot_seed_top_n"`
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
			BindAddress: "127.0.0.1", // the Auth Backend is reached only by the local Dataplane
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
			TTLSeconds: 300, MinTTL: 120, NegativeTTL: 60,
			ServeStale: true, StaleTTL: 60, PrefetchPct: 10,
		},
		Resolver: ResolverConfig{
			// Default: Unbound hybrid (loopback). Host compose starts Unbound on :5353.
			Mode:          "forward",
			Forwarders:    []string{"127.0.0.1:5353"},
			ForwardOnFail: false,
			DNSSECMode:    "off", QNameMinimization: true,
			EDNSBufferSize: 1232, TimeoutMS: 3000,
			MaxInflight: 1024, FallbackTimeoutMS: 400,
			ECSEnabled: true, ECSPrefixV4: 24, ECSPrefixV6: 56,
		},
		API: APIConfig{RESTEnabled: true, RESTBind: "0.0.0.0:5380", GRPCEnabled: false, GRPCBind: "0.0.0.0:5381", AuthType: "none"},
		Logging: LoggingConfig{
			Level: "info", Format: "json", QueryLogEnabled: false,
			QueryLogDestination: "postgresql", QueryLogRetentionDays: 30,
			QueryLogMaxSizeMB: 5120, QueryLogMaskIP: true, QueryLogSampleRate: 0.05,
		},
		RateLimit: RateLimitConfig{
			Enabled: false, DefaultQPS: 100, DefaultBurst: 200, BlockDuration: 300,
			Whitelist: []string{"127.0.0.1/32", "::1/128"},
			GlobalQPS: 7500, GlobalBurst: 2000,
		},
		RPZ: RPZConfig{Enabled: false, UpdateInterval: 3600, AxfrUpdateInterval: 86400},
		Metrics: MetricsConfig{
			PrometheusEnabled: true,
			PrometheusBind:    "0.0.0.0:9100",
		},
		TSIG:        TSIGConfig{Enabled: false},
		Transfer:    TransferConfig{AllowAXFR: false, RequireTSIG: true},
		Update:      UpdateConfig{Enabled: false, RequireTSIG: true},
		KominfoSync: KominfoSyncConfig{Enabled: false},
		ACL:         ACLConfig{},
		GeoDNS: GeoDNSConfig{
			Enabled: false, DatabasePath: "./data/dbip-country-lite.mmdb", DefaultTag: "default",
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
		normalizeResolverBuffers(cfg)
		return cfg, nil
	}
	if _, err := toml.DecodeFile(path, cfg); err != nil {
		return nil, fmt.Errorf("load config %s: %w", path, err)
	}
	expandEnv(cfg)
	normalizeDNSSEC(cfg)
	normalizeResolverBuffers(cfg)
	return cfg, nil
}

// EDNSBufferMin/Max follow RFC 6891 practice: 1232 is the IPv6-safe path MTU
// advertisement; 4096 is an upper bound for large DNSSEC replies before TCP.
const (
	EDNSBufferMin uint16 = 1232
	EDNSBufferMax uint16 = 4096
)

// NormalizeEDNSBufferSize clamps to [1232, 4096]. Zero → 1232.
// 1232 is the RFC 6891 IPv6-safe path size; 4096 allows larger DNSSEC replies.
func NormalizeEDNSBufferSize(size uint16) uint16 {
	if size == 0 || size < EDNSBufferMin {
		return EDNSBufferMin
	}
	if size > EDNSBufferMax {
		return EDNSBufferMax
	}
	return size
}

func normalizeResolverBuffers(cfg *Config) {
	if cfg == nil {
		return
	}
	cfg.Resolver.EDNSBufferSize = NormalizeEDNSBufferSize(cfg.Resolver.EDNSBufferSize)
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
// Empty / unknown defaults to forward (Unbound hybrid is the production default).
func NormalizeResolverMode(mode string) string {
	if strings.EqualFold(strings.TrimSpace(mode), "recursive") {
		return "recursive"
	}
	return "forward"
}

// NormalizeForwarder accepts:
//   - "1.1.1.1", "1.1.1.1:53", "[::1]:53" → UDP host:port
//   - "tls://host:853" or "tls://1.1.1.1:853#sni.example.com" → DoT
//   - "https://host/dns-query" → DoH
func NormalizeForwarder(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("empty forwarder")
	}
	lower := strings.ToLower(s)
	switch {
	case strings.HasPrefix(lower, "https://"), strings.HasPrefix(lower, "http://"):
		u, err := url.Parse(s)
		if err != nil || u.Host == "" {
			return "", fmt.Errorf("invalid doh forwarder %q", raw)
		}
		if !strings.EqualFold(u.Scheme, "https") {
			return "", fmt.Errorf("doh forwarder must use https://")
		}
		if u.Path == "" || u.Path == "/" {
			u.Path = "/dns-query"
		}
		u.Fragment = ""
		u.RawQuery = ""
		return u.String(), nil
	case strings.HasPrefix(lower, "tls://"):
		rest := s[len("tls://"):]
		sni := ""
		if i := strings.IndexByte(rest, '#'); i >= 0 {
			sni = strings.TrimSpace(rest[i+1:])
			rest = rest[:i]
		}
		host, port, err := net.SplitHostPort(rest)
		if err != nil {
			host, port = rest, "853"
		}
		if port == "" {
			port = "853"
		}
		if _, err := strconv.Atoi(port); err != nil {
			return "", fmt.Errorf("invalid tls forwarder port %q", port)
		}
		if host == "" || strings.ContainsAny(host, " \t") {
			return "", fmt.Errorf("invalid tls forwarder host %q", host)
		}
		out := "tls://" + net.JoinHostPort(host, port)
		if sni != "" {
			out += "#" + sni
		}
		return out, nil
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
		if host == "" || strings.ContainsAny(host, " \t") {
			return "", fmt.Errorf("invalid forwarder host %q", host)
		}
	}
	return net.JoinHostPort(host, port), nil
}

// ForwardTarget is a parsed upstream dial target.
type ForwardTarget struct {
	Network    string // "udp", "tcp-tls", "https"
	Addr       string // host:port for udp/tls
	URL        string // full URL for https
	ServerName string // TLS SNI
	Display    string // canonical form for logs/metrics
}

// ParseForwardTarget parses a normalized forwarder string.
func ParseForwardTarget(raw string) (ForwardTarget, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ForwardTarget{}, fmt.Errorf("empty forwarder")
	}
	lower := strings.ToLower(s)
	switch {
	case strings.HasPrefix(lower, "https://"):
		u, err := url.Parse(s)
		if err != nil {
			return ForwardTarget{}, err
		}
		return ForwardTarget{Network: "https", URL: s, Display: s, ServerName: u.Hostname()}, nil
	case strings.HasPrefix(lower, "tls://"):
		rest := s[len("tls://"):]
		sni := ""
		if i := strings.IndexByte(rest, '#'); i >= 0 {
			sni = strings.TrimSpace(rest[i+1:])
			rest = rest[:i]
		}
		host, port, err := net.SplitHostPort(rest)
		if err != nil {
			return ForwardTarget{}, fmt.Errorf("invalid tls forwarder %q", raw)
		}
		if sni == "" {
			if net.ParseIP(host) == nil {
				sni = host
			}
		}
		addr := net.JoinHostPort(host, port)
		return ForwardTarget{Network: "tcp-tls", Addr: addr, ServerName: sni, Display: s}, nil
	default:
		addr := s
		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr = net.JoinHostPort(s, "53")
		}
		return ForwardTarget{Network: "udp", Addr: addr, Display: addr}, nil
	}
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

// NormalizeForwardZones validates conditional forwarder entries.
func NormalizeForwardZones(in []ForwardZoneConfig) ([]ForwardZoneConfig, error) {
	out := make([]ForwardZoneConfig, 0, len(in))
	seen := map[string]struct{}{}
	for _, z := range in {
		zone := NormalizeName(z.Zone)
		if zone == "." {
			return nil, fmt.Errorf("forward zone cannot be root; use global forwarders")
		}
		fwd, err := NormalizeForwarders(z.Forwarders)
		if err != nil {
			return nil, fmt.Errorf("zone %s: %w", zone, err)
		}
		if len(fwd) == 0 {
			return nil, fmt.Errorf("zone %s: at least one forwarder required", zone)
		}
		if _, ok := seen[zone]; ok {
			continue
		}
		seen[zone] = struct{}{}
		out = append(out, ForwardZoneConfig{Zone: zone, Forwarders: fwd})
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
		host = "127.0.0.1"
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
