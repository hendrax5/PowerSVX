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

	// RemovedKeys are the version 1 keys the file still sets. They are ignored;
	// the caller logs one warning per key.
	RemovedKeys []string `toml:"-"`
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
	Workers     int    `toml:"workers"`
	// ProxyProtocol says how the Auth Backend treats a PROXY protocol v2 header from the local
	// Dataplane: "optional" (default) takes it when there is one and a plain query when there is
	// none, "required" takes only queries that carry one, "off" never reads one. A header is
	// believed only from a loopback peer. See docs/adr/0003.
	ProxyProtocol string `toml:"proxy_protocol"`
	// TProxy enables IP_TRANSPARENT on UDP/TCP DNS sockets (Linux only).
	// Needed for nftables/iptables TPROXY where the packet destination stays
	// non-local (e.g. 8.8.8.8). Not required for MikroTik/iptables DNAT.
	TProxy bool      `toml:"tproxy"`
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

type ResolverConfig struct {
	Mode       string   `toml:"mode"`
	Forwarders []string `toml:"forwarders"`
	// ForwardZones routes queries for matching domains to specific upstreams
	// (longest-suffix match). Checked before recursion and before global forwarders.
	ForwardZones  []ForwardZoneConfig `toml:"forward_zones"`
	// ForwardOnFail: when mode=recursive, fall back to forwarders if root iteration fails.
	ForwardOnFail     bool   `toml:"forward_on_fail"`
	DNSSECValidation  bool   `toml:"dnssec_validation"`
	DNSSECMode        string `toml:"dnssec_mode"`
	EDNSBufferSize    uint16 `toml:"edns_buffer_size"`
	ECSEnabled        bool   `toml:"ecs_enabled"`
}

// ForwardZoneConfig is a conditional/stub forwarder for a domain suffix.
type ForwardZoneConfig struct {
	Zone       string   `toml:"zone" json:"zone"`
	Forwarders []string `toml:"forwarders" json:"forwarders"`
}

type APIConfig struct {
	RESTEnabled bool   `toml:"rest_enabled"`
	RESTBind    string `toml:"rest_bind"`
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
	// IgnoreClientSubnet makes GeoDNS use only the client address, never the EDNS client subnet a
	// query from the Dataplane carries (docs/adr/0003).
	IgnoreClientSubnet bool `toml:"ignore_client_subnet"`
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

func Default() *Config {
	return &Config{
		Server: ServerConfig{
			BindAddress: "127.0.0.1", // the Auth Backend is reached only by the local Dataplane
			UDPPort:     5353,
			TCPPort:     5353,
			Workers:     0,
			ProxyProtocol: "optional",
		},
		Database: DatabaseConfig{
			Type: "postgres", Host: "localhost", Port: 5432,
			Database: "PowerSVX", User: "PowerSVX", MaxConnections: 20,
		},
		Resolver: ResolverConfig{
			// Default: Unbound recurses by itself. A forwarder on Unbound's own address
			// (127.0.0.1:5353) would make it forward to itself.
			Mode:          "recursive",
			Forwarders:    nil,
			ForwardOnFail: false,
			DNSSECMode:    "off",
			EDNSBufferSize: 1232,
			ECSEnabled:     true,
		},
		API: APIConfig{RESTEnabled: true, RESTBind: "0.0.0.0:5380", AuthType: "none"},
		Logging: LoggingConfig{
			Level: "info", Format: "json", QueryLogEnabled: false,
			QueryLogRetentionDays: 30,
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
	}
}

func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		normalizeResolverBuffers(cfg)
		return cfg, nil
	}
	md, err := toml.DecodeFile(path, cfg)
	if err != nil {
		return nil, fmt.Errorf("load config %s: %w", path, err)
	}
	cfg.RemovedKeys = removedKeysIn(md)
	expandEnv(cfg)
	applyDatabaseEnv(cfg)
	normalizeDNSSEC(cfg)
	normalizeResolverBuffers(cfg)
	return cfg, nil
}

// applyDatabaseEnv lets POWERSVX_DATABASE_ENABLED override [database] enabled, so a
// Core Profile node runs without Postgres while the shared TOML stays unchanged.
// Unset (or any other value) leaves the file's setting alone.
func applyDatabaseEnv(cfg *Config) {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("POWERSVX_DATABASE_ENABLED"))) {
	case "0", "false", "no", "off":
		cfg.Database.Enabled = false
	case "1", "true", "yes", "on":
		cfg.Database.Enabled = true
	}
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
