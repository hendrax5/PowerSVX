package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// RuntimeSettings is persisted UI-editable feature flags (survives restart).
type RuntimeSettings struct {
	GeoDNS               *bool    `json:"geodns,omitempty"`
	RPZ                  *bool    `json:"rpz_enabled,omitempty"`
	RateLimit            *bool    `json:"rate_limit,omitempty"`
	RateLimitQPS         *int     `json:"rate_limit_qps,omitempty"`
	RateLimitBurst       *int     `json:"rate_limit_burst,omitempty"`
	RateLimitBlockDur    *int     `json:"rate_limit_block_duration,omitempty"`
	RateLimitWhitelist   []string `json:"rate_limit_whitelist"`
	ECS                  *bool    `json:"ecs_enabled,omitempty"`
	SplitHorizon         *bool    `json:"split_horizon,omitempty"`
	ResolverMode         *string  `json:"resolver_mode,omitempty"`
	ForwardOnFail        *bool    `json:"forward_on_fail,omitempty"`
	QueryLog              *bool    `json:"query_log_enabled,omitempty"`
	QueryLogRetentionDays *int     `json:"query_log_retention_days,omitempty"`
	QueryLogMaxSizeMB     *int     `json:"query_log_max_size_mb,omitempty"`
	QueryLogSampleRate    *float64 `json:"query_log_sample_rate,omitempty"`
	Forwarders           []string `json:"forwarders"`
	ForwardZones         []ForwardZoneConfig `json:"forward_zones"`
	AllowQuery           []string `json:"allow_query"`
	DenyQuery            []string `json:"deny_query"`
	KominfoSyncEnabled   *bool    `json:"kominfo_sync_enabled,omitempty"` // legacy
	AxfrSyncEnabled      *bool    `json:"axfr_sync_enabled,omitempty"`
	AxfrSyncTargets      []string `json:"axfr_sync_targets,omitempty"`
	// TPROXY (Linux transparent intercept)
	TProxyListen    *bool    `json:"tproxy_listen,omitempty"`    // IP_TRANSPARENT sockets (needs restart)
	TProxyIntercept *bool    `json:"tproxy_intercept,omitempty"` // nftables + ip rule (live apply)
	TProxyIface     string   `json:"tproxy_iface,omitempty"`
	TProxyMode      string   `json:"tproxy_mode,omitempty"` // public | all | custom
	TProxyResolvers []string `json:"tproxy_resolvers,omitempty"`
	TProxyMark      *uint32  `json:"tproxy_mark,omitempty"`
}

func RuntimeSettingsPath(dir string) string {
	if dir == "" {
		dir = "./data"
	}
	return filepath.Join(dir, "runtime-settings.json")
}

func LoadRuntimeSettings(path string) (RuntimeSettings, error) {
	var s RuntimeSettings
	b, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	err = json.Unmarshal(b, &s)
	return s, err
}

func SaveRuntimeSettings(path string, s RuntimeSettings) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func (c *Config) ApplyRuntimeSettings(s RuntimeSettings) {
	if s.GeoDNS != nil {
		c.GeoDNS.Enabled = *s.GeoDNS
	}
	if s.RPZ != nil {
		c.RPZ.Enabled = *s.RPZ
	}
	if s.RateLimit != nil {
		c.RateLimit.Enabled = *s.RateLimit
	}
	if s.RateLimitQPS != nil && *s.RateLimitQPS > 0 {
		c.RateLimit.DefaultQPS = *s.RateLimitQPS
	}
	if s.RateLimitBurst != nil && *s.RateLimitBurst > 0 {
		c.RateLimit.DefaultBurst = *s.RateLimitBurst
	}
	if s.RateLimitBlockDur != nil && *s.RateLimitBlockDur > 0 {
		c.RateLimit.BlockDuration = *s.RateLimitBlockDur
	}
	if s.RateLimitWhitelist != nil {
		c.RateLimit.Whitelist = append([]string(nil), s.RateLimitWhitelist...)
	}
	if s.ECS != nil {
		c.Resolver.ECSEnabled = *s.ECS
	}
	if s.SplitHorizon != nil {
		c.SplitHorizon.Enabled = *s.SplitHorizon
	}
	if s.ResolverMode != nil {
		c.Resolver.Mode = NormalizeResolverMode(*s.ResolverMode)
	}
	if s.ForwardOnFail != nil {
		c.Resolver.ForwardOnFail = *s.ForwardOnFail
	}
	if s.QueryLog != nil {
		c.Logging.QueryLogEnabled = *s.QueryLog
	}
	if s.QueryLogRetentionDays != nil && *s.QueryLogRetentionDays >= 0 {
		c.Logging.QueryLogRetentionDays = *s.QueryLogRetentionDays
	}
	if s.QueryLogMaxSizeMB != nil && *s.QueryLogMaxSizeMB >= 0 {
		c.Logging.QueryLogMaxSizeMB = *s.QueryLogMaxSizeMB
	}
	if s.QueryLogSampleRate != nil && *s.QueryLogSampleRate >= 0 && *s.QueryLogSampleRate <= 1 {
		c.Logging.QueryLogSampleRate = *s.QueryLogSampleRate
	}
	if s.Forwarders != nil {
		c.Resolver.Forwarders = append([]string(nil), s.Forwarders...)
	}
	if s.ForwardZones != nil {
		c.Resolver.ForwardZones = append([]ForwardZoneConfig(nil), s.ForwardZones...)
	}
	// Distinguish omitted (nil) vs explicit empty list via JSON null vs [].
	// When unmarshaling, missing keys leave nil; present arrays are non-nil.
	if s.AllowQuery != nil {
		c.ACL.AllowQuery = append([]string(nil), s.AllowQuery...)
	}
	if s.DenyQuery != nil {
		c.ACL.DenyQuery = append([]string(nil), s.DenyQuery...)
	}
	if s.KominfoSyncEnabled != nil {
		c.KominfoSync.Enabled = *s.KominfoSyncEnabled
	}
	if s.AxfrSyncEnabled != nil {
		c.KominfoSync.Enabled = *s.AxfrSyncEnabled
	}
	if s.AxfrSyncTargets != nil {
		c.KominfoSync.Targets = append([]string(nil), s.AxfrSyncTargets...)
	}
	if s.TProxyListen != nil {
		c.Server.TProxy = *s.TProxyListen
	}
}
