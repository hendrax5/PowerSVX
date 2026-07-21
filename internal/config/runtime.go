package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// RuntimeSettings is persisted UI-editable feature flags (survives restart).
type RuntimeSettings struct {
	GeoDNS        *bool    `json:"geodns,omitempty"`
	RPZ           *bool    `json:"rpz_enabled,omitempty"`
	RateLimit     *bool    `json:"rate_limit,omitempty"`
	ECS           *bool    `json:"ecs_enabled,omitempty"`
	SplitHorizon  *bool    `json:"split_horizon,omitempty"`
	ResolverMode  *string  `json:"resolver_mode,omitempty"`
	ForwardOnFail *bool    `json:"forward_on_fail,omitempty"`
	QueryLog      *bool    `json:"query_log_enabled,omitempty"`
	Forwarders    []string `json:"forwarders"`
	AllowQuery    []string `json:"allow_query"`
	DenyQuery     []string `json:"deny_query"`
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
	if s.Forwarders != nil {
		c.Resolver.Forwarders = append([]string(nil), s.Forwarders...)
	}
	// Distinguish omitted (nil) vs explicit empty list via JSON null vs [].
	// When unmarshaling, missing keys leave nil; present arrays are non-nil.
	if s.AllowQuery != nil {
		c.ACL.AllowQuery = append([]string(nil), s.AllowQuery...)
	}
	if s.DenyQuery != nil {
		c.ACL.DenyQuery = append([]string(nil), s.DenyQuery...)
	}
}
