package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// RuntimeSettings is persisted UI-editable feature flags (survives restart).
type RuntimeSettings struct {
	GeoDNS       *bool `json:"geodns,omitempty"`
	RPZ          *bool `json:"rpz_enabled,omitempty"`
	RateLimit    *bool `json:"rate_limit,omitempty"`
	ECS          *bool `json:"ecs_enabled,omitempty"`
	SplitHorizon *bool `json:"split_horizon,omitempty"`
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
}
