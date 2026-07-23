package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// RPZPoliciesFile is UI-editable RPZ policy list (survives restart; overrides TOML policies when present).
type RPZPoliciesFile struct {
	Policies       []RPZPolicyTOML `json:"policies"`
	UpdateInterval int             `json:"update_interval"` // hosts; seconds; 0 = disabled
	// AxfrUpdateInterval is nil when omitted from older files (caller applies default 86400).
	AxfrUpdateInterval *int `json:"axfr_update_interval,omitempty"`
}

func RPZPoliciesPath(dir string) string {
	if dir == "" {
		dir = "./data"
	}
	return filepath.Join(dir, "rpz-policies.json")
}

func LoadRPZPoliciesFile(path string) (RPZPoliciesFile, error) {
	var f RPZPoliciesFile
	b, err := os.ReadFile(path)
	if err != nil {
		return f, err
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return f, err
	}
	if f.Policies == nil {
		f.Policies = []RPZPolicyTOML{}
	}
	return f, nil
}

func LoadRPZPolicies(path string) ([]RPZPolicyTOML, error) {
	f, err := LoadRPZPoliciesFile(path)
	if err != nil {
		return nil, err
	}
	return f.Policies, nil
}

func SaveRPZPoliciesFile(path string, f RPZPoliciesFile) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if f.Policies == nil {
		f.Policies = []RPZPolicyTOML{}
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func SaveRPZPolicies(path string, policies []RPZPolicyTOML) error {
	f, err := LoadRPZPoliciesFile(path)
	if err != nil && !os.IsNotExist(err) {
		f = RPZPoliciesFile{}
	}
	f.Policies = policies
	return SaveRPZPoliciesFile(path, f)
}

// DefaultAxfrUpdateInterval is used when axfr_update_interval is omitted from disk.
const DefaultAxfrUpdateInterval = 86400
