package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// RPZPoliciesFile is UI-editable RPZ policy list (survives restart; overrides TOML policies when present).
type RPZPoliciesFile struct {
	Policies       []RPZPolicyTOML `json:"policies"`
	UpdateInterval int             `json:"update_interval"` // hosts; seconds; 0 = disabled
	// UpdateAt is local "HH:MM" for daily hosts refresh (empty = interval ticker from start).
	UpdateAt string `json:"update_at,omitempty"`
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

// DefaultKomdigiZone is the official TrustPositif AXFR apex.
const DefaultKomdigiZone = "trustpositifkominfo."

// DefaultKomdigiPolicyName is the canonical filter feed name.
const DefaultKomdigiPolicyName = "trustpositifkominfo"

// DefaultFilterSeedURL is the GitHub Release asset for first-boot CDB bootstrap
// (published from a synced host such as JMG). Override with POWERSVX_FILTER_SEED_URL.
const DefaultFilterSeedURL = "https://github.com/hendrax5/PowerSVX/releases/latest/download/blocklist-seed.tgz"

// PolicyEnabled reports whether a policy should sync (nil/omitted = enabled).
func PolicyEnabled(p RPZPolicyTOML) bool {
	if p.Enabled == nil {
		return true
	}
	return *p.Enabled
}

// BoolPtr returns a *bool for JSON/TOML literals.
func BoolPtr(v bool) *bool { return &v }

// DefaultKomdigiAXFRPolicy returns the fleet-standard TrustPositif AXFR feed (enabled).
func DefaultKomdigiAXFRPolicy() RPZPolicyTOML {
	return RPZPolicyTOML{
		Name:    DefaultKomdigiPolicyName,
		Source:  DefaultKomdigiPolicyName,
		Format:  "axfr",
		Action:  "redirect",
		Target:  "139.255.196.196",
		Zone:    DefaultKomdigiZone,
		Masters: []string{"182.23.79.202:53", "139.255.196.202:53"},
		Enabled: BoolPtr(true),
	}
}

func hasValidTrustpositifAXFR(pols []RPZPolicyTOML) bool {
	for _, p := range pols {
		if strings.ToLower(strings.TrimSpace(p.Format)) != "axfr" {
			continue
		}
		z := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p.Zone), "."))
		if strings.Contains(z, "trustpositif") {
			return true
		}
		n := strings.ToLower(strings.TrimSpace(p.Name))
		if strings.Contains(n, "trustpositif") {
			return true
		}
	}
	return false
}

func onlyBrokenKominfoLegacy(pols []RPZPolicyTOML) bool {
	if len(pols) == 0 {
		return false
	}
	for _, p := range pols {
		z := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p.Zone), "."))
		n := strings.ToLower(strings.TrimSpace(p.Name))
		format := strings.ToLower(strings.TrimSpace(p.Format))
		if format != "" && format != "axfr" {
			return false
		}
		// Broken legacy: zone/name "kominfo" without trustpositif.
		okLegacy := (z == "kominfo" || n == "kominfo") && !strings.Contains(z, "trustpositif")
		if !okLegacy {
			return false
		}
	}
	return true
}

// EnsureDefaultRPZPolicies writes the default TrustPositif AXFR policy when missing,
// empty, or only a broken legacy kominfo. zone. Returns true if the file was written.
func EnsureDefaultRPZPolicies(path string) (wrote bool, err error) {
	f, err := LoadRPZPoliciesFile(path)
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	if err == nil && len(f.Policies) > 0 && hasValidTrustpositifAXFR(f.Policies) {
		return false, nil
	}
	if err == nil && len(f.Policies) > 0 && !onlyBrokenKominfoLegacy(f.Policies) {
		// Custom non-empty policies without trustpositif — leave alone.
		return false, nil
	}
	axfr := DefaultAxfrUpdateInterval
	out := RPZPoliciesFile{
		Policies:           []RPZPolicyTOML{DefaultKomdigiAXFRPolicy()},
		UpdateInterval:     0,  // hosts feeds disabled by default (no web scraping)
		UpdateAt:           "", // no hosts schedule by default
		AxfrUpdateInterval: &axfr,
	}
	if f.UpdateInterval > 0 {
		out.UpdateInterval = f.UpdateInterval
	}
	if strings.TrimSpace(f.UpdateAt) != "" {
		out.UpdateAt = strings.TrimSpace(f.UpdateAt)
	}
	if f.AxfrUpdateInterval != nil {
		out.AxfrUpdateInterval = f.AxfrUpdateInterval
	}
	if err := SaveRPZPoliciesFile(path, out); err != nil {
		return false, err
	}
	return true, nil
}

// FilterSeedURL returns POWERSVX_FILTER_SEED_URL or the GitHub release default.
// Set to "off" / "none" / "-" to disable seed bootstrap.
func FilterSeedURL() string {
	v := strings.TrimSpace(os.Getenv("POWERSVX_FILTER_SEED_URL"))
	if v == "" {
		return DefaultFilterSeedURL
	}
	switch strings.ToLower(v) {
	case "off", "none", "-", "0", "false":
		return ""
	default:
		return v
	}
}
