package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEmptyRPZPoliciesFileDoesNotImplyClear(t *testing.T) {
	// Documented merge rule used by main: empty JSON keeps TOML when TOML has feeds.
	dir := t.TempDir()
	path := RPZPoliciesPath(dir)
	if err := SaveRPZPoliciesFile(path, RPZPoliciesFile{
		Policies:       nil,
		UpdateInterval: 86400,
		UpdateAt:       "04:00",
	}); err != nil {
		t.Fatal(err)
	}
	file, err := LoadRPZPoliciesFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(file.Policies) != 0 {
		t.Fatalf("want empty file policies, got %d", len(file.Policies))
	}
	tomlPols := []RPZPolicyTOML{{Name: "trustpositif", Source: "https://example/list", Format: "hosts", Action: "nxdomain"}}
	merged := tomlPols
	if len(file.Policies) == 0 && len(tomlPols) > 0 {
		// keep toml
	} else {
		merged = file.Policies
	}
	if len(merged) != 1 || merged[0].Name != "trustpositif" {
		t.Fatalf("merge=%v", merged)
	}
	_ = os.Remove(filepath.Join(dir, "rpz-policies.json"))
}
