package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRPZPoliciesRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rpz-policies.json")
	in := RPZPoliciesFile{
		UpdateInterval: 3600,
		Policies: []RPZPolicyTOML{
			{Name: "trustpositif", Source: "https://example.com/list", Format: "hosts", Action: "nxdomain"},
		},
	}
	if err := SaveRPZPoliciesFile(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := LoadRPZPoliciesFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if out.UpdateInterval != 3600 || len(out.Policies) != 1 || out.Policies[0].Name != "trustpositif" {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}
