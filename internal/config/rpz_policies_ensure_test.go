package config

import (
	"os"
	"testing"
)

func TestEnsureDefaultRPZPolicies(t *testing.T) {
	dir := t.TempDir()
	path := RPZPoliciesPath(dir)
	wrote, err := EnsureDefaultRPZPolicies(path)
	if err != nil || !wrote {
		t.Fatalf("wrote=%v err=%v", wrote, err)
	}
	f, err := LoadRPZPoliciesFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Policies) != 1 || f.Policies[0].Name != DefaultKomdigiPolicyName {
		t.Fatalf("%+v", f.Policies)
	}
	if !PolicyEnabled(f.Policies[0]) {
		t.Fatal("default should be enabled")
	}
	wrote2, err := EnsureDefaultRPZPolicies(path)
	if err != nil || wrote2 {
		t.Fatalf("second ensure should no-op: wrote=%v err=%v", wrote2, err)
	}
}

func TestEnsureDefaultReplacesBrokenKominfo(t *testing.T) {
	dir := t.TempDir()
	path := RPZPoliciesPath(dir)
	if err := SaveRPZPoliciesFile(path, RPZPoliciesFile{
		Policies: []RPZPolicyTOML{{
			Name: "kominfo", Format: "axfr", Zone: "kominfo.",
			Masters: []string{"182.23.79.202:53"}, Action: "redirect", Target: "139.255.196.196",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	wrote, err := EnsureDefaultRPZPolicies(path)
	if err != nil || !wrote {
		t.Fatalf("wrote=%v err=%v", wrote, err)
	}
	f, _ := LoadRPZPoliciesFile(path)
	if f.Policies[0].Name != DefaultKomdigiPolicyName {
		t.Fatalf("got %s", f.Policies[0].Name)
	}
}

func TestEnsureDefaultKeepsCustom(t *testing.T) {
	dir := t.TempDir()
	path := RPZPoliciesPath(dir)
	if err := SaveRPZPoliciesFile(path, RPZPoliciesFile{
		Policies: []RPZPolicyTOML{{
			Name: "custom", Format: "hosts", Source: "https://example/list", Action: "nxdomain",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	wrote, err := EnsureDefaultRPZPolicies(path)
	if err != nil || wrote {
		t.Fatalf("must not overwrite custom hosts: wrote=%v err=%v", wrote, err)
	}
}

func TestPolicyEnabledNil(t *testing.T) {
	if !PolicyEnabled(RPZPolicyTOML{}) {
		t.Fatal("nil enabled = on")
	}
	off := false
	if PolicyEnabled(RPZPolicyTOML{Enabled: &off}) {
		t.Fatal("false = off")
	}
}

func TestFilterSeedURL(t *testing.T) {
	t.Setenv("POWERSVX_FILTER_SEED_URL", "")
	// Empty env → default (Unsetenv may be enough; Setenv "" can differ by OS)
	_ = os.Unsetenv("POWERSVX_FILTER_SEED_URL")
	if FilterSeedURL() != DefaultFilterSeedURL {
		t.Fatalf("default=%s", FilterSeedURL())
	}
	t.Setenv("POWERSVX_FILTER_SEED_URL", "off")
	if FilterSeedURL() != "" {
		t.Fatal("off disables")
	}
	t.Setenv("POWERSVX_FILTER_SEED_URL", "https://example/seed.tgz")
	if FilterSeedURL() != "https://example/seed.tgz" {
		t.Fatal(FilterSeedURL())
	}
}
