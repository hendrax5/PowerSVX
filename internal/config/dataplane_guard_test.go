package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func setDataplaneEnv(t *testing.T, mode string, set bool, host, legacy string) {
	t.Helper()
	if set {
		t.Setenv("POWERSVX_DNS_DATAPLANE", mode)
	} else {
		t.Setenv("POWERSVX_DNS_DATAPLANE", "")
		os.Unsetenv("POWERSVX_DNS_DATAPLANE")
	}
	t.Setenv("POWERSVX_HOST_DEPLOYMENT", host)
	t.Setenv("POWERSVX_ALLOW_LEGACY_DATAPLANE", legacy)
}

func TestCheckDataplane(t *testing.T) {
	cases := []struct {
		name   string
		mode   string
		set    bool
		host   string
		legacy string
		reject bool
	}{
		{"dnsdist", "dnsdist", true, "", "", false},
		{"dnsdist upper-case with spaces", " DnsDist ", true, "", "", false},
		{"cdb alias of dnsdist", "cdb", true, "", "", false},
		{"unbound rejected", "unbound", true, "", "", true},
		{"external rejected", "external", true, "", "", true},
		{"powersvx rejected", "powersvx", true, "", "", true},
		{"unknown value rejected", "bogus", true, "", "", true},
		{"unbound with escape hatch", "unbound", true, "", "1", false},
		{"powersvx with escape hatch", "powersvx", true, "", "1", false},
		{"escape hatch other than 1 does not count", "unbound", true, "", "0", true},
		{"unset off host keeps development default", "", false, "", "", false},
		{"empty off host keeps development default", "", true, "", "", false},
		{"unset on host means dnsdist", "", false, "1", "", false},
		{"unbound on host rejected", "unbound", true, "1", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			setDataplaneEnv(t, c.mode, c.set, c.host, c.legacy)
			err := CheckDataplane()
			if c.reject && err == nil {
				t.Fatal("expected the mode to be rejected")
			}
			if !c.reject && err != nil {
				t.Fatalf("expected the mode to be accepted: %v", err)
			}
		})
	}
}

func TestUnsetModeOnHostIsDnsdist(t *testing.T) {
	setDataplaneEnv(t, "", false, "1", "")
	if DNSDataplane() != "dnsdist" {
		t.Fatalf("got %q", DNSDataplane())
	}
	setDataplaneEnv(t, "", false, "", "")
	if DNSDataplane() != "powersvx" {
		t.Fatalf("development default changed: %q", DNSDataplane())
	}
}

func TestRejectionMessageNamesModeAndRemedy(t *testing.T) {
	setDataplaneEnv(t, "unbound", true, "", "")
	msg := CheckDataplane().Error()
	for _, want := range []string{"unbound", "next major version", "dnsdist", "docs/PRODUCTION.md"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message %q lacks %q", msg, want)
		}
	}
}

// The shell guard and the Control Plane must tell the operator the same thing.
func TestShellGuardUsesTheSameMessage(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	script, err := filepath.Abs("../../deploy/linux/dataplane-guard.sh")
	if err != nil {
		t.Fatal(err)
	}
	setDataplaneEnv(t, "unbound", true, "", "")
	want := CheckDataplane().Error()
	cmd := exec.Command("sh", script)
	cmd.Env = append(os.Environ(), "POWERSVX_DNS_DATAPLANE=unbound")
	out, _ := cmd.CombinedOutput()
	if !strings.Contains(string(out), want) {
		t.Fatalf("shell output %q does not contain Control Plane message %q", out, want)
	}
}
