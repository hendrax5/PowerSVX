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
		{"unbound ignores the old escape hatch", "unbound", true, "", "1", true},
		{"external ignores the old escape hatch", "external", true, "", "1", true},
		{"powersvx ignores the old escape hatch", "powersvx", true, "", "1", true},
		{"unknown value ignores the old escape hatch", "bogus", true, "1", "1", true},
		{"unset means dnsdist", "", false, "", "", false},
		{"empty means dnsdist", "", true, "", "", false},
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

func TestUnsetModeIsDnsdistEverywhere(t *testing.T) {
	for _, host := range []string{"1", ""} {
		setDataplaneEnv(t, "", false, host, "")
		if DNSDataplane() != "dnsdist" {
			t.Fatalf("host=%q: got %q", host, DNSDataplane())
		}
	}
}

func TestRejectionMessageNamesModeAndRemedy(t *testing.T) {
	for mode, want := range map[string][]string{
		"unbound":  {"unbound", "has been removed", "dnsdist", "docs/PRODUCTION.md"},
		"external": {"external", "has been removed", "dnsdist", "docs/PRODUCTION.md"},
		"powersvx": {"powersvx", "Go resolver", "has been removed", "dnsdist", "docs/PRODUCTION.md"},
	} {
		setDataplaneEnv(t, mode, true, "", "")
		msg := CheckDataplane().Error()
		for _, w := range want {
			if !strings.Contains(msg, w) {
				t.Errorf("%s: message %q lacks %q", mode, msg, w)
			}
		}
		if strings.Contains(msg, "ALLOW_LEGACY") {
			t.Errorf("%s: message still mentions the void escape hatch: %q", mode, msg)
		}
	}
}

// The shell guard and the Control Plane must tell the operator the same thing,
// with and without the old escape hatch.
func TestShellGuardUsesTheSameMessage(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	script, err := filepath.Abs("../../deploy/linux/dataplane-guard.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ mode, legacy string }{
		{"unbound", ""}, {"unbound", "1"}, {"external", "1"}, {"powersvx", ""}, {"powersvx", "1"},
	} {
		setDataplaneEnv(t, c.mode, true, "", c.legacy)
		want := CheckDataplane().Error()
		cmd := exec.Command("sh", script)
		cmd.Env = append(os.Environ(), "POWERSVX_DNS_DATAPLANE="+c.mode, "POWERSVX_ALLOW_LEGACY_DATAPLANE="+c.legacy)
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), want) {
			t.Fatalf("%s/%q: shell output %q does not contain Control Plane message %q", c.mode, c.legacy, out, want)
		}
	}
}
