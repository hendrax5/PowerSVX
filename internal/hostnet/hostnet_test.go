package hostnet

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateIfaceName(t *testing.T) {
	valid := []string{"eth0", "ens18", "enp3s0f0", "bond0.100", "vlan_10", "eth0:1"}
	for _, v := range valid {
		if err := validateIfaceName(v); err != nil {
			t.Fatalf("expected valid iface %q, got %v", v, err)
		}
	}
	invalid := []string{"", "eth0\n  routes:", "eth 0", "../etc", "eth0\"test", "verylonginterfacename123"}
	for _, iv := range invalid {
		if err := validateIfaceName(iv); err == nil {
			t.Fatalf("expected error for invalid iface %q", iv)
		}
	}
}

func TestSanitizeDNSList(t *testing.T) {
	got, err := sanitizeDNSList([]string{" 8.8.8.8 ", "1.1.1.1", "8.8.8.8", ""})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 || got[0] != "8.8.8.8" || got[1] != "1.1.1.1" {
		t.Fatalf("unexpected sanitized DNS list: %#v", got)
	}

	if _, err := sanitizeDNSList([]string{"8.8.8.8\n    - 9.9.9.9"}); err == nil {
		t.Fatal("expected YAML newline injection in DNS list to fail")
	}
}

func TestWriteNetplanConfigValidationAndRender(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("POWERSVX_NETPLAN_DIR", dir)

	req := ApplyRequest{
		Iface:   "ens18",
		IP:      "103.162.17.246/28",
		Gateway: "103.162.17.241",
		DNS:     []string{"1.1.1.1", "8.8.8.8"},
	}
	if err := writeNetplanConfig(req, []string{"103.162.17.246/28"}); err != nil {
		t.Fatalf("writeNetplanConfig failed: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "60-powersvx.yaml"))
	if err != nil {
		t.Fatalf("read written netplan failed: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, "ens18:") || !strings.Contains(s, `"103.162.17.246/28"`) || !strings.Contains(s, "via: 103.162.17.241") {
		t.Fatalf("unexpected netplan YAML:\n%s", s)
	}
}

func TestRemoveIPRejectsBadInputsWithoutPanic(t *testing.T) {
	if _, err := RemoveIP(RemoveIPRequest{Iface: "eth0\nbad", IP: "10.0.0.1/24"}); err == nil {
		t.Fatal("expected invalid iface error")
	}
	if _, err := RemoveIP(RemoveIPRequest{Iface: "eth0", IP: "not-an-ip"}); err == nil {
		t.Fatal("expected invalid IP error")
	}
}
