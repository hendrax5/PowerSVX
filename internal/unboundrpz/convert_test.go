package unboundrpz

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConvertHostsBankSafe(t *testing.T) {
	dir := t.TempDir()
	hosts := filepath.Join(dir, "hosts.txt")
	content := "0.0.0.0 evil.example\n0.0.0.0 brimo.id\n0.0.0.0 www.bca.co.id\ngoogle.com\n"
	if err := os.WriteFile(hosts, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.rpz")
	n, err := ConvertHostsFile(hosts, out, "redirect", "139.255.196.196")
	if err != nil {
		t.Fatal(err)
	}
	if n < 2 {
		t.Fatalf("entries=%d", n)
	}
	b, _ := os.ReadFile(out)
	s := string(b)
	if !contains(s, "$ORIGIN "+TrustZoneName) {
		t.Fatalf("missing ORIGIN:\n%s", s)
	}
	if !contains(s, "evil.example A 139.255.196.196") {
		t.Fatalf("missing redirect:\n%s", s)
	}
	if !contains(s, "brimo.id CNAME .") {
		t.Fatalf("bank-like should NXDOMAIN:\n%s", s)
	}
	if contains(s, "bca.co.id") {
		t.Fatalf("official bank must be skipped:\n%s", s)
	}
}

func TestWriteBankPassthru(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "banks.rpz")
	if err := WriteBankPassthru(path); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	s := string(b)
	if !contains(s, "$ORIGIN "+BankZoneName) {
		t.Fatal(s)
	}
	if !contains(s, "bca.co.id CNAME rpz-passthru.") {
		t.Fatal(s)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		(len(s) > 0 && findSub(s, sub)))
}

func findSub(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
