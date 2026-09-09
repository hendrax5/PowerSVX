package unboundrpz

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNamePriority(t *testing.T) {
	cases := []struct {
		name string
		want int
	}{
		{"evil.com", prioHigh},
		{"phish.co.id", prioHigh},
		{"www.phish.co.id", prioHigh},
		{"a.b.phish.co.id", prioMid},
		{"www.evil.com", prioMid},
		{"a.b.c.evil.com", prioLow},
		{"deep.sub.track.bad.xyz", prioLow},
	}
	for _, tc := range cases {
		if got := namePriority(tc.name); got != tc.want {
			t.Fatalf("%s: got prio %d want %d", tc.name, got, tc.want)
		}
	}
}

func TestConvertHostsFileCapPrefersHighPriority(t *testing.T) {
	dir := t.TempDir()
	hosts := filepath.Join(dir, "hosts.txt")
	var b strings.Builder
	// Many low-priority names first (would win a naive "first N" trim).
	for i := 0; i < 50; i++ {
		b.WriteString("0.0.0.0 a.b.c.low")
		b.WriteByte(byte('a' + i%26))
		b.WriteString(".example\n")
	}
	b.WriteString("0.0.0.0 hot-phish.id\n")
	b.WriteString("0.0.0.0 apex-bad.com\n")
	b.WriteString("0.0.0.0 mid.bad.com\n")
	if err := os.WriteFile(hosts, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.rpz")
	written, scanned, err := ConvertHostsFileOpts(hosts, out, ConvertHostsOpts{
		Action:     "nxdomain",
		MaxEntries: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 50 {
		t.Fatalf("scanned=%d", scanned)
	}
	if written != 5 {
		t.Fatalf("written=%d want 5", written)
	}
	s := string(mustRead(t, out))
	if !strings.Contains(s, "hot-phish.id CNAME .") {
		t.Fatalf("missing high .id:\n%s", s)
	}
	if !strings.Contains(s, "apex-bad.com CNAME .") {
		t.Fatalf("missing high apex:\n%s", s)
	}
	if !strings.Contains(s, "mid.bad.com CNAME .") {
		t.Fatalf("missing mid:\n%s", s)
	}
	// At most a few lows should appear after high/mid fill remaining slots.
	lowHits := strings.Count(s, "a.b.c.low")
	if lowHits > 3 {
		t.Fatalf("too many low-prio lines (%d):\n%s", lowHits, s)
	}
}

func TestConvertHostsFileUnlimitedIgnoresCap(t *testing.T) {
	dir := t.TempDir()
	hosts := filepath.Join(dir, "hosts.txt")
	if err := os.WriteFile(hosts, []byte("0.0.0.0 one.com\n0.0.0.0 two.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.rpz")
	written, scanned, err := ConvertHostsFileOpts(hosts, out, ConvertHostsOpts{MaxEntries: 0})
	if err != nil {
		t.Fatal(err)
	}
	if written != 2 || scanned != 2 {
		t.Fatalf("written=%d scanned=%d", written, scanned)
	}
}

func TestAutoMaxEntries(t *testing.T) {
	if got := autoMaxEntries(11 * 1024); got != 1_500_000 {
		t.Fatalf("11GiB: %d", got)
	}
	if got := autoMaxEntries(16 * 1024); got != 5_000_000 {
		t.Fatalf("16GiB: %d", got)
	}
	if got := autoMaxEntries(32 * 1024); got != 0 {
		t.Fatalf("32GiB unlimited: %d", got)
	}
	if got := autoMaxEntries(0); got != 0 {
		t.Fatalf("unknown mem unlimited: %d", got)
	}
}

func TestMaxEntriesFromEnvExplicit(t *testing.T) {
	t.Setenv("POWERSVX_RPZ_MAX_ENTRIES", "12345")
	if got := MaxEntriesFromEnv(); got != 12345 {
		t.Fatalf("got %d", got)
	}
	t.Setenv("POWERSVX_RPZ_MAX_ENTRIES", "0")
	if got := MaxEntriesFromEnv(); got != 0 {
		t.Fatalf("unlimited got %d", got)
	}
	t.Setenv("POWERSVX_RPZ_MAX_ENTRIES", "unlimited")
	if got := MaxEntriesFromEnv(); got != 0 {
		t.Fatalf("unlimited keyword got %d", got)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
