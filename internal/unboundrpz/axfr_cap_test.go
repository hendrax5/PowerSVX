package unboundrpz

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSelectNamesByPriority(t *testing.T) {
	names := make([]string, 0, 60)
	for i := 0; i < 50; i++ {
		names = append(names, "a.b.c.low"+string(rune('a'+i%26))+".example")
	}
	names = append(names, "hot-phish.id", "apex-bad.com", "mid.bad.com")
	got := SelectNamesByPriority(names, 5)
	if len(got) != 5 {
		t.Fatalf("len=%d want 5: %v", len(got), got)
	}
	joined := stringsJoin(got)
	if !contains(joined, "hot-phish.id") || !contains(joined, "apex-bad.com") {
		t.Fatalf("missing high prio: %v", got)
	}
}

func TestSyncAXFRNamesRespectsMax(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("POWERSVX_UNBOUND_RPZ_DIR", dir)
	t.Setenv("POWERSVX_RPZ_MAX_ENTRIES", "3")
	names := []string{
		"a.b.c.deep.example",
		"b.b.c.deep.example",
		"phish.co.id",
		"evil.com",
		"www.mid.com",
	}
	n, err := SyncAXFRNames(dir, names, "nxdomain", "")
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("written=%d", n)
	}
	b, _ := os.ReadFile(filepath.Join(dir, AXFRFile))
	s := string(b)
	if !contains(s, "phish.co.id") || !contains(s, "evil.com") {
		t.Fatalf("expected high priority kept:\n%s", s)
	}
}

func stringsJoin(ss []string) string {
	out := ""
	for _, s := range ss {
		out += s + "\n"
	}
	return out
}
