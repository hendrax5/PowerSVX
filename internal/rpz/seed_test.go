package rpz

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSeedHotFromStore(t *testing.T) {
	dir := t.TempDir()
	e := New(true)
	if err := e.OpenDisk(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	hosts := filepath.Join(dir, "hosts.txt")
	if err := os.WriteFile(hosts, []byte("0.0.0.0 hot.blocked.test\n0.0.0.0 other.blocked.test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := e.LoadPolicies([]PolicyConfig{{
		Name: "t", Source: hosts, Format: "hosts", Action: ActionNXDOMAIN,
	}}, time.Second); err != nil {
		t.Fatal(err)
	}
	n := e.SeedHot([]string{"hot.blocked.test", "missing.example", "other.blocked.test"})
	if n != 2 {
		t.Fatalf("seeded=%d want 2", n)
	}
	// Hot path should hit without relying on further disk I/O semantics.
	if h, ok := e.Lookup("hot.blocked.test"); !ok || h.Action != ActionNXDOMAIN {
		t.Fatalf("lookup after seed: ok=%v hit=%v", ok, h)
	}
}

func TestHotSeedFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, HotSeedPath)
	if err := WriteHotSeed(path, []string{"a.example.", "b.example"}); err != nil {
		t.Fatal(err)
	}
	names, err := ReadHotSeed(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 {
		t.Fatalf("names=%v", names)
	}
}
