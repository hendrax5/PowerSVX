package api

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The IXFR merge must give the same set the former map-based merge gave: base names minus the
// removed ones, plus the added ones, each once, normalised.
func TestMergeFeedFileAppliesAnIXFRDelta(t *testing.T) {
	path := filepath.Join(t.TempDir(), "feed.txt")
	base := "keep.example\nDrop.Example\n# comment\n\nreadd.example\nalready.example\nkeep2.example\n"
	if err := os.WriteFile(path, []byte(base), 0o644); err != nil {
		t.Fatal(err)
	}
	n, err := mergeFeedFile(path,
		[]string{"drop.example.", "readd.example", "never-there.example"},
		[]string{"New.Example.", "already.example", "readd.example", "new.example", "", "other.example"})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	got := strings.Split(strings.TrimSpace(string(b)), "\n")
	want := []string{"keep.example", "already.example", "keep2.example", "new.example", "readd.example", "other.example"}
	if strings.Join(got, ",") != strings.Join(want, ",") || n != len(want) {
		t.Fatalf("got %v (n=%d), want %v", got, n, want)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp file left behind")
	}
}

func TestMergeFeedFileMissingFeedReportsErrorAndWritesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.txt")
	if _, err := mergeFeedFile(path, nil, []string{"a.example"}); err == nil {
		t.Fatal("expected an error so the caller falls back to a full transfer")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("a file appeared for a missing feed: %v", err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp file left behind")
	}
}

// Merging a delta into a large feed must cost memory for the delta, not for the feed: the former
// merge built a map of every name (over 100 bytes each).
func TestMergeFeedFileMemoryDoesNotGrowWithTheFeed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.txt")
	var sb strings.Builder
	const n = 600000
	for i := 0; i < n; i++ {
		fmt.Fprintf(&sb, "host-%d.blocked.example\n", i)
	}
	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	sb.Reset()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if _, err := mergeFeedFile(path, []string{"host-5.blocked.example"}, []string{"added.example"}); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	// TotalAlloc counts everything allocated, garbage included: the scanner's line strings are
	// short-lived, so the bound is on total allocation, generous but far under a map's cost.
	if grew := after.TotalAlloc - before.TotalAlloc; grew > uint64(n)*64 {
		t.Fatalf("merge allocated %d bytes for %d names", grew, n)
	}
}
