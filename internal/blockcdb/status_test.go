package blockcdb

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCleanStaleTmpRemovesOnlyTempFiles(t *testing.T) {
	data := t.TempDir()
	dir := Dir(data)
	live := map[string]string{
		CDBFile:                    "live cdb",
		DomainsFile:                "live txt",
		MetaFile:                   `{"cdb":1}`,
		"whitelist.cdb":            "wl",
		"banks.lua":                "lua",
		"feeds/policy-1234.txt":    "feed",
		"feeds/manifest.txt":       "m",
		"notes.tmp.keep":           "not a temp file",
		"seed-manifest.json":       "{}",
		RebuildPendingFile:         "x",
		"feeds/policy-1234.txt.gz": "gz",
	}
	for name, body := range live {
		writeFile(t, filepath.Join(dir, name), body)
	}
	stale := map[string]string{
		CDBFile + ".tmp":            "partial cdb partial cdb",
		DomainsFile + ".tmp":        "partial",
		"banks.lua.tmp":             "x",
		"feeds/policy-1234.txt.tmp": "half",
		"whitelist.cdb.tmp":         "y",
	}
	for name, body := range stale {
		writeFile(t, filepath.Join(dir, name), body)
	}
	if err := os.MkdirAll(filepath.Join(dir, "dir.tmp"), 0o755); err != nil { // a directory is never removed
		t.Fatal(err)
	}

	removed := CleanStaleTmp(data)
	if len(removed) != len(stale) {
		t.Fatalf("removed %d files, want %d: %+v", len(removed), len(stale), removed)
	}
	var want int64
	for _, b := range stale {
		want += int64(len(b))
	}
	if TotalBytes(removed) != want {
		t.Fatalf("freed %d bytes, want %d", TotalBytes(removed), want)
	}
	for name := range stale {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s should be gone (%v)", name, err)
		}
	}
	for name, body := range live {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(got) != body {
			t.Fatalf("live file %s changed or missing: %v %q", name, err, got)
		}
	}
	if st, err := os.Stat(filepath.Join(dir, "dir.tmp")); err != nil || !st.IsDir() {
		t.Fatal("directory named *.tmp must be left alone")
	}
	if again := CleanStaleTmp(data); len(again) != 0 {
		t.Fatalf("second clean removed %v", again)
	}
}

func TestCleanRebuildTmpLeavesOtherWritersAlone(t *testing.T) {
	data := t.TempDir()
	dir := Dir(data)
	for _, name := range []string{CDBFile + ".tmp", DomainsFile + ".tmp", "feeds/a-1.txt.tmp", "banks.lua.tmp", "whitelist.cdb.tmp"} {
		writeFile(t, filepath.Join(dir, name), "x")
	}
	removed := CleanRebuildTmp(data)
	if len(removed) != 3 {
		t.Fatalf("removed %d, want 3: %+v", len(removed), removed)
	}
	for _, name := range []string{"banks.lua.tmp", "whitelist.cdb.tmp"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("%s belongs to another writer and must stay: %v", name, err)
		}
	}
}

// cancelAfter reports an error from Err once it was asked n times, so a build is cut off
// part-way, deterministically.
type cancelAfter struct {
	context.Context
	n, calls int
}

func (c *cancelAfter) Err() error {
	c.calls++
	if c.calls > c.n {
		return context.Canceled
	}
	return nil
}

func bigNames(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("host-%d.blocked.example", i)
	}
	return out
}

func TestInterruptedRebuildKeepsPreviousCDBAndLeavesNoTmp(t *testing.T) {
	data := t.TempDir()
	dir := Dir(data)
	if _, _, err := SyncNames(data, []string{"old-one.example", "old-two.example"}); err != nil {
		t.Fatal(err)
	}
	cdbPath := filepath.Join(dir, CDBFile)
	before, err := os.ReadFile(cdbPath)
	if err != nil {
		t.Fatal(err)
	}

	names := bigNames(3 * ctxCheckEvery)
	pre, cancel := context.WithCancel(context.Background())
	cancel()
	cases := map[string]context.Context{
		"cancelled before start": pre,
		"cut off mid-build":      &cancelAfter{Context: context.Background(), n: 2},
		"cut off at the end":     &cancelAfter{Context: context.Background(), n: 3},
	}
	for name, ctx := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := BuildCDBContext(ctx, cdbPath, names)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("err=%v, want context.Canceled", err)
			}
			if _, err := os.Stat(cdbPath + ".tmp"); !os.IsNotExist(err) {
				t.Fatalf("partial .tmp left behind: %v", err)
			}
			after, err := os.ReadFile(cdbPath)
			if err != nil || string(after) != string(before) {
				t.Fatalf("previous CDB changed after an interrupted build: %v", err)
			}
		})
	}

	// Whole sync: domains.txt is written first, then the CDB; cancelling leaves no temp file.
	_, _, err = SyncNamesContext(&cancelAfter{Context: context.Background(), n: 5}, data, names)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("SyncNamesContext err=%v", err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
	after, _ := os.ReadFile(cdbPath)
	if string(after) != string(before) {
		t.Fatal("previous CDB changed after an interrupted sync")
	}
}

func TestBuildCDBContextCompletesAndMatchesBuildCDB(t *testing.T) {
	dir := t.TempDir()
	names := append(bigNames(2*ctxCheckEvery+7), "DUP.example.", "dup.example", "localhost", "")
	n1, err := BuildCDB(filepath.Join(dir, "a.cdb"), names)
	if err != nil {
		t.Fatal(err)
	}
	n2, err := BuildCDBContext(context.Background(), filepath.Join(dir, "b.cdb"), names)
	if err != nil || n1 != n2 {
		t.Fatalf("n1=%d n2=%d err=%v", n1, n2, err)
	}
	a, _ := os.ReadFile(filepath.Join(dir, "a.cdb"))
	b, _ := os.ReadFile(filepath.Join(dir, "b.cdb"))
	if string(a) != string(b) {
		t.Fatal("outputs differ")
	}
	if !cdbContains(t, filepath.Join(dir, "a.cdb"), "dup.example") || !cdbContains(t, filepath.Join(dir, "a.cdb"), "host-5.blocked.example") {
		t.Fatal("keys missing")
	}
}

func TestSyncStatusRoundTrip(t *testing.T) {
	data := t.TempDir()
	if _, ok := ReadSyncStatus(data); ok {
		t.Fatal("no status expected yet")
	}
	want := SyncStatus{Status: SyncFailed, Reason: "manual reload", StartedAt: time.Unix(100, 0).UTC(), FinishedAt: time.Unix(105, 0).UTC(), DurationMS: 5000, Entries: 42, Error: "axfr: refused, with \"quotes\", and commas"}
	if err := WriteSyncStatus(data, want); err != nil {
		t.Fatal(err)
	}
	got, ok := ReadSyncStatus(data)
	if !ok || got != want {
		t.Fatalf("got %+v ok=%v want %+v", got, ok, want)
	}
	if _, err := os.Stat(filepath.Join(Dir(data), SyncStatusFile+".tmp")); !os.IsNotExist(err) {
		t.Fatal("status temp file left behind")
	}
}
