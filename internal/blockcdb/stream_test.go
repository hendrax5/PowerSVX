package blockcdb

import (
	"bufio"
	"crypto/sha256"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// referenceRebuild is the in-memory rebuild the Control Plane used before the streaming one:
// read every feed cache into one slice, FilterBlockNames, SyncNamesGuardedContext. It is the
// byte-for-byte reference for SyncFeedFilesGuardedContext.
func referenceRebuild(t testing.TB, dataDir string, feeds []string) (int, int, error) {
	t.Helper()
	var all []string
	for _, fp := range feeds {
		f, err := os.Open(fp)
		if err != nil {
			return 0, 0, err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 1<<20), 8<<20)
		for sc.Scan() {
			line := strings.ToLower(strings.TrimSpace(sc.Text()))
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			all = append(all, line)
		}
		_ = f.Close()
		if err := sc.Err(); err != nil {
			return 0, 0, err
		}
	}
	return SyncNamesGuardedContext(context.Background(), dataDir, FilterBlockNames(all))
}

func writeFeed(t testing.TB, path string, lines []string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t testing.TB, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func assertNoTmp(t testing.TB, dir string) {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Fatalf("temporary file left behind: %s", e.Name())
		}
	}
}

func TestStreamingRebuildWritesTheSameBytesAsTheInMemoryOne(t *testing.T) {
	work := t.TempDir()
	feedA := filepath.Join(work, "a.txt")
	feedB := filepath.Join(work, "b.txt")
	writeFeed(t, feedA, []string{
		"# comment line",
		"",
		"Evil.Example",
		"evil.example.",
		"  spaced.example  ",
		"*.wild.example",
		"wild.example",
		"UPPER.Case.Example.",
		"double.dot.example..",
		"localhost",
		"localhost.",
		"*.localhost",
		"bca.co.id",
		"www.bca.co.id",
		"phish-bca.co.id.example",
		"crlf.example\r",
		"first.example",
		"second.example",
		"first.example",
		"idn-bücher.example",
		"a",
	})
	writeFeed(t, feedB, []string{
		"second.example",
		"EVIL.example",
		"third.example",
		"UPPER.CASE.EXAMPLE",
		"fourth.example.",
		"*.first.example",
	})

	ref, got := t.TempDir(), t.TempDir()
	rn, rc, rerr := referenceRebuild(t, ref, []string{feedA, feedB})
	gn, gc, gerr := SyncFeedFilesGuardedContext(context.Background(), got, []string{feedA, feedB})
	if rerr != nil || gerr != nil {
		t.Fatalf("reference err=%v streaming err=%v", rerr, gerr)
	}
	if rn != gn || rc != gc {
		t.Fatalf("counts differ: reference %d/%d streaming %d/%d", rn, rc, gn, gc)
	}
	if rn < 10 {
		t.Fatalf("fixture produced only %d names", rn)
	}
	for _, name := range []string{CDBFile, DomainsFile, MetaFile} {
		a := mustRead(t, filepath.Join(Dir(ref), name))
		b := mustRead(t, filepath.Join(Dir(got), name))
		if string(a) != string(b) {
			t.Fatalf("%s differs (reference %d bytes, streaming %d bytes)", name, len(a), len(b))
		}
	}
	cdb := filepath.Join(Dir(got), CDBFile)
	for _, gone := range []string{"bca.co.id", "www.bca.co.id", "localhost"} {
		if cdbContains(t, cdb, gone) {
			t.Fatalf("%q must not be in the CDB", gone)
		}
	}
	for _, want := range []string{"evil.example", "spaced.example", "wild.example", "upper.case.example", "double.dot.example", "crlf.example", "first.example", "idn-bücher.example", "a", "fourth.example", "phish-bca.co.id.example"} {
		if !cdbContains(t, cdb, want) {
			t.Fatalf("%q missing from the CDB", want)
		}
	}
	assertNoTmp(t, Dir(got))
}

// Many names, so the de-duplication table grows and names are compared from disk, not only
// from the in-memory buffer.
func TestStreamingRebuildLargeInputMatchesReference(t *testing.T) {
	work := t.TempDir()
	feedA := filepath.Join(work, "a.txt")
	feedB := filepath.Join(work, "b.txt")
	n := 150000
	a := make([]string, 0, n)
	for i := 0; i < n; i++ {
		a = append(a, fmt.Sprintf("Host-%d.Blocked.Example.", i))
	}
	b := make([]string, 0, n)
	for i := n / 2; i < n+n/2; i++ {
		b = append(b, fmt.Sprintf("host-%d.blocked.example", i))
	}
	writeFeed(t, feedA, a)
	writeFeed(t, feedB, b)

	ref, got := t.TempDir(), t.TempDir()
	if _, _, err := referenceRebuild(t, ref, []string{feedA, feedB}); err != nil {
		t.Fatal(err)
	}
	gn, _, err := SyncFeedFilesGuardedContext(context.Background(), got, []string{feedA, feedB})
	if err != nil {
		t.Fatal(err)
	}
	if gn != n+n/2 {
		t.Fatalf("got %d unique names, want %d", gn, n+n/2)
	}
	for _, name := range []string{CDBFile, DomainsFile, MetaFile} {
		if string(mustRead(t, filepath.Join(Dir(ref), name))) != string(mustRead(t, filepath.Join(Dir(got), name))) {
			t.Fatalf("%s differs from the in-memory rebuild", name)
		}
	}
}

func TestStreamingRebuildRefusesToWipeAndKeepsFiles(t *testing.T) {
	data := t.TempDir()
	if _, _, err := SyncNames(data, []string{"old-one.example", "old-two.example"}); err != nil {
		t.Fatal(err)
	}
	before := mustRead(t, filepath.Join(Dir(data), CDBFile))
	empty := filepath.Join(t.TempDir(), "empty.txt")
	writeFeed(t, empty, []string{"# nothing", "localhost", "bca.co.id"})
	if _, _, err := SyncFeedFilesGuardedContext(context.Background(), data, []string{empty}); err == nil {
		t.Fatal("an empty rebuild replaced a useful CDB")
	}
	if string(mustRead(t, filepath.Join(Dir(data), CDBFile))) != string(before) {
		t.Fatal("CDB changed by a refused rebuild")
	}
	assertNoTmp(t, Dir(data))
}

func TestStreamingRebuildMissingFeedKeepsFiles(t *testing.T) {
	data := t.TempDir()
	if _, _, err := SyncNames(data, []string{"old.example"}); err != nil {
		t.Fatal(err)
	}
	before := mustRead(t, filepath.Join(Dir(data), CDBFile))
	if _, _, err := SyncFeedFilesGuardedContext(context.Background(), data, []string{filepath.Join(t.TempDir(), "nope.txt")}); err == nil {
		t.Fatal("expected an error for a missing feed cache")
	}
	if string(mustRead(t, filepath.Join(Dir(data), CDBFile))) != string(before) {
		t.Fatal("CDB changed")
	}
	assertNoTmp(t, Dir(data))
}

// cancelAt reports cancellation from its n-th Err call on.
type cancelAt struct {
	context.Context
	n     int32
	calls atomic.Int32
}

func (c *cancelAt) Err() error {
	if c.calls.Add(1) >= c.n {
		return context.Canceled
	}
	return nil
}

func TestStreamingRebuildCancelKeepsLiveFilesAndLeavesNoTmp(t *testing.T) {
	data := t.TempDir()
	if _, _, err := SyncNames(data, []string{"old-one.example", "old-two.example"}); err != nil {
		t.Fatal(err)
	}
	cdb := mustRead(t, filepath.Join(Dir(data), CDBFile))
	txt := mustRead(t, filepath.Join(Dir(data), DomainsFile))
	feed := filepath.Join(t.TempDir(), "f.txt")
	writeFeed(t, feed, bigNames(5*ctxCheckEvery))
	for _, at := range []int32{1, 2, 3, 5, 7, 9} {
		_, _, err := SyncFeedFilesGuardedContext(&cancelAt{Context: context.Background(), n: at}, data, []string{feed})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel at call %d: err=%v", at, err)
		}
		assertNoTmp(t, Dir(data))
		if string(mustRead(t, filepath.Join(Dir(data), CDBFile))) != string(cdb) ||
			string(mustRead(t, filepath.Join(Dir(data), DomainsFile))) != string(txt) {
			t.Fatalf("live files changed by a rebuild cancelled at call %d", at)
		}
	}
}

func TestCleanRebuildTmpRemovesNamesScratch(t *testing.T) {
	data := t.TempDir()
	dir := Dir(data)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, NamesScratchFile), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if removed := CleanRebuildTmp(data); len(removed) != 1 {
		t.Fatalf("removed %v", removed)
	}
}

// peakHeap runs fn and returns the highest HeapAlloc (live plus not yet collected heap) seen
// while it ran, minus the heap in use before it started.
func peakHeap(fn func()) uint64 {
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	var peak atomic.Uint64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var ms runtime.MemStats
		for {
			runtime.ReadMemStats(&ms)
			if ms.HeapAlloc > peak.Load() {
				peak.Store(ms.HeapAlloc)
			}
			select {
			case <-stop:
				return
			case <-time.After(2 * time.Millisecond):
			}
		}
	}()
	fn()
	close(stop)
	wg.Wait()
	if p := peak.Load(); p > base.HeapAlloc {
		return p - base.HeapAlloc
	}
	return 0
}

func syntheticFeed(t testing.TB, path string, n, dupEvery int) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := bufio.NewWriterSize(f, 1<<20)
	for i := 0; i < n; i++ {
		k := i
		if dupEvery > 0 && i%dupEvery == 0 && i > 0 {
			k = i / 2 // a name written before
		}
		fmt.Fprintf(w, "host-%d.blocked.example\n", k)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
}

// The rebuild must not hold the names in memory: a regression to a slice of names plus a seen
// map costs well over 100 bytes per name (see TestRebuildMemoryReport) and fails this bound.
const fixedOverhead = 8 << 20 // the rebuild's 1 MB I/O buffers and the scanner's line buffer

func TestStreamingRebuildMemoryIsBoundedPerName(t *testing.T) {
	n := 1_000_000
	if testing.Short() {
		n = 200_000
	}
	feed := filepath.Join(t.TempDir(), "big.txt")
	syntheticFeed(t, feed, n, 5)
	data := t.TempDir()
	var got int
	peak := peakHeap(func() {
		var err error
		got, _, err = SyncFeedFilesGuardedContext(context.Background(), data, []string{feed})
		if err != nil {
			t.Error(err)
		}
	})
	if peak < fixedOverhead {
		peak = fixedOverhead
	}
	if got < n*7/10 {
		t.Fatalf("only %d names written", got)
	}
	perName := float64(peak-fixedOverhead) / float64(n)
	t.Logf("peak heap %.1f MB for %d names (%.1f bytes/name above %d MB fixed buffers)", float64(peak)/(1<<20), n, perName, fixedOverhead>>20)
	if perName > 40 {
		t.Fatalf("peak heap %.1f bytes per name; the streaming rebuild should stay well under 40", perName)
	}
}

// TestRebuildMemoryReport prints the peak of the streaming rebuild, or with
// POWERSVX_REBUILD_REPORT_OLD=1 of the former in-memory one, for POWERSVX_REBUILD_REPORT=<names>
// synthetic names. It checks nothing; it produces the numbers quoted in the pull request.
func TestRebuildMemoryReport(t *testing.T) {
	v := os.Getenv("POWERSVX_REBUILD_REPORT")
	if v == "" {
		t.Skip("set POWERSVX_REBUILD_REPORT=<number of names> to run")
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		t.Fatal(err)
	}
	feed := filepath.Join(t.TempDir(), "big.txt")
	syntheticFeed(t, feed, n, 50)
	dir := t.TempDir()
	label := "streaming"
	fn := func() {
		if _, _, err := SyncFeedFilesGuardedContext(context.Background(), dir, []string{feed}); err != nil {
			t.Fatal(err)
		}
	}
	if os.Getenv("POWERSVX_REBUILD_REPORT_OLD") != "" {
		label = "in-memory"
		fn = func() {
			if _, _, err := referenceRebuild(t, dir, []string{feed}); err != nil {
				t.Fatal(err)
			}
		}
	}
	start := time.Now()
	var sys uint64
	peak := peakHeap(func() {
		fn()
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		sys = ms.Sys
	})
	t.Logf("%s: names=%d peak_heap=%d MB sys=%d MB time=%s %s", label, n, peak>>20, sys>>20, time.Since(start).Round(time.Millisecond), vmHWM())
	for _, name := range []string{CDBFile, DomainsFile} {
		sum := fileSHA256(t, filepath.Join(Dir(dir), name))
		t.Logf("%s: %s sha256=%x", label, name, sum)
	}
}

func vmHWM() string {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return "VmHWM n/a"
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "VmHWM:") {
			return "VmHWM " + strings.Join(strings.Fields(strings.TrimPrefix(l, "VmHWM:")), " ")
		}
	}
	return "VmHWM n/a"
}

func fileSHA256(t testing.TB, path string) [sha256.Size]byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	var sum [sha256.Size]byte
	copy(sum[:], h.Sum(nil))
	return sum
}
