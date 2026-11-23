package watchdog

import (
	"runtime"
	"testing"
)

func TestParseGoMemLimit(t *testing.T) {
	if parseGoMemLimit("4294967296B") != 4294967296 {
		t.Fatal(parseGoMemLimit("4294967296B"))
	}
	if parseGoMemLimit("4GiB") != 4<<30 {
		t.Fatal(parseGoMemLimit("4GiB"))
	}
	if parseGoMemLimit("") != 0 {
		t.Fatal("empty")
	}
}

func newTestMonitor(limit uint64, samples *[]sample) (*monitor, *[]int) {
	var exits []int
	i := 0
	return &monitor{
		limit: limit,
		read: func() sample {
			s := (*samples)[i%len(*samples)]
			i++
			return s
		},
		exit: func(code int) { exits = append(exits, code) },
	}, &exits
}

const mb = 1 << 20

// After a rebuild Go keeps reporting a high Sys (retained and already released heap) while the
// memory in use is small; that must never get the process killed.
func TestHighSysWithLowInUseDoesNotExit(t *testing.T) {
	samples := []sample{{InUse: 60 * mb, HeapInuse: 30 * mb, Sys: 2829 * mb}}
	m, exits := newTestMonitor(2126*mb, &samples)
	for i := 0; i < 10*overStreak; i++ {
		m.check()
	}
	if len(*exits) != 0 || m.bad != 0 {
		t.Fatalf("exited %v, streak %d, for in-use memory far below the limit", *exits, m.bad)
	}
}

func TestInUseOverLimitExitsAfterStreak(t *testing.T) {
	samples := []sample{{InUse: 2600 * mb, HeapInuse: 2500 * mb, Sys: 2829 * mb}}
	m, exits := newTestMonitor(2126*mb, &samples)
	for i := 0; i < overStreak-1; i++ {
		m.check()
	}
	if len(*exits) != 0 {
		t.Fatalf("exited after %d samples, want %d", overStreak-1, overStreak)
	}
	m.check()
	if len(*exits) != 1 || (*exits)[0] != 2 {
		t.Fatalf("exits=%v, want one exit with code 2", *exits)
	}
}

func TestRecoveryResetsStreak(t *testing.T) {
	over := sample{InUse: 3000 * mb}
	ok := sample{InUse: 100 * mb}
	var seq []sample
	for i := 0; i < overStreak-1; i++ {
		seq = append(seq, over)
	}
	seq = append(seq, ok)
	for i := 0; i < overStreak-1; i++ {
		seq = append(seq, over)
	}
	m, exits := newTestMonitor(2126*mb, &seq)
	for range seq {
		m.check()
	}
	if len(*exits) != 0 {
		t.Fatalf("exited although memory dropped back in between: %v", *exits)
	}
}

// The limit is compared with a 15% margin, as before.
func TestMarginAboveLimitIsTolerated(t *testing.T) {
	samples := []sample{{InUse: 1100 * mb}}
	m, exits := newTestMonitor(1000*mb, &samples)
	for i := 0; i < 3*overStreak; i++ {
		m.check()
	}
	if len(*exits) != 0 {
		t.Fatalf("exited at 110%% of the limit: %v", *exits)
	}
}

// readSample must count what the process really holds: a live 64 MB allocation shows up in
// InUse, and Sys stays at least as large as InUse.
func TestReadSampleSeesLiveMemory(t *testing.T) {
	runtime.GC()
	before := readSample()
	keep := make([]byte, 64*mb)
	for i := 0; i < len(keep); i += 4096 {
		keep[i] = 1
	}
	after := readSample()
	runtimeKeepAlive(keep)
	if int64(after.InUse)-int64(before.InUse) < 48*mb {
		t.Fatalf("InUse grew %d MB for a 64 MB live allocation", (int64(after.InUse)-int64(before.InUse))/mb)
	}
	if after.Sys < after.InUse {
		t.Fatalf("Sys %d < InUse %d", after.Sys, after.InUse)
	}
}

//go:noinline
func runtimeKeepAlive(b []byte) { _ = b[0] }
