package unboundrpz

import (
	"bufio"
	"net"
	"strings"
	"sync"
	"testing"
)

func TestControlCommandEmpty(t *testing.T) {
	if _, err := ControlCommand(""); err == nil {
		t.Fatal("expected error for empty command")
	}
}

// fakeUnbound answers the remote-control protocol (one "UBCT1 <command>" line per
// connection) and records the commands it receives.
func fakeUnbound(t *testing.T, replies map[string]string) (commands func() []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	t.Setenv("POWERSVX_UNBOUND_CONTROL", ln.Addr().String())
	var mu sync.Mutex
	var got []string
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				line, _ := bufio.NewReader(c).ReadString('\n')
				cmd := strings.TrimSpace(strings.TrimPrefix(line, "UBCT1 "))
				mu.Lock()
				got = append(got, cmd)
				mu.Unlock()
				reply, ok := replies[cmd]
				if !ok {
					reply = "ok\n"
				}
				c.Write([]byte(reply))
			}()
		}
	}()
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), got...)
	}
}

func TestStatsReadsUnboundControl(t *testing.T) {
	fakeUnbound(t, map[string]string{
		"stats_noreset": "total.num.queries=120\ntotal.num.cachehits=90\ntotal.num.cachemiss=30\nnum.query.type.A=100\nthread0.something=1\nnot a stat\n",
	})
	st, err := Stats()
	if err != nil {
		t.Fatal(err)
	}
	if st["total.num.queries"] != 120 || st["total.num.cachehits"] != 90 || st["total.num.cachemiss"] != 30 || st["num.query.type.A"] != 100 {
		t.Fatalf("unexpected stats: %v", st)
	}
	if _, ok := st["thread0.something"]; ok {
		t.Fatalf("unlisted counter leaked: %v", st)
	}
}

func TestDumpCacheFiltersAndCaps(t *testing.T) {
	fakeUnbound(t, map[string]string{
		"dump_cache": "START_RRSET_CACHE\n;rrset 300 1 0 2 0\nexample.com.\t300\tIN\tA\t192.0.2.1\nother.net.\t300\tIN\tA\t192.0.2.2\nEND_RRSET_CACHE\nEOF\n",
	})
	lines, err := DumpCache("example.com", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "example.com.") {
		t.Fatalf("unexpected lines: %q", lines)
	}
}

func TestFlushCommands(t *testing.T) {
	commands := fakeUnbound(t, nil)
	if _, err := FlushDomain("Example.COM."); err != nil {
		t.Fatal(err)
	}
	if _, err := FlushZone("."); err != nil {
		t.Fatal(err)
	}
	if _, err := FlushType("example.com", "aaaa"); err != nil {
		t.Fatal(err)
	}
	if _, err := FlushNegative(); err != nil {
		t.Fatal(err)
	}
	want := []string{"flush example.com.", "flush_zone .", "flush_type example.com. AAAA", "flush_negative"}
	got := commands()
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("commands = %q, want %q", got, want)
	}
	if _, err := FlushDomain("bad domain;rm"); err == nil {
		t.Fatal("expected invalid domain error")
	}
}
