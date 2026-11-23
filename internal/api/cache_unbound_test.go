package api

import (
	"bufio"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeUnboundControl speaks Unbound's remote-control protocol on a loopback port
// and records the commands it receives, so the Cache Explorer can be tested
// against the interface it uses on the dnsdist Dataplane.
func fakeUnboundControl(t *testing.T, replies map[string]string) func() []string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	t.Setenv("POWERSVX_UNBOUND_CONTROL", ln.Addr().String())
	t.Setenv("POWERSVX_DNS_DATAPLANE", "dnsdist")
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

func TestCacheExplorerWorksOnTheDnsdistDataplane(t *testing.T) {
	commands := fakeUnboundControl(t, map[string]string{
		"stats_noreset": "total.num.queries=200\ntotal.num.cachehits=150\ntotal.num.cachemiss=50\n",
		"dump_cache":    "START_RRSET_CACHE\nexample.com.\t300\tIN\tA\t192.0.2.1\nother.net.\t300\tIN\tA\t192.0.2.2\nEND_RRSET_CACHE\n",
	})
	a := &API{}

	rr := httptest.NewRecorder()
	a.handleCacheStats(rr, httptest.NewRequest(http.MethodGet, "/api/v1/cache/stats", nil))
	var stats struct {
		Unbound   struct {
			Status    string  `json:"status"`
			Queries   float64 `json:"queries"`
			HitRatio  float64 `json:"hit_ratio"`
			CacheHits float64 `json:"cache_hits"`
		} `json:"unbound"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &stats); err != nil {
		t.Fatal(err)
	}
	if stats.Unbound.Status != "ok" || stats.Unbound.Queries != 200 || stats.Unbound.HitRatio != 0.75 {
		t.Fatalf("unexpected cache stats: %s", rr.Body.String())
	}

	rr = httptest.NewRecorder()
	a.handleCacheInspect(rr, httptest.NewRequest(http.MethodGet, "/api/v1/cache/inspect?q=example.com", nil))
	var inspect struct {
		Entries []string `json:"entries"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &inspect); err != nil {
		t.Fatal(err)
	}
	if len(inspect.Entries) != 1 || !strings.HasPrefix(inspect.Entries[0], "example.com.") {
		t.Fatalf("unexpected cache entries: %s", rr.Body.String())
	}

	for _, body := range []string{
		`{"scope":"domain","domain":"example.com"}`,
		`{"scope":"zone","domain":"example.com"}`,
		`{"scope":"type","domain":"example.com","type":"A"}`,
		`{"scope":"negative"}`,
		`{"scope":"all"}`,
	} {
		rr = httptest.NewRecorder()
		a.handleCacheFlush(rr, httptest.NewRequest(http.MethodPost, "/api/v1/cache/flush", strings.NewReader(body)))
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: status %d: %s", body, rr.Code, rr.Body.String())
		}
	}
	got := strings.Join(commands(), "|")
	for _, want := range []string{"flush example.com.", "flush_zone example.com.", "flush_type example.com. A", "flush_negative", "flush_zone ."} {
		if !strings.Contains(got, want) {
			t.Errorf("Unbound never received %q; got %s", want, got)
		}
	}
}
