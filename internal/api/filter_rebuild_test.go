package api

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/blockcdb"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/rpz"
	"github.com/powersvx/powersvx/internal/server"
)

func newRebuildAPI(dir string) *API {
	return &API{
		cfg: &config.Config{}, srv: &server.Server{}, dataDir: dir,
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func hostsPolicy(t *testing.T, dir string, names ...string) rpz.PolicyConfig {
	t.Helper()
	p := filepath.Join(dir, "hosts-src.txt")
	var b strings.Builder
	for _, n := range names {
		b.WriteString("0.0.0.0 " + n + "\n")
	}
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return rpz.PolicyConfig{Name: "lab-hosts", Format: "hosts", Source: p}
}

func noTmpFiles(t *testing.T, data string) {
	t.Helper()
	dir := blockcdb.Dir(data)
	for _, sub := range []string{"", "feeds"} {
		entries, _ := os.ReadDir(filepath.Join(dir, sub))
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".tmp") {
				t.Fatalf("temp file left behind: %s/%s", sub, e.Name())
			}
		}
	}
}

func TestFilterRebuildRecordsOKFailedAndInterrupted(t *testing.T) {
	data := t.TempDir()
	a := newRebuildAPI(data)
	pol := hostsPolicy(t, data, "ads-one.example", "ads-two.example")
	cdbPath := filepath.Join(blockcdb.Dir(data), blockcdb.CDBFile)

	// ok
	n, err := a.runFilterRebuild(context.Background(), []rpz.PolicyConfig{pol}, "manual reload")
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	st, ok := blockcdb.ReadSyncStatus(data)
	if !ok || st.Status != blockcdb.SyncOK || st.Entries != 2 || st.Reason != "manual reload" || st.Error != "" || st.FinishedAt.IsZero() {
		t.Fatalf("ok status: %+v", st)
	}
	good, err := os.ReadFile(cdbPath)
	if err != nil {
		t.Fatal(err)
	}
	if blockcdb.RebuildPending(data) {
		t.Fatal("pending marker must be cleared after a finished rebuild")
	}

	// failed: the hosts source is gone; the last good CDB keeps serving.
	bad := rpz.PolicyConfig{Name: "lab-hosts", Format: "hosts", Source: filepath.Join(data, "missing-hosts.txt")}
	if _, err := a.runFilterRebuild(context.Background(), []rpz.PolicyConfig{bad}, "scheduled hosts refresh"); err == nil {
		t.Fatal("expected an error")
	}
	st, _ = blockcdb.ReadSyncStatus(data)
	if st.Status != blockcdb.SyncFailed || st.Error == "" || st.Entries != 2 {
		t.Fatalf("failed status: %+v", st)
	}
	if got, _ := os.ReadFile(cdbPath); string(got) != string(good) {
		t.Fatal("last good CDB changed after a failed rebuild")
	}
	noTmpFiles(t, data)

	// interrupted: cancelled context (shutdown).
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.runFilterRebuild(ctx, []rpz.PolicyConfig{pol}, "startup"); err == nil {
		t.Fatal("expected an error")
	}
	st, _ = blockcdb.ReadSyncStatus(data)
	if st.Status != blockcdb.SyncInterrupted || st.Error == "" || st.Entries != 2 {
		t.Fatalf("interrupted status: %+v", st)
	}
	if got, _ := os.ReadFile(cdbPath); string(got) != string(good) {
		t.Fatal("last good CDB changed after an interrupted rebuild")
	}
	noTmpFiles(t, data)
}

func TestRPZPayloadShowsLastFilterSync(t *testing.T) {
	data := t.TempDir()
	a := newRebuildAPI(data)
	if v := a.rpzPayload()["filter_sync"]; v != nil {
		t.Fatalf("no status expected before the first rebuild, got %v", v)
	}
	for _, want := range []string{blockcdb.SyncOK, blockcdb.SyncFailed, blockcdb.SyncInterrupted} {
		err := blockcdb.WriteSyncStatus(data, blockcdb.SyncStatus{Status: want, Reason: "t", Entries: 7, Error: "boom"})
		if err != nil {
			t.Fatal(err)
		}
		got, ok := a.rpzPayload()["filter_sync"].(blockcdb.SyncStatus)
		if !ok || got.Status != want || got.Entries != 7 {
			t.Fatalf("payload for %s: %+v", want, a.rpzPayload()["filter_sync"])
		}
	}
}

func TestCleanFilterTmpAtStartMarksCutOffRebuildInterrupted(t *testing.T) {
	data := t.TempDir()
	a := newRebuildAPI(data)
	if _, _, err := blockcdb.SyncNames(data, []string{"a.example", "b.example", "c.example"}); err != nil {
		t.Fatal(err)
	}
	dir := blockcdb.Dir(data)
	cdbPath := filepath.Join(dir, blockcdb.CDBFile)
	good, _ := os.ReadFile(cdbPath)
	if err := os.WriteFile(cdbPath+".tmp", []byte("half a cdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := blockcdb.WriteSyncStatus(data, blockcdb.SyncStatus{Status: blockcdb.SyncRunning, StartedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}

	a.CleanFilterTmp()

	noTmpFiles(t, data)
	if got, _ := os.ReadFile(cdbPath); string(got) != string(good) {
		t.Fatal("live CDB must be untouched")
	}
	st, _ := blockcdb.ReadSyncStatus(data)
	if st.Status != blockcdb.SyncInterrupted || st.Entries != 3 || st.Error == "" {
		t.Fatalf("status after a cut-off rebuild: %+v", st)
	}
}

func TestStopFilterSyncRefusesNewRebuilds(t *testing.T) {
	data := t.TempDir()
	a := newRebuildAPI(data)
	a.StopFilterSync(context.Background())
	if err := a.startDNSDistCDBRefresh(false, "late"); err == nil {
		t.Fatal("a rebuild must not start after shutdown began")
	}
}

// An interrupted run that already refreshed the feed cache must be finished on the next sync,
// even though the upstream serial did not move (SOA unchanged).
func TestPendingRebuildOverridesSOASkip(t *testing.T) {
	data := t.TempDir()
	zone := "pending.test."
	mux := dns.NewServeMux()
	mux.HandleFunc(zone, func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Answer = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60}, Ns: "ns." + zone, Mbox: "h." + zone, Serial: 100}}
		_ = w.WriteMsg(m)
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	defer func() { _ = srv.Shutdown() }()
	time.Sleep(30 * time.Millisecond)

	pol := rpz.PolicyConfig{Name: "kominfo", Format: "axfr", Zone: zone, Masters: []string{pc.LocalAddr().String()}}
	if err := writeFeedFileAtomic(feedCachePath(data, pol.Name), []string{"new-name.example"}); err != nil {
		t.Fatal(err)
	}
	st := rpz.LoadAxfrState(rpz.AxfrStatePath(data))
	_ = st.PutSuccess(pol.Name, zone, "full_axfr", pc.LocalAddr().String(), 100, "seeded")
	if _, _, err := blockcdb.SyncNames(data, []string{"old-name.example"}); err != nil {
		t.Fatal(err)
	}
	manifest := pol.Name + "|axfr|" + config.NormalizeName(zone) + "|"
	manifestPath := filepath.Join(blockcdb.Dir(data), "feeds", "manifest.txt")
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	a := newRebuildAPI(data)
	txt := filepath.Join(blockcdb.Dir(data), blockcdb.DomainsFile)

	// No pending marker: nothing changed upstream, so the SOA skip keeps the CDB as is.
	if _, err := a.pullAndWriteBlockCDB(context.Background(), []rpz.PolicyConfig{pol}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(txt); !strings.Contains(string(b), "old-name.example") {
		t.Fatalf("expected the SOA skip to keep the old CDB: %q", b)
	}

	// A previous run changed the feed and was cut off: the next sync must finish the CDB.
	if err := blockcdb.MarkRebuildPending(data); err != nil {
		t.Fatal(err)
	}
	n, err := a.pullAndWriteBlockCDB(context.Background(), []rpz.PolicyConfig{pol})
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if b, _ := os.ReadFile(txt); !strings.Contains(string(b), "new-name.example") || strings.Contains(string(b), "old-name.example") {
		t.Fatalf("CDB not rebuilt from the refreshed feed: %q", b)
	}
	if blockcdb.RebuildPending(data) {
		t.Fatal("marker must be cleared once the CDB is rebuilt")
	}
}
