package authoritative

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func soa(serial string) Record {
	return Record{Name: "example.com.", Type: dns.TypeSOA, Content: "ns1.example.com. admin.example.com. " + serial + " 3600 600 86400 300", TTL: 3600}
}

func openStore(t *testing.T, dir string) *Store {
	t.Helper()
	s := NewStore()
	if _, err := s.EnablePersistence(dir); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestZoneChangesSurviveRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "zones")
	s := openStore(t, dir)
	s.CreateZone("Example.com")
	s.AddRecords("example.com.", []Record{soa("1"), {Name: "www.example.com.", Type: dns.TypeA, Content: "192.0.2.1", TTL: 60, View: "lan", GeoTag: "ID"}})
	s.AddRecord("example.com.", Record{Name: "mail.example.com.", Type: dns.TypeMX, Content: "mx.example.com.", TTL: 300, Prio: 10})
	s.AddRecord("example.com.", Record{Name: "x.example.com.", Type: 65280, Content: `\# 1 ff`, TTL: 60})
	on := true
	refresh := 7200
	if _, ok := s.UpdateZoneMeta("example.com", ZoneMetaPatch{DNSSECEnabled: &on, SOARefresh: &refresh}); !ok {
		t.Fatal("meta update failed")
	}
	s.CreateZone("gone.test")
	s.AddRecord("gone.test.", Record{Name: "a.gone.test.", Type: dns.TypeA, Content: "192.0.2.9", TTL: 60})
	if !s.DeleteZone("gone.test") {
		t.Fatal("delete zone")
	}
	if err := s.PersistError(); err != nil {
		t.Fatal(err)
	}
	wantRecs, _ := s.GetRecords("example.com.")
	wantMeta, _ := s.GetZoneMeta("example.com.")

	s2 := openStore(t, dir)
	if s2.ZoneCount() != 1 {
		t.Fatalf("zones after restart = %d, want 1 (deleted zone must stay deleted)", s2.ZoneCount())
	}
	gotRecs, ok := s2.GetRecords("example.com.")
	if !ok || !reflect.DeepEqual(gotRecs, wantRecs) {
		t.Fatalf("records after restart\n got %+v\nwant %+v", gotRecs, wantRecs)
	}
	gotMeta, _ := s2.GetZoneMeta("example.com.")
	if gotMeta != wantMeta || !gotMeta.DNSSECEnabled || gotMeta.SOARefresh != 7200 {
		t.Fatalf("meta after restart %+v want %+v", gotMeta, wantMeta)
	}
	if rrs, _ := s2.LookupScoped("www.example.com.", dns.TypeA, "lan", "ID"); len(rrs) != 1 {
		t.Fatal("record not served after restart")
	}

	s2.UpdateRecord("example.com.", "www.example.com.", dns.TypeA, Record{Name: "www.example.com.", Type: dns.TypeA, Content: "192.0.2.2", TTL: 60})
	s2.DeleteRecord("example.com.", "mail.example.com.", dns.TypeMX)
	s3 := openStore(t, dir)
	recs, _ := s3.GetRecords("example.com.")
	var sawNew, sawMX bool
	for _, r := range recs {
		sawNew = sawNew || r.Content == "192.0.2.2"
		sawMX = sawMX || r.Type == dns.TypeMX
	}
	if !sawNew || sawMX {
		t.Fatalf("update/delete not persisted: %+v", recs)
	}
	if _, err := os.Stat(filepath.Join(dir, ZoneFileName("gone.test"))); !os.IsNotExist(err) {
		t.Fatal("deleted zone file still present")
	}
}

func TestSecondaryZonesAreNotWrittenAsFiles(t *testing.T) {
	dir := t.TempDir()
	s := openStore(t, dir)
	s.UpsertZone("sec.test")
	s.ReplaceZoneRecords("sec.test.", []Record{{Name: "sec.test.", Type: dns.TypeA, Content: "192.0.2.3", TTL: 60}})
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("secondary zone leaked into zone files: %v", entries)
	}
}

func TestZoneFileNameIsSafeAndUnique(t *testing.T) {
	names := []string{"example.com.", "../../etc/passwd", "a/b.test.", `a\b.test.`, "..", ".", "con", "ünï.test.", "a_b.test.", "a b.test.", "a-b.test.", strings.Repeat("x", 300) + ".test."}
	seen := map[string]string{}
	for _, n := range names {
		f := ZoneFileName(n)
		if f != filepath.Base(f) || strings.ContainsAny(f, `/\:*?"<>|`) || strings.HasPrefix(f, ".") || !strings.HasSuffix(f, ".json") || len(f) > 255 {
			t.Errorf("unsafe file name %q for zone %q", f, n)
		}
		if prev, dup := seen[f]; dup {
			t.Errorf("collision: %q and %q -> %q", prev, n, f)
		}
		seen[f] = n
	}
}

func TestUnsafeZoneNamesRoundTripInsideDir(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "zones")
	s := openStore(t, dir)
	unsafe := []string{"../../escape", "a/b", "w e.test"}
	for _, n := range unsafe {
		s.CreateZone(n)
		s.AddRecord(n, Record{Name: "h." + n, Type: dns.TypeTXT, Content: "hi", TTL: 60})
	}
	if err := s.PersistError(); err != nil {
		t.Fatal(err)
	}
	var found []string
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			found = append(found, p)
		}
		return nil
	})
	if len(found) != 3 {
		t.Fatalf("want exactly 3 files, got %v", found)
	}
	for _, f := range found {
		if filepath.Dir(f) != dir {
			t.Fatalf("file escaped zones dir: %s", f)
		}
	}
	s2 := openStore(t, dir)
	for _, n := range unsafe {
		if recs, ok := s2.GetRecords(n); !ok || len(recs) != 1 {
			t.Fatalf("zone %q lost after restart", n)
		}
	}
}

func TestFailedWriteKeepsOldFileAndLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "z.json")
	if err := writeFileAtomic(target, []byte(`{"ok":1}`)); err != nil {
		t.Fatal(err)
	}
	// Rename onto a non-empty directory fails after the temp file was written.
	blocked := filepath.Join(dir, "blocked.json")
	if err := os.MkdirAll(filepath.Join(blocked, "child"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(blocked, []byte("new")); err == nil {
		t.Fatal("expected rename failure")
	}
	if b, _ := os.ReadFile(target); string(b) != `{"ok":1}` {
		t.Fatalf("existing file changed: %q", b)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
}

func TestPersistErrorSurfacesAndStoreRecovers(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "zones")
	s := openStore(t, dir)
	s.CreateZone("example.com")
	// Block the zone's file with a non-empty directory so the write fails.
	p := filepath.Join(dir, ZoneFileName("example.com"))
	_ = os.Remove(p)
	if err := os.MkdirAll(filepath.Join(p, "child"), 0o755); err != nil {
		t.Fatal(err)
	}
	s.AddRecord("example.com", Record{Name: "a.example.com.", Type: dns.TypeA, Content: "192.0.2.1", TTL: 60})
	if s.PersistError() == nil {
		t.Fatal("write failure must be reported")
	}
	if recs, _ := s.GetRecords("example.com"); len(recs) != 1 {
		t.Fatal("memory state must still serve")
	}
	_ = os.RemoveAll(p)
	s.AddRecord("example.com", Record{Name: "b.example.com.", Type: dns.TypeA, Content: "192.0.2.2", TTL: 60})
	if err := s.PersistError(); err != nil {
		t.Fatalf("next write should succeed: %v", err)
	}
}

func TestLoadSkipsCorruptAndTempFilesWithoutTouchingThem(t *testing.T) {
	dir := t.TempDir()
	s := openStore(t, dir)
	s.CreateZone("good.test")
	bad := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(bad, []byte(`{"version":1,"name":"bad.test.","reco`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, ".tmp-123"), []byte("half"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "future.json"), []byte(`{"version":99,"name":"f.test."}`), 0o644)

	s2 := NewStore()
	n, err := s2.EnablePersistence(dir)
	if n != 1 || err == nil || !strings.Contains(err.Error(), "bad.json") || !strings.Contains(err.Error(), "future.json") {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if b, _ := os.ReadFile(bad); !strings.HasPrefix(string(b), `{"version":1`) {
		t.Fatal("corrupt file must be left for the operator, not rewritten")
	}
}

type fakeSource struct {
	zones   map[string][]Record
	metas   map[string]ZoneMeta
	loadErr error
}

func (f *fakeSource) LoadZones(context.Context) (map[string][]Record, error) {
	return f.zones, f.loadErr
}
func (f *fakeSource) LoadZoneMeta(context.Context) (map[string]ZoneMeta, error) { return f.metas, nil }

func TestExportReproducesSourceAndRunsOnce(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "zones")
	src := &fakeSource{
		zones: map[string][]Record{
			"example.com.": {soa("7"), {Name: "www.example.com.", Type: dns.TypeA, Content: "192.0.2.1", TTL: 60, GeoTag: "ID", View: "lan"}, {Name: "example.com.", Type: dns.TypeMX, Content: "mx.example.com.", TTL: 300, Prio: 5}},
			"empty.test.":  nil,
		},
		metas: map[string]ZoneMeta{
			"example.com.": {Type: "native", DNSSECEnabled: true, SOASerial: 7, SOARefresh: 3600, SOARetry: 600, SOAExpire: 86400, SOAMinimum: 300},
			"empty.test.":  {Type: "native", SOASerial: 3, SOARefresh: 1, SOARetry: 2, SOAExpire: 3, SOAMinimum: 4},
		},
	}
	n, ran, err := ExportFromSource(context.Background(), src, dir)
	if err != nil || !ran || n != 2 {
		t.Fatalf("n=%d ran=%v err=%v", n, ran, err)
	}
	s := openStore(t, dir)
	for name, want := range src.zones {
		got, ok := s.GetRecords(name)
		if !ok || len(got) != len(want) || (len(want) > 0 && !reflect.DeepEqual(got, want)) {
			t.Fatalf("zone %s: got %+v want %+v", name, got, want)
		}
	}
	if m, _ := s.GetZoneMeta("empty.test."); m != src.metas["empty.test."] {
		t.Fatalf("meta %+v", m)
	}
	if m, _ := s.GetZoneMeta("example.com."); !m.DNSSECEnabled {
		t.Fatal("dnssec flag lost in export")
	}

	// Not twice: neither with the files present nor after every zone is deleted.
	src.zones["new.test."] = nil
	if _, ran, _ := ExportFromSource(context.Background(), src, dir); ran {
		t.Fatal("export ran twice")
	}
	s.DeleteZone("example.com.")
	s.DeleteZone("empty.test.")
	if _, ran, _ := ExportFromSource(context.Background(), src, dir); ran {
		t.Fatal("export re-ran after all zones were deleted")
	}
	if openStore(t, dir).ZoneCount() != 0 {
		t.Fatal("deleted zones came back from the database")
	}
}

func TestFailedExportLeavesNothingBehind(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "zones")

	src := &fakeSource{zones: map[string][]Record{"a.test.": nil}, loadErr: errors.New("db down")}
	if _, ran, err := ExportFromSource(context.Background(), src, dir); err == nil || ran {
		t.Fatalf("want error, ran=%v err=%v", ran, err)
	}

	// Part-way failure: the zones directory holds a foreign file, so the final move fails.
	_ = os.MkdirAll(dir, 0o755)
	stray := filepath.Join(dir, "notes.txt")
	_ = os.WriteFile(stray, []byte("x"), 0o644)
	src.loadErr = nil
	if _, ran, err := ExportFromSource(context.Background(), src, dir); err == nil || ran {
		t.Fatalf("want error, ran=%v err=%v", ran, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != "notes.txt" {
		t.Fatalf("zones dir changed by failed export: %v", entries)
	}
	if _, err := os.Stat(dir + ".export-tmp"); !os.IsNotExist(err) {
		t.Fatal("staging directory left behind")
	}
	if hasZoneState(dir) {
		t.Fatal("failed export must not look finished")
	}

	_ = os.Remove(stray)
	if n, ran, err := ExportFromSource(context.Background(), src, dir); err != nil || !ran || n != 1 {
		t.Fatalf("retry: n=%d ran=%v err=%v", n, ran, err)
	}
}

func servedSOA(t *testing.T, s *Store) string {
	t.Helper()
	rrs, ok := s.Lookup("example.com.", dns.TypeSOA)
	if !ok || len(rrs) != 1 {
		t.Fatalf("SOA lookup: ok=%v rrs=%v", ok, rrs)
	}
	return rrs[0].String()
}

// Before this change the SOA a resolver saw came from the stored SOA record
// only: the metadata columns never reached it, and each record change moved
// the serial forward by one. Metadata updates must not change either.
func TestMetaUpdateDoesNotChangeServedSOA(t *testing.T) {
	plain := NewStore() // behaviour of the base branch: no persistence, no metadata
	files := openStore(t, t.TempDir())
	plain.UpsertZone("example.com")
	plain.AddRecord("example.com", soa("5"))
	files.CreateZone("example.com")
	files.AddRecords("example.com", []Record{soa("5")})

	serial, refresh, minimum := int64(900), 7200, 60
	on := true
	files.UpdateZoneMeta("example.com", ZoneMetaPatch{SOASerial: &serial, SOARefresh: &refresh, SOAMinimum: &minimum, DNSSECEnabled: &on})
	if got, want := servedSOA(t, files), servedSOA(t, plain); got != want {
		t.Fatalf("metadata update changed the served SOA:\n got %s\nwant %s", got, want)
	}

	// Same serial rules afterwards: +1 per record change, timers untouched.
	for _, s := range []*Store{plain, files} {
		s.AddRecord("example.com", Record{Name: "a.example.com.", Type: dns.TypeA, Content: "192.0.2.1", TTL: 60})
		s.DeleteRecord("example.com", "a.example.com.", dns.TypeA)
	}
	if got, want := servedSOA(t, files), servedSOA(t, plain); got != want || !strings.Contains(got, " 7 3600 600 86400 300") {
		t.Fatalf("serial rules differ:\n got %s\nwant %s", got, want)
	}
	if m, _ := files.GetZoneMeta("example.com"); m.SOASerial != 900 || m.SOARefresh != 7200 || !m.DNSSECEnabled {
		t.Fatalf("stored meta %+v", m)
	}
	if _, ok := files.UpdateZoneMeta("nope.test", ZoneMetaPatch{}); ok {
		t.Fatal("unknown zone must not update")
	}
}
