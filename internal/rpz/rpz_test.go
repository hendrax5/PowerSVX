package rpz

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestLookupExactAndWildcard(t *testing.T) {
	e := New(true)
	e.Replace(map[string]Action{
		"bad.example.com.": ActionNXDOMAIN,
		"*.ads.test.":      ActionNXDOMAIN,
	})
	if h, ok := e.Lookup("bad.example.com"); !ok || h.Action != ActionNXDOMAIN {
		t.Fatalf("exact miss: %v %v", h, ok)
	}
	if h, ok := e.Lookup("tracker.ads.test"); !ok || h.Action != ActionNXDOMAIN {
		t.Fatalf("wildcard miss: %v %v", h, ok)
	}
	if _, ok := e.Lookup("good.example.com"); ok {
		t.Fatal("should not match")
	}
}

func TestColdTierLookup(t *testing.T) {
	dir := t.TempDir()
	e := New(true)
	if err := e.OpenDisk(dir); err != nil {
		t.Fatal(err)
	}

	hosts := dir + "/hosts.txt"
	if err := os.WriteFile(hosts, []byte("0.0.0.0 malware.test\n0.0.0.0 track.evil\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	n, err := e.LoadPolicies([]PolicyConfig{{
		Name: "t", Source: hosts, Format: "hosts", Action: ActionNXDOMAIN,
	}}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if n < 2 {
		t.Fatalf("count=%d", n)
	}
	e.mu.RLock()
	cold := e.cold
	treeNil := e.tree == nil
	e.mu.RUnlock()
	if !cold || !treeNil {
		t.Fatalf("expected cold tier (cold=%v treeNil=%v)", cold, treeNil)
	}
	if h, ok := e.Lookup("malware.test"); !ok || h.Action != ActionNXDOMAIN {
		t.Fatalf("exact cold miss: %+v %v", h, ok)
	}
	if _, ok := e.Lookup("clean.example"); ok {
		t.Fatal("false positive")
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	// restart-style reload from disk
	e2 := New(true)
	if err := e2.OpenDisk(dir); err != nil {
		t.Fatal(err)
	}
	defer e2.Close()
	ok, n2, err := e2.TryLoadDisk([]PolicyConfig{{
		Name: "t", Source: hosts, Format: "hosts", Action: ActionNXDOMAIN,
	}})
	if err != nil || !ok || n2 < 2 {
		t.Fatalf("TryLoadDisk ok=%v n=%d err=%v", ok, n2, err)
	}
	if h, ok := e2.Lookup("track.evil"); !ok || h.Action != ActionNXDOMAIN {
		t.Fatalf("reload miss: %+v %v", h, ok)
	}
}

func TestLookupPassContinues(t *testing.T) {
	e := New(true)
	e.Replace(map[string]Action{
		"allow.example.": ActionPass,
	})
	h, ok := e.Lookup("allow.example")
	if !ok || h.Action != ActionPass {
		t.Fatalf("pass: %+v %v", h, ok)
	}
}

func TestParseHosts(t *testing.T) {
	src := `
# comment
0.0.0.0 malware.test
127.0.0.1 ads.evil
localhost
`
	m, err := parseHosts(strings.NewReader(src), ActionNXDOMAIN)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m["malware.test."]; !ok {
		t.Fatal("missing malware.test")
	}
	if _, ok := m["localhost."]; ok {
		t.Fatal("localhost should be skipped")
	}
}
