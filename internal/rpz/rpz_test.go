package rpz

import (
	"strings"
	"testing"
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
