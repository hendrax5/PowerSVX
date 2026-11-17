package blockcdb

import (
	"path/filepath"
	"testing"
)

func TestLookupCDBAndSuffix(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.cdb")
	_, err := BuildCDB(path, []string{"bad.example.com", "malware.org"})
	if err != nil {
		t.Fatalf("BuildCDB failed: %v", err)
	}

	if ok, err := LookupCDB(path, "bad.example.com"); err != nil || !ok {
		t.Fatalf("exact hit expected, got ok=%v err=%v", ok, err)
	}
	if ok, err := LookupCDB(path, "sub.bad.example.com"); err != nil || ok {
		t.Fatalf("exact lookup should not match subdomain, got ok=%v err=%v", ok, err)
	}
	if rule, ok, err := LookupCDBSuffix(path, "a.b.bad.example.com."); err != nil || !ok || rule != "bad.example.com" {
		t.Fatalf("suffix match expected bad.example.com, got rule=%q ok=%v err=%v", rule, ok, err)
	}
	if _, ok, err := LookupCDBSuffix(path, "good.example.com"); err != nil || ok {
		t.Fatalf("unexpected match for good.example.com: ok=%v err=%v", ok, err)
	}
}

func TestLookupEmptyCDB(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.cdb")
	if _, err := BuildCDB(path, nil); err != nil {
		t.Fatalf("BuildCDB empty failed: %v", err)
	}
	if _, ok, err := LookupCDBSuffix(path, "example.com"); err != nil || ok {
		t.Fatalf("empty CDB should return miss without error, got ok=%v err=%v", ok, err)
	}
}
