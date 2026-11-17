package blockcdb

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestNeedsSeed(t *testing.T) {
	dir := t.TempDir()
	if !NeedsSeed(dir) {
		t.Fatal("empty dir should need seed")
	}
	if err := EnsureEmpty(dir); err != nil {
		t.Fatal(err)
	}
	if !NeedsSeed(dir) {
		t.Fatal("empty stub CDB should still need seed")
	}
	cdb := filepath.Join(Dir(dir), CDBFile)
	if err := os.WriteFile(cdb, make([]byte, MinUsefulCDBBytes+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if NeedsSeed(dir) {
		t.Fatal("large CDB should not need seed")
	}
}

func TestSeedTarRoundTrip(t *testing.T) {
	src := t.TempDir()
	names := []string{"evil.example", "bad.test"}
	if _, _, err := SyncNames(src, names); err != nil {
		t.Fatal(err)
	}
	man := SeedManifest{Policy: "trustpositifkominfo", Zone: "trustpositifkominfo.", Serial: 42, Entries: 2}
	var buf bytes.Buffer
	if err := WriteSeedTarGz(src, man, "", &buf); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	got, err := InstallSeedTarGz(dst, bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if got.Serial != 42 {
		t.Fatalf("serial=%d", got.Serial)
	}
	b, err := os.ReadFile(filepath.Join(Dir(dst), DomainsFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("evil.example")) {
		t.Fatalf("domains.txt missing names: %s", b)
	}
	readMan, ok := ReadSeedManifest(dst)
	if !ok || readMan.Serial != 42 || readMan.Policy != "trustpositifkominfo" {
		t.Fatalf("ReadSeedManifest ok=%v man=%+v", ok, readMan)
	}
	keys, err := ReadCDBKeys(filepath.Join(Dir(dst), CDBFile))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0] != "evil.example" || keys[1] != "bad.test" {
		t.Fatalf("ReadCDBKeys=%v", keys)
	}
}

func TestSyncNamesGuarded(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := SyncNames(dir, []string{"a.com", "b.com"}); err != nil {
		t.Fatal(err)
	}
	_, _, err := SyncNamesGuarded(dir, nil)
	if err == nil {
		t.Fatal("expected refuse wipe")
	}
}
