package blockcdb

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestSyncNamesCDBRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("POWERSVX_BLOCKLIST_DIR", dir)
	names := []string{"Evil.Example", "phish.co.id.", "evil.example", "good.com"}
	txtN, cdbN, err := SyncNames(dir, names)
	if err != nil {
		t.Fatal(err)
	}
	if txtN != 3 || cdbN != 3 {
		t.Fatalf("txt=%d cdb=%d", txtN, cdbN)
	}
	cdbPath := filepath.Join(dir, CDBFile)
	if st, err := os.Stat(cdbPath); err != nil || st.Size() < 2048 {
		t.Fatalf("cdb missing/small: %v", err)
	}
	for _, want := range []string{"evil.example", "phish.co.id", "good.com"} {
		if !cdbContains(t, cdbPath, want) {
			t.Fatalf("missing key %s", want)
		}
	}
	if cdbContains(t, cdbPath, "nope.example") {
		t.Fatal("unexpected key")
	}
}

func cdbContains(t *testing.T, path, key string) bool {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) < headerSize {
		return false
	}
	h := cdbHash([]byte(key))
	table := int(h & 0xff)
	tpos := binary.LittleEndian.Uint32(b[table*8:])
	tlen := binary.LittleEndian.Uint32(b[table*8+4:])
	if tlen == 0 {
		return false
	}
	idx := (h >> 8) % tlen
	for i := uint32(0); i < tlen; i++ {
		off := tpos + ((idx+i)%tlen)*8
		if int(off+8) > len(b) {
			return false
		}
		hh := binary.LittleEndian.Uint32(b[off:])
		p := binary.LittleEndian.Uint32(b[off+4:])
		if p == 0 {
			return false
		}
		if hh != h {
			continue
		}
		if int(p+8) > len(b) {
			continue
		}
		klen := binary.LittleEndian.Uint32(b[p:])
		dlen := binary.LittleEndian.Uint32(b[p+4:])
		ks := p + 8
		ke := ks + klen
		if int(ke+dlen) > len(b) {
			continue
		}
		if string(b[ks:ke]) == key {
			return true
		}
	}
	return false
}
