package blockcdb

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Dir returns blocklist directory (domains.txt + domains.cdb).
func Dir(dataDir string) string {
	if d := strings.TrimSpace(os.Getenv("POWERSVX_BLOCKLIST_DIR")); d != "" {
		return d
	}
	if dataDir == "" {
		dataDir = "./data"
	}
	return filepath.Join(dataDir, "blocklist")
}

const (
	DomainsFile = "domains.txt"
	CDBFile     = "domains.cdb"
	headerSize  = 2048 // 256 × 8
)

func cdbHash(b []byte) uint32 {
	var h uint32 = 5381
	for _, c := range b {
		h = ((h << 5) + h) ^ uint32(c)
	}
	return h
}

type slot struct {
	h, pos uint32
}

// WriteDomainsTxt writes one lowercase domain per line (no trailing dots).
func WriteDomainsTxt(path string, names []string) (int, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return 0, err
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return 0, err
	}
	w := bufio.NewWriterSize(f, 1<<20)
	n := 0
	seen := make(map[string]struct{}, len(names)/2+1)
	for _, name := range names {
		name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
		if name == "" || name == "localhost" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		if _, err := w.WriteString(name); err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
			return 0, err
		}
		if err := w.WriteByte('\n'); err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
			return 0, err
		}
		n++
	}
	if err := w.Flush(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return 0, err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return 0, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return 0, err
	}
	return n, nil
}

// BuildCDB writes a tinycdb-compatible CDB: key=domain, value="1".
func BuildCDB(cdbPath string, names []string) (int, error) {
	if err := os.MkdirAll(filepath.Dir(cdbPath), 0o755); err != nil {
		return 0, err
	}
	tmp := cdbPath + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return 0, err
	}
	if _, err := f.Write(make([]byte, headerSize)); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return 0, err
	}
	pos := uint32(headerSize)
	var tables [256][]slot
	val := []byte("1")
	n := 0
	seen := make(map[string]struct{}, len(names)/2+1)
	buf := make([]byte, 8)
	for _, name := range names {
		name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
		if name == "" || name == "localhost" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		key := []byte(name)
		recPos := pos
		binary.LittleEndian.PutUint32(buf[0:4], uint32(len(key)))
		binary.LittleEndian.PutUint32(buf[4:8], uint32(len(val)))
		if _, err := f.Write(buf); err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
			return 0, err
		}
		if _, err := f.Write(key); err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
			return 0, err
		}
		if _, err := f.Write(val); err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
			return 0, err
		}
		pos += 8 + uint32(len(key)) + uint32(len(val))
		h := cdbHash(key)
		tables[h&0xff] = append(tables[h&0xff], slot{h: h, pos: recPos})
		n++
	}

	header := make([]byte, headerSize)
	for i := 0; i < 256; i++ {
		slots := tables[i]
		tablePos := pos
		tlen := uint32(len(slots) * 2)
		binary.LittleEndian.PutUint32(header[i*8:], tablePos)
		binary.LittleEndian.PutUint32(header[i*8+4:], tlen)
		if tlen == 0 {
			continue
		}
		cell := make([]byte, tlen*8)
		for _, s := range slots {
			idx := (s.h >> 8) % tlen
			for {
				off := idx * 8
				if binary.LittleEndian.Uint32(cell[off+4:]) == 0 {
					binary.LittleEndian.PutUint32(cell[off:], s.h)
					binary.LittleEndian.PutUint32(cell[off+4:], s.pos)
					break
				}
				idx++
				if idx >= tlen {
					idx = 0
				}
			}
		}
		if _, err := f.Write(cell); err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
			return 0, err
		}
		pos += tlen * 8
	}
	if _, err := f.WriteAt(header, 0); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return 0, err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return 0, err
	}
	if err := os.Rename(tmp, cdbPath); err != nil {
		return 0, err
	}
	return n, nil
}

// SyncNames writes domains.txt + domains.cdb under Dir(dataDir).
func SyncNames(dataDir string, names []string) (txtN, cdbN int, err error) {
	dir := Dir(dataDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, 0, err
	}
	txtN, err = WriteDomainsTxt(filepath.Join(dir, DomainsFile), names)
	if err != nil {
		return 0, 0, fmt.Errorf("domains.txt: %w", err)
	}
	cdbN, err = BuildCDB(filepath.Join(dir, CDBFile), names)
	if err != nil {
		return txtN, 0, fmt.Errorf("domains.cdb: %w", err)
	}
	_ = os.WriteFile(filepath.Join(dir, "blocklist.meta.json"), []byte(fmt.Sprintf(
		`{"domains":%d,"cdb":%d,"format":"cdb"}`+"\n", txtN, cdbN)), 0o644)
	return txtN, cdbN, nil
}

// EnsureEmpty creates an empty CDB so dnsdist can start before first sync.
func EnsureEmpty(dataDir string) error {
	dir := Dir(dataDir)
	cdb := filepath.Join(dir, CDBFile)
	if _, err := os.Stat(cdb); err == nil {
		return nil
	}
	_, _, err := SyncNames(dataDir, nil)
	return err
}

// ReadCDBKeys streams all keys sequentially from a tinycdb data section (before the hash tables).
func ReadCDBKeys(cdbPath string) ([]string, error) {
	f, err := os.Open(cdbPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() < headerSize {
		return nil, fmt.Errorf("invalid cdb size %d", st.Size())
	}

	hdr := make([]byte, headerSize)
	if _, err := f.ReadAt(hdr, 0); err != nil {
		return nil, err
	}
	eod := int64(binary.LittleEndian.Uint32(hdr[0:4]))
	if eod < headerSize || eod > st.Size() {
		return nil, fmt.Errorf("invalid cdb eod %d (size %d)", eod, st.Size())
	}

	if _, err := f.Seek(headerSize, 0); err != nil {
		return nil, err
	}
	r := bufio.NewReaderSize(f, 1<<20)
	var recHdr [8]byte
	pos := int64(headerSize)
	var keys []string
	for pos+8 <= eod {
		if _, err := io.ReadFull(r, recHdr[:]); err != nil {
			return nil, err
		}
		klen := int64(binary.LittleEndian.Uint32(recHdr[0:4]))
		vlen := int64(binary.LittleEndian.Uint32(recHdr[4:8]))
		if klen < 0 || vlen < 0 || pos+8+klen+vlen > eod {
			return nil, fmt.Errorf("corrupt cdb record at %d", pos)
		}
		kbuf := make([]byte, klen)
		if _, err := io.ReadFull(r, kbuf); err != nil {
			return nil, err
		}
		if vlen > 0 {
			if _, err := io.CopyN(io.Discard, r, vlen); err != nil {
				return nil, err
			}
		}
		if len(kbuf) > 0 {
			keys = append(keys, string(kbuf))
		}
		pos += 8 + klen + vlen
	}
	return keys, nil
}
