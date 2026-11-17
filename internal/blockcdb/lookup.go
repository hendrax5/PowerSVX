package blockcdb

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"strings"
)

// LookupCDB checks whether an exact lowercase key exists in a tinycdb file.
func LookupCDB(cdbPath, key string) (bool, error) {
	f, err := os.Open(cdbPath)
	if err != nil {
		return false, err
	}
	defer f.Close()
	return lookupInReaderAt(f, strings.ToLower(strings.TrimSuffix(strings.TrimSpace(key), ".")))
}

// LookupCDBSuffix mirrors dnsdist KeyValueLookupKeySuffix behavior:
// checks domain and each parent label up to TLD against the CDB.
// Returns the matched domain rule (if any) and true on hit.
func LookupCDBSuffix(cdbPath, qname string) (string, bool, error) {
	f, err := os.Open(cdbPath)
	if err != nil {
		return "", false, err
	}
	defer f.Close()

	norm := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(qname), "."))
	if norm == "" {
		return "", false, nil
	}
	cur := norm
	for cur != "" {
		ok, err := lookupInReaderAt(f, cur)
		if err != nil {
			return "", false, err
		}
		if ok {
			return cur, true, nil
		}
		dot := strings.IndexByte(cur, '.')
		if dot < 0 {
			break
		}
		cur = cur[dot+1:]
	}
	return "", false, nil
}

func lookupInReaderAt(r io.ReaderAt, key string) (bool, error) {
	if key == "" {
		return false, nil
	}
	keyBytes := []byte(key)
	h := cdbHash(keyBytes)

	var ptr [8]byte
	slotOff := int64(h&0xff) * 8
	if _, err := r.ReadAt(ptr[:], slotOff); err != nil {
		if err == io.EOF {
			return false, nil
		}
		return false, err
	}
	tablePos := binary.LittleEndian.Uint32(ptr[0:4])
	tableSlots := binary.LittleEndian.Uint32(ptr[4:8])
	if tableSlots == 0 {
		return false, nil
	}

	start := (h >> 8) % tableSlots
	var cell [8]byte
	var recHdr [8]byte
	for probe := uint32(0); probe < tableSlots; probe++ {
		idx := (start + probe) % tableSlots
		if _, err := r.ReadAt(cell[:], int64(tablePos)+int64(idx)*8); err != nil {
			return false, err
		}
		ch := binary.LittleEndian.Uint32(cell[0:4])
		cpos := binary.LittleEndian.Uint32(cell[4:8])
		if cpos == 0 {
			return false, nil
		}
		if ch != h {
			continue
		}
		if _, err := r.ReadAt(recHdr[:], int64(cpos)); err != nil {
			return false, err
		}
		klen := binary.LittleEndian.Uint32(recHdr[0:4])
		if int(klen) != len(keyBytes) {
			continue
		}
		gotKey := make([]byte, klen)
		if _, err := r.ReadAt(gotKey, int64(cpos)+8); err != nil {
			return false, err
		}
		if bytes.Equal(gotKey, keyBytes) {
			return true, nil
		}
	}
	return false, nil
}
