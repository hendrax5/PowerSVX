package blockcdb

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"hash/maphash"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// NamesScratchFile is the temporary file a streaming rebuild keeps its de-duplicated names in.
// It ends in ".tmp" so the stale-temp cleanup removes it after a crash.
const NamesScratchFile = "domains.names" + tmpSuffix

// Line limits of a feed cache file, as the former in-memory reader had them.
const (
	feedLineInit = 1 << 20
	feedLineMax  = 8 << 20
)

// avgFeedLineBytes sizes the de-duplication table from the size of the feed files. A feed with
// longer lines just makes the table smaller than needed and it grows once or twice.
const avgFeedLineBytes = 20

var feedSeed = maphash.MakeSeed()

// canonFeedName is the name a feed cache line becomes in the Filter. It applies, in order, the
// three normalisations the in-memory rebuild applied (reading a feed cache, FilterBlockNames,
// and the CDB/domains.txt writers), so a streaming rebuild writes the same bytes.
func canonFeedName(line string) (string, bool) {
	line = strings.ToLower(strings.TrimSpace(line))
	if line == "" || strings.HasPrefix(line, "#") {
		return "", false
	}
	name, ok := filterBlockName(line)
	if !ok {
		return "", false
	}
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" || name == "localhost" {
		return "", false
	}
	return name, true
}

// SyncFeedFilesGuardedContext rebuilds domains.txt and domains.cdb from feed cache files
// (one name per line, the files in order) without holding the names in memory. Output bytes
// are identical to FilterBlockNames followed by SyncNamesContext on the same names: first
// occurrence wins and keeps its position. Like SyncNamesGuardedContext it refuses to replace
// a useful CDB with an empty one. Memory use is the de-duplication table (8 bytes per name,
// sized for the input) plus the CDB hash tables (8 bytes per name) at the end; the names
// themselves stream through a temporary file, so memory does not depend on name length.
// On any error, including cancellation, all temporary files are removed and the live files
// are untouched.
func SyncFeedFilesGuardedContext(ctx context.Context, dataDir string, feeds []string) (txtN, cdbN int, err error) {
	dir := Dir(dataDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, 0, err
	}
	scratchPath := filepath.Join(dir, NamesScratchFile)
	txtPath := filepath.Join(dir, DomainsFile)
	cdbPath := filepath.Join(dir, CDBFile)
	txtTmp := txtPath + tmpSuffix
	cdbTmp := cdbPath + tmpSuffix

	var open []*os.File
	defer func() {
		for _, f := range open {
			_ = f.Close()
		}
		_ = os.Remove(scratchPath)
		if err != nil {
			_ = os.Remove(txtTmp)
			_ = os.Remove(cdbTmp)
		}
	}()
	create := func(path string) (*os.File, error) {
		f, err := os.Create(path)
		if err == nil {
			open = append(open, f)
		}
		return f, err
	}

	// Pass 1: normalise and de-duplicate into the scratch file, in input order.
	sf, err := create(scratchPath)
	if err != nil {
		return 0, 0, err
	}
	var feedBytes int64
	for _, fp := range feeds {
		if st, serr := os.Stat(fp); serr == nil {
			feedBytes += st.Size()
		}
	}
	scratch := &scratchFile{f: sf}
	set := newNameSet(int(feedBytes/avgFeedLineBytes), scratch)
	lines := 0
	for _, fp := range feeds {
		if err := ctx.Err(); err != nil {
			return 0, 0, err
		}
		f, err := os.Open(fp)
		if err != nil {
			return 0, 0, fmt.Errorf("read feed cache %s: %w", filepath.Base(fp), err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, feedLineInit), feedLineMax)
		for sc.Scan() {
			lines++
			if lines%ctxCheckEvery == 0 {
				if err := ctx.Err(); err != nil {
					_ = f.Close()
					return 0, 0, err
				}
			}
			name, ok := canonFeedName(sc.Text())
			if !ok {
				continue
			}
			if _, err := set.add(name); err != nil {
				_ = f.Close()
				return 0, 0, err
			}
		}
		serr := sc.Err()
		_ = f.Close()
		if serr != nil {
			return 0, 0, fmt.Errorf("read feed cache %s: %w", filepath.Base(fp), serr)
		}
	}
	n := set.n
	set = nil
	// The table is not needed any more. Collect it now, before the CDB hash tables are allocated,
	// or both would be live at once and the peak would be the sum instead of the larger one.
	runtime.GC()
	if n == 0 {
		if prev := existingMetaEntries(dataDir); prev > 0 {
			return 0, prev, fmt.Errorf("refusing to wipe blocklist CDB (%d entries) with empty set", prev)
		}
	}
	if err := scratch.flush(); err != nil {
		return 0, 0, err
	}
	if _, err := sf.Seek(0, io.SeekStart); err != nil {
		return 0, 0, err
	}

	// Pass 2: stream the unique names into domains.txt and the CDB data section.
	tf, err := create(txtTmp)
	if err != nil {
		return 0, 0, err
	}
	cf, err := create(cdbTmp)
	if err != nil {
		return 0, 0, err
	}
	tw := bufio.NewWriterSize(tf, 1<<20)
	cw := bufio.NewWriterSize(cf, 1<<20)
	if _, err := cw.Write(make([]byte, headerSize)); err != nil {
		return 0, 0, err
	}
	pos := uint64(headerSize)
	var tables [256][]slot
	perTable := n/256 + n/4096 + 16
	for i := range tables {
		tables[i] = make([]slot, 0, perTable)
	}
	val := []byte("1")
	var rec [8]byte
	r := bufio.NewReaderSize(sf, 1<<20)
	var longLine []byte
	for i := 0; i < n; i++ {
		if i%ctxCheckEvery == 0 {
			if err := ctx.Err(); err != nil {
				return 0, 0, err
			}
		}
		line, err := r.ReadSlice('\n')
		if err == bufio.ErrBufferFull {
			longLine = append(longLine[:0], line...)
			for err == bufio.ErrBufferFull {
				line, err = r.ReadSlice('\n')
				longLine = append(longLine, line...)
			}
			line = longLine
		}
		if err != nil {
			return 0, 0, fmt.Errorf("names scratch: %w", err)
		}
		key := line[:len(line)-1]
		recPos := pos
		pos += 8 + uint64(len(key)) + uint64(len(val))
		if pos > math.MaxUint32 {
			return 0, 0, fmt.Errorf("blocklist too large for a CDB (over 4 GiB)")
		}
		binary.LittleEndian.PutUint32(rec[0:4], uint32(len(key)))
		binary.LittleEndian.PutUint32(rec[4:8], uint32(len(val)))
		if _, err := cw.Write(rec[:]); err != nil {
			return 0, 0, err
		}
		if _, err := cw.Write(key); err != nil {
			return 0, 0, err
		}
		if _, err := cw.Write(val); err != nil {
			return 0, 0, err
		}
		if _, err := tw.Write(line); err != nil {
			return 0, 0, err
		}
		h := cdbHash(key)
		tables[h&0xff] = append(tables[h&0xff], slot{h: h, pos: uint32(recPos)})
	}
	if err := ctx.Err(); err != nil {
		return 0, 0, err
	}
	if err := tw.Flush(); err != nil {
		return 0, 0, err
	}
	if err := writeCDBTables(ctx, cw, cf, &tables, pos); err != nil {
		return 0, 0, err
	}
	for _, f := range []*os.File{tf, cf} {
		if err := f.Close(); err != nil {
			return 0, 0, err
		}
	}
	if err := os.Rename(cdbTmp, cdbPath); err != nil {
		return 0, 0, err
	}
	if err := os.Rename(txtTmp, txtPath); err != nil {
		return 0, 0, err
	}
	_ = writeFileAtomic(filepath.Join(dir, MetaFile), []byte(fmt.Sprintf(
		`{"domains":%d,"cdb":%d,"format":"cdb"}`+"\n", n, n)))
	return n, n, nil
}

// writeCDBTables appends the 256 hash tables after the data section (which ends at pos) and
// then writes the header. It is the table half of BuildCDBContext, byte for byte.
func writeCDBTables(ctx context.Context, w *bufio.Writer, f *os.File, tables *[256][]slot, pos uint64) error {
	header := make([]byte, headerSize)
	maxSlots := 0
	for i := range tables {
		maxSlots = max(maxSlots, len(tables[i]))
	}
	cellBuf := make([]byte, maxSlots*2*8) // one buffer for every table: no per-table garbage
	for i := 0; i < 256; i++ {
		slots := tables[i]
		tlen := uint32(len(slots) * 2)
		binary.LittleEndian.PutUint32(header[i*8:], uint32(pos))
		binary.LittleEndian.PutUint32(header[i*8+4:], tlen)
		if tlen == 0 {
			continue
		}
		cell := cellBuf[:tlen*8]
		clear(cell)
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
		if _, err := w.Write(cell); err != nil {
			return err
		}
		pos += uint64(tlen) * 8
		if pos > math.MaxUint32 {
			return fmt.Errorf("blocklist too large for a CDB (over 4 GiB)")
		}
		tables[i] = nil
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	_, err := f.WriteAt(header, 0)
	return err
}

// scratchFile appends names (one per line) to a file through a buffer and can compare a stored
// name with another, whether it is still in the buffer or already on disk.
type scratchFile struct {
	f       *os.File
	buf     []byte
	flushed int64
	cmp     []byte
}

func (s *scratchFile) off() int64 { return s.flushed + int64(len(s.buf)) }

func (s *scratchFile) writeLine(name string) error {
	s.buf = append(s.buf, name...)
	s.buf = append(s.buf, '\n')
	if len(s.buf) >= 1<<20 {
		return s.flush()
	}
	return nil
}

func (s *scratchFile) flush() error {
	if len(s.buf) == 0 {
		return nil
	}
	if _, err := s.f.Write(s.buf); err != nil {
		return err
	}
	s.flushed += int64(len(s.buf))
	s.buf = s.buf[:0]
	return nil
}

// equalAt reports whether the line stored at off is exactly name.
func (s *scratchFile) equalAt(off int64, name string) (bool, error) {
	need := len(name) + 1
	if off >= s.flushed {
		b := s.buf[off-s.flushed:]
		return len(b) >= need && b[len(name)] == '\n' && string(b[:len(name)]) == name, nil
	}
	if cap(s.cmp) < need {
		s.cmp = make([]byte, need)
	}
	b := s.cmp[:need]
	if _, err := s.f.ReadAt(b, off); err != nil {
		if err == io.EOF {
			return false, nil
		}
		return false, err
	}
	return b[len(name)] == '\n' && string(b[:len(name)]) == name, nil
}

type nameSlot struct {
	h    uint32
	off1 uint32 // scratch offset + 1; 0 marks an empty slot
}

// nameSet is an open-addressing set of the names written to a scratchFile. A slot holds a
// 32-bit hash and the name's offset; a name is compared byte for byte, from the scratch file,
// only when the hashes are equal, so the set is exact.
type nameSet struct {
	slots []nameSlot
	n     int
	sf    *scratchFile
}

func newNameSet(estimate int, sf *scratchFile) *nameSet {
	if estimate < 1024 {
		estimate = 1024
	}
	return &nameSet{slots: make([]nameSlot, estimate/3*4+16), sf: sf}
}

func (s *nameSet) at(h uint32) int { return int(uint64(h) * uint64(len(s.slots)) >> 32) }

// add stores name unless it is already in the set, and reports whether it was new.
func (s *nameSet) add(name string) (bool, error) {
	x := maphash.String(feedSeed, name)
	h := uint32(x) ^ uint32(x>>32)
	i := s.at(h)
	for {
		sl := s.slots[i]
		if sl.off1 == 0 {
			break
		}
		if sl.h == h {
			same, err := s.sf.equalAt(int64(sl.off1-1), name)
			if err != nil {
				return false, err
			}
			if same {
				return false, nil
			}
		}
		if i++; i == len(s.slots) {
			i = 0
		}
	}
	off := s.sf.off()
	if off >= math.MaxUint32-1 {
		return false, fmt.Errorf("blocklist too large for a CDB (over 4 GiB)")
	}
	if err := s.sf.writeLine(name); err != nil {
		return false, err
	}
	s.slots[i] = nameSlot{h: h, off1: uint32(off) + 1}
	s.n++
	if s.n*4 > len(s.slots)*3 {
		s.grow()
	}
	return true, nil
}

// grow enlarges the table by half and re-places every slot from its stored hash.
func (s *nameSet) grow() {
	old := s.slots
	s.slots = make([]nameSlot, len(old)+len(old)/2)
	for _, sl := range old {
		if sl.off1 == 0 {
			continue
		}
		i := s.at(sl.h)
		for s.slots[i].off1 != 0 {
			if i++; i == len(s.slots) {
				i = 0
			}
		}
		s.slots[i] = sl
	}
}
