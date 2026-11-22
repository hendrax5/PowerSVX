package authoritative

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/config"
)

// ZoneFileVersion is the format version written into every zone file.
const ZoneFileVersion = 1

// ZoneMeta is the per-zone metadata kept next to the records.
type ZoneMeta struct {
	Type          string `json:"type"`
	DNSSECEnabled bool   `json:"dnssec_enabled"`
	SOASerial     int64  `json:"soa_serial"`
	SOARefresh    int    `json:"soa_refresh"`
	SOARetry      int    `json:"soa_retry"`
	SOAExpire     int    `json:"soa_expire"`
	SOAMinimum    int    `json:"soa_minimum"`
}

// DefaultZoneMeta matches the column defaults of the legacy zones table.
func DefaultZoneMeta() ZoneMeta {
	return ZoneMeta{Type: "native", SOASerial: 1, SOARefresh: 3600, SOARetry: 600, SOAExpire: 86400, SOAMinimum: 3600}
}

// ZoneMetaPatch carries the optional fields of a metadata update.
type ZoneMetaPatch struct {
	DNSSECEnabled *bool
	SOASerial     *int64
	SOARefresh    *int
	SOARetry      *int
	SOAExpire     *int
	SOAMinimum    *int
}

type zoneFile struct {
	Version int          `json:"version"`
	Name    string       `json:"name"`
	Meta    ZoneMeta     `json:"meta"`
	Records []fileRecord `json:"records"`
}

type fileRecord struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	TTL     uint32 `json:"ttl"`
	Prio    uint16 `json:"prio,omitempty"`
	View    string `json:"view,omitempty"`
	GeoTag  string `json:"geo_tag,omitempty"`
}

func typeName(t uint16) string {
	if n, ok := dns.TypeToString[t]; ok {
		return n
	}
	return "TYPE" + strconv.Itoa(int(t))
}

func parseTypeName(s string) (uint16, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if t, ok := dns.StringToType[s]; ok {
		return t, nil
	}
	if strings.HasPrefix(s, "TYPE") {
		if n, err := strconv.ParseUint(s[4:], 10, 16); err == nil {
			return uint16(n), nil
		}
	}
	return 0, fmt.Errorf("unknown record type %q", s)
}

func encodeZoneFile(name string, meta ZoneMeta, recs []Record) ([]byte, error) {
	zf := zoneFile{Version: ZoneFileVersion, Name: name, Meta: meta, Records: make([]fileRecord, 0, len(recs))}
	for _, r := range recs {
		zf.Records = append(zf.Records, fileRecord{
			Name: r.Name, Type: typeName(r.Type), Content: r.Content,
			TTL: r.TTL, Prio: r.Prio, View: r.View, GeoTag: r.GeoTag,
		})
	}
	return json.MarshalIndent(zf, "", "  ")
}

func decodeZoneFile(b []byte) (string, ZoneMeta, []Record, error) {
	var zf zoneFile
	if err := json.Unmarshal(b, &zf); err != nil {
		return "", ZoneMeta{}, nil, err
	}
	if zf.Version != ZoneFileVersion {
		return "", ZoneMeta{}, nil, fmt.Errorf("unsupported zone file version %d", zf.Version)
	}
	if strings.TrimSpace(zf.Name) == "" {
		return "", ZoneMeta{}, nil, fmt.Errorf("zone file has no name")
	}
	recs := make([]Record, 0, len(zf.Records))
	for _, fr := range zf.Records {
		t, err := parseTypeName(fr.Type)
		if err != nil {
			return "", ZoneMeta{}, nil, err
		}
		recs = append(recs, Record{
			Name: config.NormalizeName(fr.Name), Type: t, Content: fr.Content,
			TTL: fr.TTL, Prio: fr.Prio, View: fr.View, GeoTag: fr.GeoTag,
		})
	}
	meta := zf.Meta
	if meta.Type == "" {
		meta.Type = "native"
	}
	return config.NormalizeName(zf.Name), meta, recs, nil
}

// ZoneFileName maps a zone name to a file name that is safe on every
// filesystem and unique per zone: bytes outside [a-z0-9-.] become _xx, so
// "/" and ".." can never escape the directory and two names never collide.
func ZoneFileName(zone string) string {
	zone = strings.TrimSuffix(config.NormalizeName(zone), ".")
	if zone == "" {
		return "_root.json"
	}
	var b strings.Builder
	for i := 0; i < len(zone); i++ {
		c := zone[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || (c == '.' && i > 0) {
			// A leading dot is escaped: dot files are skipped at load.
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "_%02x", c)
		}
	}
	s := b.String()
	if len(s) > 200 {
		sum := sha256.Sum256([]byte(zone))
		s = s[:150] + "~" + hex.EncodeToString(sum[:8])
	}
	return s + ".json"
}

// ZonesDir is where Authoritative Zone files live inside the data directory.
func ZonesDir(dataDir string) string {
	if dataDir == "" {
		dataDir = "./data"
	}
	return filepath.Join(dataDir, "zones")
}

// writeFileAtomic writes data to a temp file in the same directory, syncs it
// and renames it over path, so a crash leaves either the old or the new file.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// zoneFiles is the persistence state of a Store.
type zoneFiles struct {
	dir   string
	owned map[string]bool // Authoritative Zones; guarded by Store.mu

	seq     uint64            // guarded by Store.mu
	writeMu sync.Mutex        // serialises disk writes
	written map[string]uint64 // newest sequence applied per zone
	errMu   sync.Mutex
	lastErr error
}

type persistJob struct {
	zone   string
	seq    uint64
	data   []byte
	remove bool
}

// EnablePersistence loads every zone file in dir into the store and from then
// on rewrites a zone's file after each change. It returns the number of zones
// loaded; unreadable files are skipped and reported in the error, and are
// never overwritten or removed.
func (s *Store) EnablePersistence(dir string) (int, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	loaded := make(map[string][]Record)
	metas := make(map[string]ZoneMeta)
	var bad []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err == nil {
			var name string
			var meta ZoneMeta
			var recs []Record
			name, meta, recs, err = decodeZoneFile(b)
			if err == nil {
				loaded[name] = recs
				metas[name] = meta
				continue
			}
		}
		bad = append(bad, fmt.Sprintf("%s: %v", e.Name(), err))
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	pf := &zoneFiles{dir: dir, owned: make(map[string]bool), written: make(map[string]uint64)}
	for name, recs := range loaded {
		s.zones[name] = recs
		if s.meta == nil {
			s.meta = make(map[string]ZoneMeta)
		}
		s.meta[name] = metas[name]
		pf.owned[name] = true
	}
	s.files = pf
	if len(bad) > 0 {
		return len(loaded), fmt.Errorf("skipped unreadable zone files: %s", strings.Join(bad, "; "))
	}
	return len(loaded), nil
}

// PersistError returns the result of the most recent zone file write (nil when
// it succeeded or persistence is off).
func (s *Store) PersistError() error {
	s.mu.RLock()
	pf := s.files
	s.mu.RUnlock()
	if pf == nil {
		return nil
	}
	pf.errMu.Lock()
	defer pf.errMu.Unlock()
	return pf.lastErr
}

// captureLocked snapshots the zone for writing. Must hold s.mu. Returns nil for
// zones that are not persisted (memory-only and Secondary Zones).
func (s *Store) captureLocked(zone string) *persistJob {
	pf := s.files
	if pf == nil || !pf.owned[zone] {
		return nil
	}
	pf.seq++
	job := &persistJob{zone: zone, seq: pf.seq}
	recs, ok := s.zones[zone]
	if !ok {
		job.remove = true
		delete(pf.owned, zone)
		delete(s.meta, zone)
		return job
	}
	data, err := encodeZoneFile(zone, s.metaLocked(zone), recs)
	if err != nil {
		pf.setErr(err)
		return nil
	}
	job.data = data
	return job
}

func (pf *zoneFiles) setErr(err error) {
	pf.errMu.Lock()
	pf.lastErr = err
	pf.errMu.Unlock()
}

// flush performs the disk write for a job captured under the store lock.
func (s *Store) flush(job *persistJob) {
	if job == nil {
		return
	}
	s.mu.RLock()
	pf := s.files
	s.mu.RUnlock()
	if pf == nil {
		return
	}
	pf.writeMu.Lock()
	defer pf.writeMu.Unlock()
	if job.seq < pf.written[job.zone] {
		return
	}
	pf.written[job.zone] = job.seq
	path := filepath.Join(pf.dir, ZoneFileName(job.zone))
	var err error
	if job.remove {
		if err = os.Remove(path); os.IsNotExist(err) {
			err = nil
		}
	} else {
		err = writeFileAtomic(path, job.data)
	}
	pf.setErr(err)
}

// CreateZone registers an Authoritative Zone (idempotent) and persists it.
// It reports whether the zone was newly created.
func (s *Store) CreateZone(name string) bool {
	var job *persistJob
	s.mu.Lock()
	defer func() { s.mu.Unlock(); s.flush(job) }()
	name = config.NormalizeName(name)
	_, exists := s.zones[name]
	if !exists {
		s.zones[name] = nil
	}
	if s.files != nil && !s.files.owned[name] {
		s.files.owned[name] = true
		job = s.captureLocked(name)
	}
	return !exists
}

// AddRecords appends records to a zone (creating it) and persists once.
func (s *Store) AddRecords(zone string, recs []Record) {
	var job *persistJob
	s.mu.Lock()
	defer func() { s.mu.Unlock(); s.flush(job) }()
	zone = config.NormalizeName(zone)
	if _, ok := s.zones[zone]; !ok {
		s.zones[zone] = nil
	}
	if s.files != nil {
		s.files.owned[zone] = true
	}
	for _, rec := range recs {
		s.addRecordLocked(zone, rec)
	}
	job = s.captureLocked(zone)
}

func (s *Store) metaLocked(zone string) ZoneMeta {
	m, ok := s.meta[zone]
	if !ok {
		m = DefaultZoneMeta()
	}
	for _, r := range s.zones[zone] {
		if r.Type != dns.TypeSOA {
			continue
		}
		p := strings.Fields(r.Content)
		if len(p) < 7 {
			break
		}
		ser, e1 := strconv.ParseInt(p[2], 10, 64)
		rf, e2 := strconv.Atoi(p[3])
		rt, e3 := strconv.Atoi(p[4])
		ex, e4 := strconv.Atoi(p[5])
		mn, e5 := strconv.Atoi(p[6])
		if e1 == nil && e2 == nil && e3 == nil && e4 == nil && e5 == nil {
			m.SOASerial, m.SOARefresh, m.SOARetry, m.SOAExpire, m.SOAMinimum = ser, rf, rt, ex, mn
		}
		break
	}
	return m
}

// GetZoneMeta returns the zone's metadata. SOA values come from the zone's SOA
// record when it has one, since that is what the Dataplane serves.
func (s *Store) GetZoneMeta(zone string) (ZoneMeta, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	zone = config.NormalizeName(zone)
	if _, ok := s.zones[zone]; !ok {
		return ZoneMeta{}, false
	}
	return s.metaLocked(zone), true
}

// UpdateZoneMeta applies a patch, keeps the SOA record in step with the SOA
// fields, persists the zone and returns the new metadata.
func (s *Store) UpdateZoneMeta(zone string, p ZoneMetaPatch) (ZoneMeta, bool) {
	var job *persistJob
	s.mu.Lock()
	defer func() { s.mu.Unlock(); s.flush(job) }()
	zone = config.NormalizeName(zone)
	if _, ok := s.zones[zone]; !ok {
		return ZoneMeta{}, false
	}
	if s.meta == nil {
		s.meta = make(map[string]ZoneMeta)
	}
	m := s.metaLocked(zone)
	if p.DNSSECEnabled != nil {
		m.DNSSECEnabled = *p.DNSSECEnabled
	}
	if p.SOASerial != nil {
		m.SOASerial = *p.SOASerial
	}
	if p.SOARefresh != nil {
		m.SOARefresh = *p.SOARefresh
	}
	if p.SOARetry != nil {
		m.SOARetry = *p.SOARetry
	}
	if p.SOAExpire != nil {
		m.SOAExpire = *p.SOAExpire
	}
	if p.SOAMinimum != nil {
		m.SOAMinimum = *p.SOAMinimum
	}
	s.meta[zone] = m
	recs := s.zones[zone]
	for i, r := range recs {
		if r.Type != dns.TypeSOA {
			continue
		}
		parts := strings.Fields(r.Content)
		if len(parts) >= 7 {
			parts[2] = strconv.FormatInt(m.SOASerial, 10)
			parts[3] = strconv.Itoa(m.SOARefresh)
			parts[4] = strconv.Itoa(m.SOARetry)
			parts[5] = strconv.Itoa(m.SOAExpire)
			parts[6] = strconv.Itoa(m.SOAMinimum)
			recs[i].Content = strings.Join(parts, " ")
		}
		break
	}
	job = s.captureLocked(zone)
	return s.metaLocked(zone), true
}
