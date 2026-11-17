package secondary

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/tsig"
)

// Zone is a secondary (slave) zone definition.
type Zone struct {
	Name        string   `json:"name"`
	Masters     []string `json:"masters"`
	TSIGKey     string   `json:"tsig_key,omitempty"`
	Refresh     int      `json:"refresh_seconds,omitempty"` // 0 = use master SOA refresh (fallback 3600)
	SOARefresh  uint32   `json:"soa_refresh,omitempty"`
	SOARetry    uint32   `json:"soa_retry,omitempty"`
	SOAExpire   uint32   `json:"soa_expire,omitempty"`
	LastPull    string   `json:"last_pull,omitempty"`
	LastCheck   string   `json:"last_check,omitempty"`
	LastMode    string   `json:"last_mode,omitempty"` // axfr | ixfr | skipped | failed
	LastMaster  string   `json:"last_master,omitempty"`
	LastErr     string   `json:"last_error,omitempty"`
	Serial      uint32   `json:"serial,omitempty"`
	RecordCount int      `json:"record_count,omitempty"`
}

// Manager pulls zones from masters via SOA check + IXFR/AXFR and installs them into the auth store.
type Manager struct {
	mu       sync.Mutex
	path     string
	zones    []Zone
	auth     *authoritative.Store
	tsig     *tsig.Store
	onChange func(zone string)
	inFlight map[string]bool
	log      *slog.Logger
	cancel   context.CancelFunc
}

func DefaultPath(dataDir string) string {
	if dataDir == "" {
		dataDir = "./data"
	}
	return filepath.Join(dataDir, "secondary-zones.json")
}

func New(path string, auth *authoritative.Store, log *slog.Logger) *Manager {
	if log == nil {
		log = slog.Default()
	}
	return &Manager{
		path:     path,
		auth:     auth,
		inFlight: make(map[string]bool),
		log:      log,
	}
}

// SetTSIGStore attaches TSIG keys for outbound SOA/IXFR/AXFR authentication.
func (m *Manager) SetTSIGStore(s *tsig.Store) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.tsig = s
	m.mu.Unlock()
}

// SetOnChange registers a callback invoked after a secondary zone's records or membership change (e.g. CDB/dataplane sync).
func (m *Manager) SetOnChange(fn func(zone string)) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.onChange = fn
	m.mu.Unlock()
}

func (m *Manager) notifyChanged(zone string) {
	m.mu.Lock()
	fn := m.onChange
	m.mu.Unlock()
	if fn != nil {
		fn(zone)
	}
}

func (m *Manager) zoneCachePath(zone string) string {
	if m.path == "" {
		return ""
	}
	safe := strings.TrimSuffix(config.NormalizeName(zone), ".")
	if safe == "" {
		safe = "root"
	}
	safe = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '_'
	}, strings.ToLower(safe))
	return filepath.Join(filepath.Dir(m.path), "secondary-zones", safe+".json")
}

func (m *Manager) saveZoneRecords(zone string, recs []authoritative.Record) {
	p := m.zoneCachePath(zone)
	if p == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return
	}
	b, err := json.Marshal(recs)
	if err != nil {
		return
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, p)
}

func (m *Manager) loadZoneRecords(zone string) ([]authoritative.Record, bool) {
	p := m.zoneCachePath(zone)
	if p == "" {
		return nil, false
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	var recs []authoritative.Record
	if err := json.Unmarshal(b, &recs); err != nil || len(recs) == 0 {
		return nil, false
	}
	return recs, true
}

func (m *Manager) deleteZoneRecords(zone string) {
	p := m.zoneCachePath(zone)
	if p != "" {
		_ = os.Remove(p)
	}
}

func (m *Manager) Load() error {
	if m == nil {
		return nil
	}
	b, err := os.ReadFile(m.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var zones []Zone
	if err := json.Unmarshal(b, &zones); err != nil {
		return err
	}
	norm, err := normalizeZones(zones)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.zones = norm
	auth := m.auth
	m.mu.Unlock()

	if auth != nil {
		restored := 0
		for i := range norm {
			if recs, ok := m.loadZoneRecords(norm[i].Name); ok {
				auth.ReplaceZoneRecords(norm[i].Name, recs)
				restored++
				if norm[i].RecordCount == 0 {
					m.mu.Lock()
					if i < len(m.zones) && m.zones[i].Name == norm[i].Name {
						m.zones[i].RecordCount = len(recs)
					}
					m.mu.Unlock()
				}
			}
		}
		if restored > 0 && m.log != nil {
			m.log.Info("restored secondary zones from disk cache", "zones", restored)
		}
	}
	return nil
}

func (m *Manager) saveLocked() error {
	if m.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(m.path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m.zones, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, m.path)
}

func normalizeZones(in []Zone) ([]Zone, error) {
	out := make([]Zone, 0, len(in))
	seen := map[string]struct{}{}
	for _, z := range in {
		name := config.NormalizeName(z.Name)
		if name == "" || name == "." {
			return nil, fmt.Errorf("valid zone name required")
		}
		masters, err := config.NormalizeForwarders(z.Masters)
		if err != nil {
			return nil, fmt.Errorf("zone %s: %w", name, err)
		}
		if len(masters) == 0 {
			return nil, fmt.Errorf("zone %s: at least one master required", name)
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		z.Name = name
		z.Masters = masters
		z.TSIGKey = strings.TrimSpace(z.TSIGKey)
		out = append(out, z)
	}
	return out, nil
}

func (m *Manager) List() []Zone {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Zone, len(m.zones))
	copy(out, m.zones)
	return out
}

func (m *Manager) Upsert(z Zone) error {
	if m == nil {
		return fmt.Errorf("secondary manager nil")
	}
	norm, err := normalizeZones([]Zone{z})
	if err != nil {
		return err
	}
	z = norm[0]
	m.mu.Lock()
	replaced := false
	for i := range m.zones {
		if m.zones[i].Name == z.Name {
			z.SOARefresh = m.zones[i].SOARefresh
			z.SOARetry = m.zones[i].SOARetry
			z.SOAExpire = m.zones[i].SOAExpire
			z.LastPull = m.zones[i].LastPull
			z.LastCheck = m.zones[i].LastCheck
			z.LastMode = m.zones[i].LastMode
			z.LastMaster = m.zones[i].LastMaster
			z.LastErr = m.zones[i].LastErr
			z.Serial = m.zones[i].Serial
			z.RecordCount = m.zones[i].RecordCount
			m.zones[i] = z
			replaced = true
			break
		}
	}
	if !replaced {
		m.zones = append(m.zones, z)
		if m.auth != nil {
			m.auth.UpsertZone(z.Name)
		}
	}
	err = m.saveLocked()
	m.mu.Unlock()
	if err == nil && !replaced {
		m.notifyChanged(z.Name)
	}
	return err
}

func (m *Manager) Delete(name string) bool {
	if m == nil {
		return false
	}
	name = config.NormalizeName(name)
	m.mu.Lock()
	found := false
	for i := range m.zones {
		if m.zones[i].Name == name {
			m.zones = append(m.zones[:i], m.zones[i+1:]...)
			_ = m.saveLocked()
			found = true
			break
		}
	}
	auth := m.auth
	m.mu.Unlock()
	if !found {
		return false
	}
	m.deleteZoneRecords(name)
	if auth != nil {
		auth.DeleteZone(name)
	}
	m.notifyChanged(name)
	return true
}

func (m *Manager) Has(name string) bool {
	if m == nil {
		return false
	}
	name = config.NormalizeName(name)
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, z := range m.zones {
		if z.Name == name {
			return true
		}
	}
	return false
}

// Start begins background refresh loops and an initial sync of all zones.
func (m *Manager) Start(parent context.Context) {
	if m == nil {
		return
	}
	ctx, cancel := context.WithCancel(parent)
	m.cancel = cancel
	go func() {
		m.TransferAll(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(30 * time.Second):
				m.refreshDue(ctx)
			}
		}
	}()
}

func (m *Manager) Stop() {
	if m != nil && m.cancel != nil {
		m.cancel()
	}
}

func (m *Manager) TransferAll(ctx context.Context) {
	for _, z := range m.List() {
		_ = m.Transfer(ctx, z.Name)
	}
}

func effectiveInterval(z Zone) time.Duration {
	if z.LastErr != "" {
		retry := int(z.SOARetry)
		if retry <= 0 {
			retry = 300
		}
		if retry < 30 {
			retry = 30
		}
		if retry > 3600 {
			retry = 3600
		}
		return time.Duration(retry) * time.Second
	}
	refresh := z.Refresh
	if refresh <= 0 {
		refresh = int(z.SOARefresh)
	}
	if refresh <= 0 {
		refresh = 3600
	}
	if refresh < 30 {
		refresh = 30
	}
	return time.Duration(refresh) * time.Second
}

func (m *Manager) refreshDue(ctx context.Context) {
	for _, z := range m.List() {
		stamp := z.LastCheck
		if stamp == "" {
			stamp = z.LastPull
		}
		if stamp == "" {
			_ = m.Transfer(ctx, z.Name)
			continue
		}
		t, err := time.Parse(time.RFC3339, stamp)
		if err != nil || time.Since(t) >= effectiveInterval(z) {
			_ = m.Transfer(ctx, z.Name)
		}
	}
}

// HandleNotify triggers a slave sync if zone is configured as secondary (without IP restriction).
func (m *Manager) HandleNotify(zone string) bool {
	return m.HandleNotifyFrom(zone, "", true)
}

// HandleNotifyFrom triggers a slave sync if zone is configured as secondary AND either tsigValid is true
// or clientIP matches one of the zone's masters (or loopback).
func (m *Manager) HandleNotifyFrom(zone, clientIP string, tsigValid bool) bool {
	if m == nil {
		return false
	}
	zone = config.NormalizeName(zone)
	m.mu.Lock()
	var masters []string
	found := false
	for _, z := range m.zones {
		if z.Name == zone {
			found = true
			masters = append([]string(nil), z.Masters...)
			break
		}
	}
	m.mu.Unlock()
	if !found {
		return false
	}
	if !tsigValid && !notifyAllowedFrom(clientIP, masters) {
		if m.log != nil {
			m.log.Warn("rejected unauthorized NOTIFY for secondary zone", "zone", zone, "client", clientIP)
		}
		return false
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		_ = m.Transfer(ctx, zone)
	}()
	return true
}

func notifyAllowedFrom(clientIP string, masters []string) bool {
	ipStr := strings.TrimSpace(clientIP)
	if ipStr == "" {
		return false
	}
	if host, _, err := net.SplitHostPort(ipStr); err == nil {
		ipStr = host
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	for _, m := range masters {
		host := strings.TrimSpace(m)
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if mip := net.ParseIP(host); mip != nil && mip.Equal(ip) {
			return true
		}
	}
	return false
}

func (m *Manager) resolveTSIG(keyName string) tsig.Auth {
	keyName = strings.TrimSpace(keyName)
	if keyName == "" {
		return tsig.Auth{}
	}
	m.mu.Lock()
	store := m.tsig
	m.mu.Unlock()
	if store == nil {
		return tsig.Auth{}
	}
	fqdn, secret, ok := store.Get(keyName)
	if !ok {
		return tsig.Auth{}
	}
	return tsig.Auth{Name: fqdn, Secret: secret}
}

func (m *Manager) Transfer(ctx context.Context, name string) error {
	if m == nil || m.auth == nil {
		return fmt.Errorf("secondary manager not ready")
	}
	name = config.NormalizeName(name)
	m.mu.Lock()
	if m.inFlight == nil {
		m.inFlight = make(map[string]bool)
	}
	if m.inFlight[name] {
		m.mu.Unlock()
		return nil
	}
	var z Zone
	found := false
	for i := range m.zones {
		if m.zones[i].Name == name {
			z = m.zones[i]
			found = true
			break
		}
	}
	if !found {
		m.mu.Unlock()
		return fmt.Errorf("secondary zone not found")
	}
	m.inFlight[name] = true
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		delete(m.inFlight, name)
		m.mu.Unlock()
	}()

	auth := m.resolveTSIG(z.TSIGKey)
	existingRecs, hasExisting := m.auth.GetRecords(name)
	localSerial := z.Serial
	if localSerial == 0 && hasExisting {
		localSerial = m.auth.CurrentSOASerial(name)
	}

	nowStr := time.Now().UTC().Format(time.RFC3339)

	// 1. SOA Pre-check when we already hold valid records and a local serial.
	if localSerial > 0 && hasExisting && len(existingRecs) > 0 {
		remoteSOA, soaMaster, soaErr := querySOARecord(ctx, name, z.Masters, auth)
		if soaErr == nil {
			if !tsig.SerialGreater(remoteSOA.Serial, localSerial) {
				m.mu.Lock()
				for i := range m.zones {
					if m.zones[i].Name == name {
						m.zones[i].LastCheck = nowStr
						m.zones[i].LastMode = "skipped"
						m.zones[i].LastMaster = soaMaster
						m.zones[i].LastErr = ""
						m.zones[i].SOARefresh = remoteSOA.Refresh
						m.zones[i].SOARetry = remoteSOA.Retry
						m.zones[i].SOAExpire = remoteSOA.Expire
						m.zones[i].RecordCount = len(existingRecs)
						_ = m.saveLocked()
						break
					}
				}
				m.mu.Unlock()
				return nil
			}
		}
	}

	var lastErr error
	// 2. Try IXFR when localSerial > 0 and we have existing base records.
	if localSerial > 0 && hasExisting && len(existingRecs) > 0 {
		for _, master := range z.Masters {
			recs, soa, mode, usedMaster, err := ixfrZonePull(ctx, name, master, localSerial, existingRecs, auth)
			if err != nil {
				lastErr = err
				m.log.Debug("secondary ixfr attempt failed; will try next/axfr", "zone", name, "master", master, "err", err)
				continue
			}
			m.commitTransferredZone(name, recs, soa, mode, usedMaster, nowStr)
			return nil
		}
	}

	// 3. Full AXFR (initial pull or fallback).
	for _, master := range z.Masters {
		recs, soa, usedMaster, err := axfrZonePull(ctx, name, master, auth)
		if err != nil {
			lastErr = err
			m.log.Warn("secondary axfr failed", "zone", name, "master", master, "err", err)
			continue
		}
		m.commitTransferredZone(name, recs, soa, "axfr", usedMaster, nowStr)
		return nil
	}

	m.mu.Lock()
	for i := range m.zones {
		if m.zones[i].Name == name {
			m.zones[i].LastCheck = nowStr
			m.zones[i].LastMode = "failed"
			if lastErr != nil {
				m.zones[i].LastErr = lastErr.Error()
			} else {
				m.zones[i].LastErr = "all masters failed"
			}
			_ = m.saveLocked()
			break
		}
	}
	m.mu.Unlock()
	if lastErr == nil {
		lastErr = fmt.Errorf("all masters failed")
	}
	return lastErr
}

func (m *Manager) commitTransferredZone(name string, recs []authoritative.Record, soa *dns.SOA, mode, master, nowStr string) {
	var serial, soaRefresh, soaRetry, soaExpire uint32
	if soa != nil {
		serial = soa.Serial
		soaRefresh = soa.Refresh
		soaRetry = soa.Retry
		soaExpire = soa.Expire
	}
	m.auth.ReplaceZoneRecords(name, recs)
	m.saveZoneRecords(name, recs)
	m.mu.Lock()
	for i := range m.zones {
		if m.zones[i].Name == name {
			m.zones[i].LastPull = nowStr
			m.zones[i].LastCheck = nowStr
			m.zones[i].LastMode = mode
			m.zones[i].LastMaster = master
			m.zones[i].LastErr = ""
			m.zones[i].Serial = serial
			m.zones[i].SOARefresh = soaRefresh
			m.zones[i].SOARetry = soaRetry
			m.zones[i].SOAExpire = soaExpire
			m.zones[i].RecordCount = len(recs)
			_ = m.saveLocked()
			break
		}
	}
	m.mu.Unlock()
	m.log.Info("secondary sync ok", "zone", name, "mode", mode, "master", master, "records", len(recs), "serial", serial)
	m.notifyChanged(name)
}

func applyTSIGMsg(m *dns.Msg, auth tsig.Auth) map[string]string {
	if auth.Name == "" || auth.Secret == "" {
		return nil
	}
	name := dns.Fqdn(auth.Name)
	alg := auth.Algorithm
	if alg == "" {
		alg = dns.HmacSHA256
	}
	m.SetTsig(name, alg, 300, time.Now().Unix())
	return map[string]string{name: auth.Secret}
}

func querySOARecord(ctx context.Context, zone string, masters []string, auth tsig.Auth) (*dns.SOA, string, error) {
	zone = config.NormalizeName(zone)
	var lastErr error
	for _, master := range masters {
		addr := master
		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr = net.JoinHostPort(master, "53")
		}
		for _, netw := range []string{"udp", "tcp"} {
			select {
			case <-ctx.Done():
				return nil, "", ctx.Err()
			default:
			}
			m := new(dns.Msg)
			m.SetQuestion(zone, dns.TypeSOA)
			tsigSecret := applyTSIGMsg(m, auth)
			c := &dns.Client{Net: netw, Timeout: 5 * time.Second, TsigSecret: tsigSecret}
			r, _, err := c.Exchange(m, addr)
			if err != nil {
				lastErr = err
				continue
			}
			if r == nil || r.Rcode != dns.RcodeSuccess {
				if r != nil {
					lastErr = fmt.Errorf("%s/%s: %s", addr, netw, dns.RcodeToString[r.Rcode])
				}
				continue
			}
			for _, rr := range r.Answer {
				if soa, ok := rr.(*dns.SOA); ok {
					return soa, addr, nil
				}
			}
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no SOA from masters")
	}
	return nil, "", lastErr
}

func axfrZonePull(ctx context.Context, zone, master string, auth tsig.Auth) ([]authoritative.Record, *dns.SOA, string, error) {
	addr := master
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(master, "53")
	}
	m := new(dns.Msg)
	m.SetAxfr(zone)
	tsigSecret := applyTSIGMsg(m, auth)
	tr := &dns.Transfer{DialTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second, TsigSecret: tsigSecret}
	env, err := tr.In(m, addr)
	if err != nil {
		return nil, nil, "", err
	}
	var recs []authoritative.Record
	var latestSOA *dns.SOA
	seenSOA := 0
	for e := range env {
		if e.Error != nil {
			return nil, nil, "", e.Error
		}
		select {
		case <-ctx.Done():
			return nil, nil, "", ctx.Err()
		default:
		}
		for _, rr := range e.RR {
			if soa, ok := rr.(*dns.SOA); ok {
				seenSOA++
				latestSOA = soa
				if seenSOA > 1 {
					continue // closing SOA
				}
			}
			if rec, ok := authoritative.RecordFromRR(rr); ok {
				recs = append(recs, rec)
			}
		}
	}
	if seenSOA < 2 {
		return nil, nil, "", fmt.Errorf("incomplete axfr (SOA count %d)", seenSOA)
	}
	return recs, latestSOA, addr, nil
}

func ixfrZonePull(ctx context.Context, zone, master string, clientSerial uint32, existing []authoritative.Record, auth tsig.Auth) ([]authoritative.Record, *dns.SOA, string, string, error) {
	addr := master
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(master, "53")
	}
	m := new(dns.Msg)
	m.SetIxfr(zone, clientSerial, "ns."+zone, "hostmaster."+zone)
	tsigSecret := applyTSIGMsg(m, auth)
	tr := &dns.Transfer{DialTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second, TsigSecret: tsigSecret}
	env, err := tr.In(m, addr)
	if err != nil {
		return nil, nil, "", "", err
	}
	var rrs []dns.RR
	for e := range env {
		if e.Error != nil {
			return nil, nil, "", "", e.Error
		}
		select {
		case <-ctx.Done():
			return nil, nil, "", "", ctx.Err()
		default:
		}
		rrs = append(rrs, e.RR...)
	}
	recs, soa, mode, err := applyIXFRToRecords(zone, clientSerial, existing, rrs)
	if err != nil {
		return nil, nil, "", "", err
	}
	return recs, soa, mode, addr, nil
}

// applyIXFRToRecords parses an RFC 1995 IXFR (or AXFR-style full fallback) RR stream into updated zone records.
func applyIXFRToRecords(zone string, clientSerial uint32, existing []authoritative.Record, rrs []dns.RR) ([]authoritative.Record, *dns.SOA, string, error) {
	if len(rrs) == 0 {
		return nil, nil, "", fmt.Errorf("empty IXFR")
	}
	firstSOA, ok := rrs[0].(*dns.SOA)
	if !ok {
		return nil, nil, "", fmt.Errorf("IXFR missing leading SOA")
	}
	if firstSOA.Serial == clientSerial || !tsig.SerialGreater(firstSOA.Serial, clientSerial) {
		return existing, firstSOA, "skipped", nil
	}

	// Single-SOA response shouldn't happen when serial advanced; fall back.
	if len(rrs) == 1 {
		return nil, nil, "", fmt.Errorf("incomplete IXFR single SOA")
	}

	// AXFR-style full response: second RR is NOT an SOA.
	if _, isSOA := rrs[1].(*dns.SOA); !isSOA {
		var full []authoritative.Record
		soaCount := 0
		for _, rr := range rrs {
			if _, ok := rr.(*dns.SOA); ok {
				soaCount++
				if soaCount > 1 {
					continue
				}
			}
			if rec, conv := authoritative.RecordFromRR(rr); conv {
				full = append(full, rec)
			}
		}
		if soaCount < 2 {
			return nil, nil, "", fmt.Errorf("incomplete AXFR-style IXFR")
		}
		return full, firstSOA, "axfr", nil
	}

	// True RFC 1995 incremental diff sequence:
	// [SOA_new, SOA_old1, rem..., SOA_new1, add..., ..., SOA_new]
	cur := make([]authoritative.Record, 0, len(existing))
	for _, r := range existing {
		if r.Type == dns.TypeSOA {
			continue // replaced by firstSOA
		}
		cur = append(cur, r)
	}

	removeExact := func(target authoritative.Record) {
		tName := config.NormalizeName(target.Name)
		tContent := strings.TrimSpace(target.Content)
		for i, r := range cur {
			if config.NormalizeName(r.Name) == tName && r.Type == target.Type &&
				strings.EqualFold(strings.TrimSpace(r.Content), tContent) && r.Prio == target.Prio {
				cur = append(cur[:i], cur[i+1:]...)
				return
			}
		}
	}

	state := 0 // 0=expect old SOA or end; 1=deletes; 2=adds
	for i := 1; i < len(rrs); i++ {
		rr := rrs[i]
		if soa, ok := rr.(*dns.SOA); ok {
			switch state {
			case 0:
				state = 1
			case 1:
				state = 2
			case 2:
				if soa.Serial == firstSOA.Serial && i == len(rrs)-1 {
					state = 0
				} else {
					state = 1
				}
			}
			continue
		}
		rec, conv := authoritative.RecordFromRR(rr)
		if !conv {
			continue
		}
		switch state {
		case 1:
			removeExact(rec)
		case 2:
			cur = append(cur, rec)
		}
	}

	soaRec, ok := authoritative.RecordFromRR(firstSOA)
	if ok {
		cur = append([]authoritative.Record{soaRec}, cur...)
	}
	return cur, firstSOA, "ixfr", nil
}

// IsSecondaryName reports whether name is managed as secondary (for read-only UI hints).
func (m *Manager) IsSecondaryName(name string) bool { return m.Has(name) }

func FormatMasters(masters []string) string {
	return strings.Join(masters, ", ")
}
