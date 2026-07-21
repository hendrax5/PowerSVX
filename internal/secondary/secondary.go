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
)

// Zone is a secondary (slave) zone definition.
type Zone struct {
	Name     string   `json:"name"`
	Masters  []string `json:"masters"`
	Refresh  int      `json:"refresh_seconds,omitempty"` // 0 = use SOA refresh or 3600
	LastPull string   `json:"last_pull,omitempty"`
	LastErr  string   `json:"last_error,omitempty"`
	Serial   uint32   `json:"serial,omitempty"`
}

// Manager pulls zones from masters via AXFR and installs them into the auth store.
type Manager struct {
	mu     sync.Mutex
	path   string
	zones  []Zone
	auth   *authoritative.Store
	log    *slog.Logger
	cancel context.CancelFunc
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
	return &Manager{path: path, auth: auth, log: log}
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
	m.mu.Unlock()
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
	return os.WriteFile(m.path, b, 0o644)
}

func normalizeZones(in []Zone) ([]Zone, error) {
	out := make([]Zone, 0, len(in))
	seen := map[string]struct{}{}
	for _, z := range in {
		name := config.NormalizeName(z.Name)
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
	defer m.mu.Unlock()
	replaced := false
	for i := range m.zones {
		if m.zones[i].Name == z.Name {
			z.LastPull = m.zones[i].LastPull
			z.LastErr = m.zones[i].LastErr
			z.Serial = m.zones[i].Serial
			m.zones[i] = z
			replaced = true
			break
		}
	}
	if !replaced {
		m.zones = append(m.zones, z)
	}
	return m.saveLocked()
}

func (m *Manager) Delete(name string) bool {
	if m == nil {
		return false
	}
	name = config.NormalizeName(name)
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.zones {
		if m.zones[i].Name == name {
			m.zones = append(m.zones[:i], m.zones[i+1:]...)
			_ = m.saveLocked()
			return true
		}
	}
	return false
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

// Start begins background refresh loops and an initial pull of all zones.
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
			case <-time.After(60 * time.Second):
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

func (m *Manager) refreshDue(ctx context.Context) {
	for _, z := range m.List() {
		refresh := z.Refresh
		if refresh <= 0 {
			refresh = 3600
		}
		if z.LastPull == "" {
			_ = m.Transfer(ctx, z.Name)
			continue
		}
		t, err := time.Parse(time.RFC3339, z.LastPull)
		if err != nil || time.Since(t) >= time.Duration(refresh)*time.Second {
			_ = m.Transfer(ctx, z.Name)
		}
	}
}

// HandleNotify triggers an AXFR if the NOTIFY zone is configured as secondary.
func (m *Manager) HandleNotify(zone string) bool {
	if m == nil || !m.Has(zone) {
		return false
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		_ = m.Transfer(ctx, zone)
	}()
	return true
}

func (m *Manager) Transfer(ctx context.Context, name string) error {
	if m == nil || m.auth == nil {
		return fmt.Errorf("secondary manager not ready")
	}
	name = config.NormalizeName(name)
	m.mu.Lock()
	var z *Zone
	for i := range m.zones {
		if m.zones[i].Name == name {
			z = &m.zones[i]
			break
		}
	}
	if z == nil {
		m.mu.Unlock()
		return fmt.Errorf("secondary zone not found")
	}
	masters := append([]string(nil), z.Masters...)
	m.mu.Unlock()

	var lastErr error
	for _, master := range masters {
		recs, serial, err := axfrPull(ctx, name, master)
		if err != nil {
			lastErr = err
			m.log.Warn("secondary axfr failed", "zone", name, "master", master, "err", err)
			continue
		}
		m.auth.ReplaceZoneRecords(name, recs)
		m.mu.Lock()
		for i := range m.zones {
			if m.zones[i].Name == name {
				m.zones[i].LastPull = time.Now().UTC().Format(time.RFC3339)
				m.zones[i].LastErr = ""
				m.zones[i].Serial = serial
				if m.zones[i].Refresh <= 0 {
					m.zones[i].Refresh = 3600
				}
				_ = m.saveLocked()
				break
			}
		}
		m.mu.Unlock()
		m.log.Info("secondary axfr ok", "zone", name, "master", master, "records", len(recs), "serial", serial)
		return nil
	}
	m.mu.Lock()
	for i := range m.zones {
		if m.zones[i].Name == name {
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

func axfrPull(ctx context.Context, zone, master string) ([]authoritative.Record, uint32, error) {
	addr := master
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(master, "53")
	}
	m := new(dns.Msg)
	m.SetAxfr(zone)
	tr := &dns.Transfer{DialTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second}
	env, err := tr.In(m, addr)
	if err != nil {
		return nil, 0, err
	}
	var recs []authoritative.Record
	var serial uint32
	seenSOA := 0
	for e := range env {
		if e.Error != nil {
			return nil, 0, e.Error
		}
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		default:
		}
		for _, rr := range e.RR {
			if soa, ok := rr.(*dns.SOA); ok {
				seenSOA++
				serial = soa.Serial
				if seenSOA > 1 {
					continue // closing SOA
				}
			}
			if rec, ok := authoritative.RecordFromRR(rr); ok {
				recs = append(recs, rec)
			}
		}
	}
	if seenSOA == 0 {
		return nil, 0, fmt.Errorf("axfr missing SOA")
	}
	return recs, serial, nil
}

// IsSecondaryName reports whether name is managed as secondary (for read-only UI hints).
func (m *Manager) IsSecondaryName(name string) bool { return m.Has(name) }

func FormatMasters(masters []string) string {
	return strings.Join(masters, ", ")
}
