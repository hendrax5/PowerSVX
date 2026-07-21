package kominfo

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/config"
)

// DefaultTargets are Kominfo secondary DNS endpoints (AXFR pull after NOTIFY).
var DefaultTargets = []string{"182.23.79.202:53", "139.255.196.202:53"}

// TargetStatus is per-zone per-remote sync state.
type TargetStatus struct {
	Addr         string `json:"addr"`
	Status       string `json:"status"` // idle|notify_ok|notify_fail|axfr_ok|soa_ok|soa_mismatch|fail
	Error        string `json:"error,omitempty"`
	NotifyAt     string `json:"notify_at,omitempty"`
	AXFRPullAt   string `json:"axfr_pull_at,omitempty"`
	RemoteSerial uint32 `json:"remote_serial,omitempty"`
	CheckedAt    string `json:"checked_at,omitempty"`
}

// ZoneStatus aggregates target rows for one zone.
type ZoneStatus struct {
	Zone   string         `json:"zone"`
	Serial uint32         `json:"serial"`
	Targets []TargetStatus `json:"targets"`
}

// Progress is live sync job progress.
type Progress struct {
	Running     bool   `json:"running"`
	Done        int    `json:"done"`
	Total       int    `json:"total"`
	CurrentZone string `json:"current_zone,omitempty"`
	Phase       string `json:"phase,omitempty"` // notify|verify|done
	StartedAt   string `json:"started_at,omitempty"`
	FinishedAt  string `json:"finished_at,omitempty"`
	LastError   string `json:"last_error,omitempty"`
}

// Status is the full UI/API snapshot.
type Status struct {
	Enabled  bool         `json:"enabled"`
	Targets  []string     `json:"targets"`
	Progress Progress     `json:"progress"`
	Zones    []ZoneStatus `json:"zones"`
	Note     string       `json:"note"`
}

// Manager drives Kominfo secondary sync (NOTIFY + allow AXFR + status).
type Manager struct {
	mu       sync.Mutex
	enabled  bool
	targets  []string // host:port
	auth     *authoritative.Store
	log      *slog.Logger
	timeout  time.Duration
	progress Progress
	// zone -> addr -> status
	byZone map[string]map[string]TargetStatus
}

func New(auth *authoritative.Store, log *slog.Logger, targets []string) *Manager {
	if log == nil {
		log = slog.Default()
	}
	t := normalizeTargets(targets)
	if len(t) == 0 {
		t = append([]string(nil), DefaultTargets...)
	}
	return &Manager{
		enabled: false,
		targets: t,
		auth:    auth,
		log:     log,
		timeout: 5 * time.Second,
		byZone:  map[string]map[string]TargetStatus{},
	}
}

func normalizeTargets(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		host, port, err := net.SplitHostPort(raw)
		if err != nil {
			host, port = raw, "53"
		}
		if net.ParseIP(host) == nil && host == "" {
			continue
		}
		addr := net.JoinHostPort(host, port)
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	return out
}

func (m *Manager) SetEnabled(on bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.enabled = on
	m.mu.Unlock()
}

func (m *Manager) Enabled() bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.enabled
}

func (m *Manager) Targets() []string {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.targets...)
}

// IsTargetIP reports whether ip (no port) is a Kominfo secondary.
func (m *Manager) IsTargetIP(ipStr string) bool {
	if m == nil || !m.Enabled() {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.isTargetIPLocked(ipStr)
}

func (m *Manager) isTargetIPLocked(ipStr string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	for _, t := range m.targets {
		host, _, err := net.SplitHostPort(t)
		if err != nil {
			continue
		}
		if p := net.ParseIP(host); p != nil && p.Equal(ip) {
			return true
		}
	}
	return false
}

// RecordAXFRPull notes that a Kominfo secondary completed an inbound AXFR/IXFR.
func (m *Manager) RecordAXFRPull(zone, clientIP string) {
	if m == nil {
		return
	}
	zone = config.NormalizeName(zone)
	now := time.Now().UTC().Format(time.RFC3339)
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.enabled || !m.isTargetIPLocked(clientIP) {
		return
	}
	if m.byZone[zone] == nil {
		m.byZone[zone] = map[string]TargetStatus{}
	}
	for _, addr := range m.targets {
		host, _, _ := net.SplitHostPort(addr)
		if p := net.ParseIP(host); p != nil && p.Equal(net.ParseIP(clientIP)) {
			st := m.byZone[zone][addr]
			st.Addr = addr
			st.Status = "axfr_ok"
			st.Error = ""
			st.AXFRPullAt = now
			m.byZone[zone][addr] = st
			if m.log != nil {
				m.log.Info("kominfo axfr pull", "zone", zone, "from", clientIP)
			}
			return
		}
	}
}

// NotifyZone sends NOTIFY for one zone to all Kominfo targets (best-effort).
func (m *Manager) NotifyZone(zone string) {
	if m == nil || !m.Enabled() {
		return
	}
	zone = config.NormalizeName(zone)
	targets := m.Targets()
	msg := new(dns.Msg)
	msg.SetNotify(zone)
	c := &dns.Client{Net: "udp", Timeout: m.timeout}
	now := time.Now().UTC().Format(time.RFC3339)
	for _, addr := range targets {
		_, _, err := c.Exchange(msg, addr)
		m.mu.Lock()
		if m.byZone[zone] == nil {
			m.byZone[zone] = map[string]TargetStatus{}
		}
		st := m.byZone[zone][addr]
		st.Addr = addr
		st.NotifyAt = now
		if err != nil {
			st.Status = "notify_fail"
			st.Error = err.Error()
			if m.log != nil {
				m.log.Warn("kominfo notify failed", "zone", zone, "addr", addr, "err", err)
			}
		} else {
			st.Status = "notify_ok"
			st.Error = ""
		}
		m.byZone[zone][addr] = st
		m.mu.Unlock()
	}
}

// SyncAll notifies every authoritative zone and verifies remote SOA serials.
func (m *Manager) SyncAll(ctx context.Context) error {
	if m == nil {
		return fmt.Errorf("kominfo sync unavailable")
	}
	if !m.Enabled() {
		return fmt.Errorf("kominfo sync is disabled")
	}
	m.mu.Lock()
	if m.progress.Running {
		m.mu.Unlock()
		return fmt.Errorf("sync already running")
	}
	zones := m.auth.ListZones()
	m.progress = Progress{
		Running:   true,
		Done:      0,
		Total:     len(zones),
		Phase:     "notify",
		StartedAt: time.Now().UTC().Format(time.RFC3339),
	}
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		m.progress.Running = false
		m.progress.Phase = "done"
		m.progress.CurrentZone = ""
		m.progress.FinishedAt = time.Now().UTC().Format(time.RFC3339)
		m.mu.Unlock()
	}()

	var lastErr error
	for i, zi := range zones {
		select {
		case <-ctx.Done():
			lastErr = ctx.Err()
			m.mu.Lock()
			m.progress.LastError = lastErr.Error()
			m.mu.Unlock()
			return lastErr
		default:
		}
		zone := config.NormalizeName(zi.Name)
		m.mu.Lock()
		m.progress.CurrentZone = zone
		m.progress.Phase = "notify"
		m.progress.Done = i
		m.mu.Unlock()

		m.NotifyZone(zone)

		m.mu.Lock()
		m.progress.Phase = "verify"
		m.mu.Unlock()
		m.verifyZone(zone)
		m.mu.Lock()
		m.progress.Done = i + 1
		m.mu.Unlock()
	}
	return lastErr
}

func (m *Manager) verifyZone(zone string) {
	serial := zoneSerial(m.auth, zone)
	targets := m.Targets()
	c := &dns.Client{Net: "udp", Timeout: m.timeout}
	q := new(dns.Msg)
	q.SetQuestion(zone, dns.TypeSOA)
	now := time.Now().UTC().Format(time.RFC3339)
	for _, addr := range targets {
		resp, _, err := c.Exchange(q, addr)
		m.mu.Lock()
		if m.byZone[zone] == nil {
			m.byZone[zone] = map[string]TargetStatus{}
		}
		st := m.byZone[zone][addr]
		st.Addr = addr
		st.CheckedAt = now
		if err != nil {
			if st.Status != "axfr_ok" {
				st.Status = "fail"
				st.Error = err.Error()
			}
			m.byZone[zone][addr] = st
			m.mu.Unlock()
			continue
		}
		remote := soaSerialFromMsg(resp)
		st.RemoteSerial = remote
		if remote == 0 {
			if st.Status != "axfr_ok" {
				st.Status = "fail"
				st.Error = "no SOA in reply"
			}
		} else if remote == serial {
			st.Status = "soa_ok"
			st.Error = ""
		} else {
			st.Status = "soa_mismatch"
			st.Error = fmt.Sprintf("local serial %d != remote %d", serial, remote)
		}
		m.byZone[zone][addr] = st
		m.mu.Unlock()
	}
}

func zoneSerial(auth *authoritative.Store, zone string) uint32 {
	if auth == nil {
		return 0
	}
	recs, ok := auth.GetRecords(zone)
	if !ok {
		return 0
	}
	for _, r := range recs {
		if r.Type != dns.TypeSOA {
			continue
		}
		if rr := authoritative.RecordToRR(r); rr != nil {
			if soa, ok := rr.(*dns.SOA); ok {
				return soa.Serial
			}
		}
	}
	return 0
}

func soaSerialFromMsg(msg *dns.Msg) uint32 {
	if msg == nil {
		return 0
	}
	for _, rr := range append(append([]dns.RR{}, msg.Answer...), msg.Ns...) {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa.Serial
		}
	}
	return 0
}

// Snapshot returns UI/API status.
func (m *Manager) Snapshot() Status {
	if m == nil {
		return Status{Enabled: false, Note: "unavailable"}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	zones := []ZoneStatus{}
	if m.auth != nil {
		for _, zi := range m.auth.ListZones() {
			zone := config.NormalizeName(zi.Name)
			zs := ZoneStatus{Zone: zone, Serial: zoneSerial(m.auth, zone)}
			row := m.byZone[zone]
			for _, addr := range m.targets {
				st, ok := row[addr]
				if !ok {
					st = TargetStatus{Addr: addr, Status: "idle"}
				}
				if st.Addr == "" {
					st.Addr = addr
				}
				zs.Targets = append(zs.Targets, st)
			}
			zones = append(zones, zs)
		}
	}
	return Status{
		Enabled:  m.enabled,
		Targets:  append([]string(nil), m.targets...),
		Progress: m.progress,
		Zones:    zones,
		Note:     "When enabled, Kominfo secondaries may AXFR without global allow_axfr/TSIG. Sync sends NOTIFY then checks remote SOA. Status axfr_ok appears after they pull.",
	}
}
