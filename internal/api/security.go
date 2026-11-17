package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/powersvx/powersvx/internal/apiauth"
	"github.com/powersvx/powersvx/internal/audit"
	"github.com/powersvx/powersvx/internal/blockcdb"
	"github.com/powersvx/powersvx/internal/dnsdistctl"
)

type manualBanRecord struct {
	Prefix    string     `json:"prefix"`
	Reason    string     `json:"reason"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type manualBanFile struct {
	Bans []manualBanRecord `json:"bans"`
}

var manualBanMu sync.Mutex

func (a *API) manualBanJSONPath() string {
	return filepath.Join(blockcdb.Dir(a.dataDir), "manual_bans.json")
}

func (a *API) loadManualBansLocked() []manualBanRecord {
	b, err := os.ReadFile(a.manualBanJSONPath())
	if err != nil {
		return nil
	}
	var f manualBanFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil
	}
	now := time.Now().UTC()
	out := make([]manualBanRecord, 0, len(f.Bans))
	for _, r := range f.Bans {
		if r.ExpiresAt != nil && !now.Before(*r.ExpiresAt) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func (a *API) saveManualBansLocked(list []manualBanRecord) error {
	dir := blockcdb.Dir(a.dataDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Prefix < list[j].Prefix })
	b, err := json.MarshalIndent(manualBanFile{Bans: list}, "", "  ")
	if err != nil {
		return err
	}
	p := a.manualBanJSONPath()
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		return err
	}
	cidrs := make([]string, 0, len(list))
	for _, item := range list {
		cidrs = append(cidrs, item.Prefix)
	}
	return dnsdistctl.WriteManualBans(dir, cidrs)
}

func normalizePrefix(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", false
	}
	if !strings.Contains(s, "/") {
		ip, err := netip.ParseAddr(s)
		if err != nil {
			return "", false
		}
		return netip.PrefixFrom(ip.Unmap(), ip.Unmap().BitLen()).String(), true
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return "", false
	}
	return p.Masked().String(), true
}

func (a *API) handleSecurityBlocks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	manualBanMu.Lock()
	manual := a.loadManualBansLocked()
	manualBanMu.Unlock()
	if manual == nil {
		manual = []manualBanRecord{}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	dynBlocks, dynErr := dnsdistctl.DefaultClient().ShowDynBlocks(ctx)
	if dynBlocks == nil {
		dynBlocks = []dnsdistctl.DynBlockEntry{}
	}

	aclBans := a.srv.ACLBanList()
	if aclBans == nil {
		aclBans = nil
	}
	rlBlocked := a.srv.RateLimitBlocked(100)

	out := map[string]any{
		"manual_bans":       manual,
		"dnsdist_dynblocks": dynBlocks,
		"acl_bans":          aclBans,
		"ratelimit_blocked": rlBlocked,
		"ratelimit_config":  a.srv.RateLimitConfig(),
	}
	if dynErr != nil {
		out["dnsdist_error"] = dynErr.Error()
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) handleSecurityBan(w http.ResponseWriter, r *http.Request) {
	p, _ := apiauth.PrincipalFrom(r.Context())
	switch r.Method {
	case http.MethodPost:
		var body struct {
			Prefix string `json:"prefix"`
			IP     string `json:"ip"`
			Reason string `json:"reason"`
			TTLSec int    `json:"ttl_sec"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		target := body.Prefix
		if target == "" {
			target = body.IP
		}
		norm, ok := normalizePrefix(target)
		if !ok {
			http.Error(w, "valid IP or CIDR required", http.StatusBadRequest)
			return
		}
		var exp *time.Time
		if body.TTLSec > 0 {
			t := time.Now().UTC().Add(time.Duration(body.TTLSec) * time.Second)
			exp = &t
		}
		reason := strings.TrimSpace(body.Reason)
		if reason == "" {
			reason = "manual ban"
		}

		manualBanMu.Lock()
		list := a.loadManualBansLocked()
		found := false
		for i := range list {
			if list[i].Prefix == norm {
				list[i].Reason = reason
				list[i].ExpiresAt = exp
				found = true
				break
			}
		}
		if !found {
			list = append(list, manualBanRecord{
				Prefix:    norm,
				Reason:    reason,
				CreatedAt: time.Now().UTC(),
				ExpiresAt: exp,
			})
		}
		err := a.saveManualBansLocked(list)
		manualBanMu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Also mirror single IPs in Go ACLBan guard when Go dataplane handles queries.
		if ipOnly := strings.TrimSuffix(strings.TrimSuffix(norm, "/32"), "/128"); !strings.Contains(ipOnly, "/") {
			ttl := 24 * time.Hour
			if body.TTLSec > 0 {
				ttl = time.Duration(body.TTLSec) * time.Second
			}
			_ = a.srv.BanIP(ipOnly, ttl)
		}

		if a.audit != nil {
			a.audit.Record(audit.Event{
				Actor: p.Name, Role: p.Role, Action: "security_ban", Path: r.URL.Path, Status: http.StatusOK,
				Meta: map[string]string{"prefix": norm, "reason": reason},
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "prefix": norm})

	case http.MethodDelete:
		target := r.URL.Query().Get("prefix")
		if target == "" {
			target = r.URL.Query().Get("ip")
		}
		norm, ok := normalizePrefix(target)
		if !ok {
			http.Error(w, "valid prefix or ip query param required", http.StatusBadRequest)
			return
		}
		manualBanMu.Lock()
		list := a.loadManualBansLocked()
		kept := make([]manualBanRecord, 0, len(list))
		for _, item := range list {
			if item.Prefix != norm {
				kept = append(kept, item)
			}
		}
		err := a.saveManualBansLocked(kept)
		manualBanMu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		ipOnly := strings.TrimSuffix(strings.TrimSuffix(norm, "/32"), "/128")
		a.srv.UnbanIP(ipOnly)

		if a.audit != nil {
			a.audit.Record(audit.Event{
				Actor: p.Name, Role: p.Role, Action: "security_unban", Path: r.URL.Path, Status: http.StatusOK,
				Meta: map[string]string{"prefix": norm},
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "prefix": norm})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *API) handleSecurityClearDynBlocks(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.srv.ClearRateLimitBlocks()
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	err := dnsdistctl.DefaultClient().ClearDynBlocks(ctx)
	out := map[string]any{"ok": err == nil}
	if err != nil {
		out["dnsdist_error"] = err.Error()
	}
	if a.audit != nil {
		p, _ := apiauth.PrincipalFrom(r.Context())
		a.audit.Record(audit.Event{Actor: p.Name, Role: p.Role, Action: "security_clear_dynblocks", Path: r.URL.Path, Status: http.StatusOK})
	}
	writeJSON(w, http.StatusOK, out)
}
