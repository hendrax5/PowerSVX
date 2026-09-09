package api

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/powersvx/powersvx/internal/blockcdb"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/rpz"
	"github.com/powersvx/powersvx/internal/unboundrpz"
)

// syncRPZToUnbound writes hosts (+ empty axfr placeholder) zonefiles and reloads Unbound.
func (a *API) syncRPZToUnbound() (int, error) {
	dir := unboundrpz.Dir(a.dataDir)
	if err := unboundrpz.EnsureEmptyZones(dir); err != nil {
		return 0, err
	}
	_ = unboundrpz.WriteBankPassthru(filepath.Join(dir, unboundrpz.BankFile))

	// Mirror allow_query into Unbound ACL.
	allow, _ := a.srv.QueryACL()
	_ = unboundrpz.WriteAccessControl(filepath.Join(dir, "access-control.conf"), allow)

	n, err := unboundrpz.SyncFromConfigPolicies(a.dataDir, a.cfg.RPZ.Policies, 30*time.Minute)
	if err != nil {
		return n, err
	}
	if err := unboundrpz.TryReload(); err != nil {
		a.log.Warn("unbound reload after rpz sync", "err", err, "entries", n)
		// Zonefiles are on disk; reload may succeed on next recreate.
	} else {
		a.log.Info("unbound rpz synced", "entries", n, "max_entries", unboundrpz.MaxEntriesFromEnv())
	}
	a.unboundRPZEntries.Store(int64(n))
	return n, nil
}

func (a *API) startUnboundRPZReload(sync bool) error {
	eng := a.srv.RPZ()
	if eng != nil && !eng.TryBeginLoad() {
		return errRPZ("rpz sync already in progress")
	}
	run := func() {
		n, err := a.syncRPZToUnbound()
		if eng != nil {
			eng.EndLoad(err)
		}
		if err != nil {
			a.log.Warn("unbound rpz sync failed", "err", err)
			return
		}
		a.log.Info("unbound rpz sync ok", "entries", n)
	}
	if sync {
		run()
		return nil
	}
	go run()
	return nil
}

func (a *API) unboundRPZEntryCount() int64 {
	return a.unboundRPZEntries.Load()
}

// refreshUnboundEntryCount from zonefile / CDB meta (startup / health).
func (a *API) refreshUnboundEntryCount() {
	if config.DNSDistDataplane() {
		meta := filepath.Join(blockcdb.Dir(a.dataDir), "blocklist.meta.json")
		b, err := os.ReadFile(meta)
		if err == nil {
			var m struct {
				CDB int `json:"cdb"`
			}
			if json.Unmarshal(b, &m) == nil && m.CDB > 0 {
				a.unboundRPZEntries.Store(int64(m.CDB))
				return
			}
		}
	}
	dir := unboundrpz.Dir(a.dataDir)
	var total int64
	for _, name := range []string{unboundrpz.TrustFile, unboundrpz.AXFRFile} {
		n, err := unboundrpz.CountZoneLines(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		total += int64(n)
	}
	a.unboundRPZEntries.Store(total)
}

func rpzUsesUnboundDataplane() bool {
	return config.UnboundDataplane()
}

// RefreshUnboundEntryCount exposes zonefile count for health after start.
func (a *API) RefreshUnboundEntryCount() { a.refreshUnboundEntryCount() }

// After AXFR into Go engine, also export names to Unbound axfr.rpz when dataplane.
// On unbound dataplane prefer startUnboundAXFRRefresh (avoids loading full zone into Go trie).
func (a *API) exportAXFRToUnbound(policies []rpz.PolicyConfig) {
	if !config.UnboundDataplane() {
		return
	}
	n, err := a.pullAndWriteUnboundAXFR(policies)
	if err != nil {
		a.log.Warn("unbound axfr export failed", "err", err)
		return
	}
	if n == 0 {
		return
	}
	if err := unboundrpz.TryReload(); err != nil {
		a.log.Debug("unbound reload after axfr", "err", err)
	} else {
		a.log.Info("unbound axfr zone synced", "entries", n)
	}
	a.unboundRPZEntries.Store(int64(n))
}

// startUnboundAXFRRefresh pulls Komdigi (or other) AXFR feeds straight into axfr.rpz.
// Skips the Go RPZ trie so small hosts are not OOM'd by a second in-memory copy.
func (a *API) startUnboundAXFRRefresh(sync bool) error {
	eng := a.srv.RPZ()
	if eng != nil && !eng.TryBeginLoad() {
		return errRPZ("rpz sync already in progress")
	}
	policies := rpzPolicyConfigs(a.cfg.RPZ.Policies)
	run := func() {
		n, err := a.pullAndWriteUnboundAXFR(policies)
		if eng != nil {
			eng.EndLoad(err)
		}
		if err != nil {
			a.log.Warn("unbound axfr refresh failed", "err", err)
			return
		}
		// Clear hosts zone so Unbound is not double-loaded (hosts+axfr) after switching to A.
		_ = unboundrpz.WriteMinimalTrustZone(a.dataDir)
		if err := unboundrpz.TryReload(); err != nil {
			a.log.Warn("unbound reload after axfr", "err", err, "entries", n)
		} else {
			a.log.Info("unbound axfr refreshed", "entries", n, "max_entries", unboundrpz.MaxEntriesFromEnv())
		}
		a.unboundRPZEntries.Store(int64(n))
	}
	if sync {
		run()
		return nil
	}
	go run()
	return nil
}

func (a *API) pullAndWriteUnboundAXFR(policies []rpz.PolicyConfig) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	var all []string
	action, target := "nxdomain", ""
	for _, p := range policies {
		if !strings.EqualFold(strings.TrimSpace(p.Format), "axfr") {
			continue
		}
		if strings.TrimSpace(string(p.Action)) != "" {
			action = string(p.Action)
		}
		if strings.TrimSpace(p.Target) != "" {
			target = p.Target
		}
		zone := config.NormalizeName(p.Zone)
		res, err := rpz.PullZone(ctx, zone, p.Masters, 0)
		if err != nil {
			return 0, fmt.Errorf("policy %s: %w", p.Name, err)
		}
		a.log.Info("axfr pull ok", "policy", p.Name, "names", len(res.Names), "serial", res.Serial)
		all = append(all, res.Names...)
	}
	if len(all) == 0 {
		_ = unboundrpz.EnsureEmptyZones(unboundrpz.Dir(a.dataDir))
		return 0, nil
	}
	return unboundrpz.SyncAXFRNames(a.dataDir, all, action, target)
}
