package api

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/powersvx/powersvx/internal/blockcdb"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/rpz"
	"github.com/powersvx/powersvx/internal/unboundrpz"
)

func rpzUsesDNSDistDataplane() bool { return config.DNSDistDataplane() }

// TriggerDNSDistCDBSync starts async AXFR/hosts → CDB rebuild (dnsdist dataplane).
func (a *API) TriggerDNSDistCDBSync() error {
	return a.startDNSDistCDBRefresh(false)
}

// startDNSDistCDBRefresh pulls AXFR (or uses empty) and builds domains.cdb for dnsdist.
func (a *API) startDNSDistCDBRefresh(sync bool) error {
	eng := a.srv.RPZ()
	if eng != nil && !eng.TryBeginLoad() {
		return errRPZ("rpz sync already in progress")
	}
	policies := rpzPolicyConfigs(a.cfg.RPZ.Policies)
	run := func() {
		n, err := a.pullAndWriteBlockCDB(policies)
		if eng != nil {
			eng.EndLoad(err)
		}
		if err != nil {
			a.log.Warn("dnsdist cdb refresh failed", "err", err)
			return
		}
		_, _ = blockcdb.WriteBanksWhitelist(a.dataDir)
		a.unboundRPZEntries.Store(int64(n))
		a.tryReloadDNSDist()
		a.log.Info("dnsdist cdb refreshed", "entries", n)
	}
	if sync {
		run()
		return nil
	}
	go run()
	return nil
}

func (a *API) pullAndWriteBlockCDB(policies []rpz.PolicyConfig) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	var all []string
	for _, p := range policies {
		format := strings.ToLower(strings.TrimSpace(p.Format))
		switch format {
		case "axfr":
			zone := config.NormalizeName(p.Zone)
			res, err := rpz.PullZone(ctx, zone, p.Masters, 0)
			if err != nil {
				return 0, fmt.Errorf("policy %s: %w", p.Name, err)
			}
			a.log.Info("axfr pull ok", "policy", p.Name, "names", len(res.Names), "serial", res.Serial)
			all = append(all, res.Names...)
		case "hosts", "":
			// Hosts feed → same CDB path (download via unboundrpz helpers).
			if strings.TrimSpace(p.Source) == "" {
				continue
			}
			n, err := a.hostsNamesForCDB(p)
			if err != nil {
				return 0, fmt.Errorf("policy %s: %w", p.Name, err)
			}
			all = append(all, n...)
		}
	}
	filtered := blockcdb.FilterBlockNames(all)
	if err := blockcdb.EnsureEmpty(a.dataDir); err != nil {
		return 0, err
	}
	_, cdbN, err := blockcdb.SyncNames(a.dataDir, filtered)
	if err != nil {
		return 0, err
	}
	// Keep Unbound RPZ zones minimal (recurse-only behind dnsdist).
	_ = unboundrpz.WriteMinimalTrustZone(a.dataDir)
	_ = unboundrpz.EnsureEmptyZones(unboundrpz.Dir(a.dataDir))
	return cdbN, nil
}

func (a *API) hostsNamesForCDB(p rpz.PolicyConfig) ([]string, error) {
	src := strings.TrimSpace(p.Source)
	var hostsPath string
	var cleanup func()
	var err error
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		hostsPath, cleanup, err = unboundrpz.DownloadHosts(src, 30*time.Minute)
		if err != nil {
			return nil, err
		}
		if cleanup != nil {
			defer cleanup()
		}
	} else {
		hostsPath = src
	}
	return readHostsNames(hostsPath)
}

func readHostsNames(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		name := fields[0]
		if len(fields) >= 2 && (net.ParseIP(fields[0]) != nil || fields[0] == "0.0.0.0" || fields[0] == "127.0.0.1") {
			name = fields[1]
		}
		name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
		if name != "" {
			out = append(out, name)
		}
	}
	return out, nil
}

func (a *API) tryReloadDNSDist() {
	// CDBKVStore refreshes on interval; optional console nudge.
	addr := strings.TrimSpace(os.Getenv("POWERSVX_DNSDIST_CONTROL"))
	if addr == "" {
		addr = "127.0.0.1:5199"
	}
	key := strings.TrimSpace(os.Getenv("POWERSVX_DNSDIST_KEY"))
	if key == "" {
		key = "powersvx-dnsdist-console"
	}
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		a.log.Debug("dnsdist control not ready", "addr", addr, "err", err)
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	// dnsdist console speaks a simple line protocol after key handshake is complex;
	// rely on CDB refresh interval (default 30s). Log intent only.
	a.log.Info("dnsdist cdb updated; store refresh within CDB interval", "control", addr, "key_set", key != "")
}
