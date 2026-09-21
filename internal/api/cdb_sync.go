package api

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
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

// startDNSDistCDBRefresh pulls AXFR/IXFR (or hosts) and builds domains.cdb for dnsdist.
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

	state := rpz.LoadAxfrState(rpz.AxfrStatePath(a.dataDir))
	existing := existingCDBCount(a.dataDir)
	var all []string
	needRewrite := false

	for _, p := range policies {
		format := strings.ToLower(strings.TrimSpace(p.Format))
		switch format {
		case "axfr":
			zone := config.NormalizeName(p.Zone)
			localSerial := uint32(0)
			if st, ok := state.Get(p.Name); ok {
				localSerial = st.Serial
			}
			remote, master, err := rpz.QuerySOASerial(ctx, zone, p.Masters)
			if err == nil && localSerial > 0 && remote == localSerial && existing > 0 {
				_ = state.PutSuccess(p.Name, zone, "skipped", master, remote,
					fmt.Sprintf("SOA unchanged · serial %d · master %s", remote, master))
				a.log.Info("axfr skipped (SOA unchanged)", "policy", p.Name, "serial", remote, "master", master)
				continue
			}
			res, err := rpz.PullZone(ctx, zone, p.Masters, localSerial)
			if err != nil {
				_ = state.PutFailure(p.Name, zone, "", err.Error())
				return 0, fmt.Errorf("policy %s: %w", p.Name, err)
			}
			mode := "full_axfr"
			if localSerial > 0 && !res.FullReplace {
				mode = "ixfr"
			}
			if res.FullReplace {
				a.log.Info("axfr pull ok", "policy", p.Name, "mode", mode, "names", len(res.Names), "serial", res.Serial)
				all = append(all, res.Names...)
			} else {
				base, err := readDomainsTxt(filepath.Join(blockcdb.Dir(a.dataDir), blockcdb.DomainsFile))
				if err != nil {
					// No local list — fall back to full AXFR.
					a.log.Warn("ixfr without domains.txt; forcing AXFR", "policy", p.Name, "err", err)
					res2, err2 := rpz.PullZone(ctx, zone, p.Masters, 0)
					if err2 != nil {
						_ = state.PutFailure(p.Name, zone, "", err2.Error())
						return 0, fmt.Errorf("policy %s: %w", p.Name, err2)
					}
					mode = "full_axfr"
					all = append(all, res2.Names...)
					res = res2
				} else {
					set := make(map[string]struct{}, len(base)+len(res.Added))
					for _, n := range base {
						set[n] = struct{}{}
					}
					for _, n := range res.Removed {
						delete(set, strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), ".")))
					}
					for _, n := range res.Added {
						n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
						if n != "" {
							set[n] = struct{}{}
						}
					}
					merged := make([]string, 0, len(set))
					for n := range set {
						merged = append(merged, n)
					}
					a.log.Info("ixfr pull ok", "policy", p.Name, "added", len(res.Added), "removed", len(res.Removed), "serial", res.Serial)
					all = append(all, merged...)
				}
			}
			_ = state.PutSuccess(p.Name, zone, mode, master, res.Serial,
				fmt.Sprintf("%s ok · serial %d", strings.ToUpper(mode), res.Serial))
			needRewrite = true
		case "hosts", "":
			if strings.TrimSpace(p.Source) == "" {
				continue
			}
			n, err := a.hostsNamesForCDB(p)
			if err != nil {
				return 0, fmt.Errorf("policy %s: %w", p.Name, err)
			}
			all = append(all, n...)
			needRewrite = true
		}
	}

	if !needRewrite {
		if existing > 0 {
			a.log.Info("dnsdist cdb unchanged (SOA skip)", "entries", existing)
			return existing, nil
		}
		// First boot with empty policies / empty CDB.
		if err := blockcdb.EnsureEmpty(a.dataDir); err != nil {
			return 0, err
		}
		return 0, nil
	}

	filtered := blockcdb.FilterBlockNames(all)
	if err := blockcdb.EnsureEmpty(a.dataDir); err != nil {
		return 0, err
	}
	_, cdbN, err := blockcdb.SyncNames(a.dataDir, filtered)
	if err != nil {
		return 0, err
	}
	_ = unboundrpz.WriteMinimalTrustZone(a.dataDir)
	_ = unboundrpz.EnsureEmptyZones(unboundrpz.Dir(a.dataDir))
	return cdbN, nil
}

func existingCDBCount(dataDir string) int {
	meta := filepath.Join(blockcdb.Dir(dataDir), "blocklist.meta.json")
	b, err := os.ReadFile(meta)
	if err != nil {
		return 0
	}
	// tiny JSON: {"domains":N,"cdb":N,...}
	var n int
	for _, part := range strings.Split(string(b), ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, `"cdb":`) {
			fmt.Sscanf(part, `"cdb":%d`, &n)
			return n
		}
	}
	return 0
}

func readDomainsTxt(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	buf := make([]byte, 0, 1024*1024)
	sc.Buffer(buf, 8*1024*1024)
	for sc.Scan() {
		line := strings.ToLower(strings.TrimSpace(sc.Text()))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
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
	a.log.Info("dnsdist cdb updated; store refresh within CDB interval", "control", addr, "key_set", key != "")
}
