package api

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/powersvx/powersvx/internal/blockcdb"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/dnsdistctl"
	"github.com/powersvx/powersvx/internal/rpz"
	"github.com/powersvx/powersvx/internal/unboundrpz"
)

func rpzUsesDNSDistDataplane() bool { return config.DNSDistDataplane() }

// TriggerDNSDistCDBSync starts async AXFR/hosts → CDB rebuild (dnsdist dataplane).
func (a *API) TriggerDNSDistCDBSync() error {
	return a.startDNSDistCDBRefresh(false, "startup")
}

// TryBootstrapFilterSeed downloads GitHub (or configured) seed when CDB is empty.
// Returns true if a seed was installed. Caller should then run CDB refresh for IXFR.
func (a *API) TryBootstrapFilterSeed() (bool, error) {
	if !rpzUsesDNSDistDataplane() {
		return false, nil
	}
	if !blockcdb.NeedsSeed(a.dataDir) {
		return false, nil
	}
	url := config.FilterSeedURL()
	if url == "" {
		return false, nil
	}
	man, err := blockcdb.BootstrapFromURL(a.dataDir, url, 30*time.Minute)
	if err != nil {
		return false, err
	}
	if man.Entries > 0 {
		a.unboundRPZEntries.Store(int64(man.Entries))
	} else {
		a.RefreshUnboundEntryCount()
	}
	a.tryReloadDNSDist()
	a.log.Info("filter seed installed",
		"url", url, "serial", man.Serial, "entries", man.Entries, "policy", man.Policy)
	return true, nil
}

func feedCachePath(dataDir, policyName string) string {
	sum := sha256.Sum256([]byte(policyName))
	safe := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, policyName)
	if len(safe) > 32 {
		safe = safe[:32]
	}
	if safe == "" {
		safe = "feed"
	}
	return filepath.Join(blockcdb.Dir(dataDir), "feeds", safe+"-"+hex.EncodeToString(sum[:4])+".txt")
}

func writeFeedFileAtomic(path string, names []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	w := bufio.NewWriterSize(f, 1<<20)
	for _, n := range names {
		n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
		if n == "" {
			continue
		}
		if _, err := w.WriteString(n); err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
			return err
		}
		if err := w.WriteByte('\n'); err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
			return err
		}
	}
	if err := w.Flush(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// mergeFeedFile applies an IXFR delta to a feed cache file by streaming it: lines in removed are
// dropped, lines in added that the file lacks are appended, everything else stays in order.
// Memory use is the size of the delta, not of the feed. An unreadable feed returns an error and
// leaves the file as it was, so the caller can fall back to a full transfer.
func mergeFeedFile(path string, removed, added []string) (int, error) {
	norm := func(s string) string { return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), ".")) }
	rm := make(map[string]struct{}, len(removed))
	for _, n := range removed {
		rm[norm(n)] = struct{}{}
	}
	add := make(map[string]bool, len(added))
	addOrder := make([]string, 0, len(added))
	for _, n := range added {
		if n = norm(n); n != "" {
			if _, dup := add[n]; !dup {
				add[n] = false
				addOrder = append(addOrder, n)
			}
		}
	}
	in, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer in.Close()
	tmp := path + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return 0, err
	}
	done := false
	defer func() {
		if !done {
			_ = out.Close()
			_ = os.Remove(tmp)
		}
	}()
	w := bufio.NewWriterSize(out, 1<<20)
	count := 0
	put := func(n string) error {
		count++
		if _, err := w.WriteString(n); err != nil {
			return err
		}
		return w.WriteByte('\n')
	}
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		line := strings.ToLower(strings.TrimSpace(sc.Text()))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, drop := rm[line]; drop {
			continue
		}
		if _, ok := add[line]; ok {
			add[line] = true
		}
		if err := put(line); err != nil {
			return 0, err
		}
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	for _, n := range addOrder {
		if !add[n] {
			if err := put(n); err != nil {
				return 0, err
			}
		}
	}
	if err := w.Flush(); err != nil {
		return 0, err
	}
	if err := out.Close(); err != nil {
		return 0, err
	}
	done = true
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return 0, err
	}
	return count, nil
}

func streamAXFRToFeedFile(ctx context.Context, zone string, masters []string, auth rpz.TSIGAuth, path string) (serial uint32, master string, count int, err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return 0, "", 0, err
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return 0, "", 0, err
	}
	w := bufio.NewWriterSize(f, 1<<20)
	ser, m, cnt, err := rpz.StreamAXFRNames(ctx, zone, masters, auth, func(rel string) error {
		n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rel), "."))
		if n == "" {
			return nil
		}
		if _, werr := w.WriteString(n); werr != nil {
			return werr
		}
		return w.WriteByte('\n')
	})
	if err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return 0, "", 0, err
	}
	if err := w.Flush(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return 0, "", 0, err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return 0, "", 0, err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return 0, "", 0, err
	}
	return ser, m, cnt, nil
}

func (a *API) pullAndWriteBlockCDB(parent context.Context, policies []rpz.PolicyConfig) (int, error) {
	ctx, cancel := context.WithTimeout(parent, 45*time.Minute)
	defer cancel()

	state := rpz.LoadAxfrState(rpz.AxfrStatePath(a.dataDir))
	existing := existingCDBCount(a.dataDir)
	globalTxtPath := filepath.Join(blockcdb.Dir(a.dataDir), blockcdb.DomainsFile)

	var enabled []rpz.PolicyConfig
	for _, p := range policies {
		if rpz.PolicyEnabled(p) {
			enabled = append(enabled, p)
		} else {
			a.log.Info("rpz feed skipped (policy disabled)", "policy", p.Name)
		}
	}

	activeKeyList := make([]string, 0, len(enabled))
	for _, p := range enabled {
		activeKeyList = append(activeKeyList, p.Name+"|"+strings.ToLower(strings.TrimSpace(p.Format))+"|"+config.NormalizeName(p.Zone)+"|"+strings.TrimSpace(p.Source))
	}
	activeManifest := strings.Join(activeKeyList, "\n")
	manifestPath := filepath.Join(blockcdb.Dir(a.dataDir), "feeds", "manifest.txt")
	prevManifestBytes, _ := os.ReadFile(manifestPath)
	// A previous run that changed the feeds but never finished the CDB must be redone even when
	// the upstream serial has not moved, or the older CDB would stay in service.
	needRewrite := string(prevManifestBytes) != activeManifest || blockcdb.RebuildPending(a.dataDir)

	feedFiles := make([]string, 0, len(enabled))
	for _, p := range enabled {
		format := strings.ToLower(strings.TrimSpace(p.Format))
		if format == "" {
			format = "hosts"
		}
		if err := ctx.Err(); err != nil {
			return existing, err
		}
		feedPath := feedCachePath(a.dataDir, p.Name)

		switch format {
		case "axfr":
			zone := config.NormalizeName(p.Zone)
			auth := rpz.TSIGAuth{}
			if p.TSIGKey != "" && p.TSIGSecret != "" {
				auth = rpz.TSIGAuth{Name: p.TSIGKey, Secret: p.TSIGSecret}
			}

			var localSerial uint32
			if st, ok := state.Get(p.Name); ok && config.NormalizeName(st.Zone) == zone {
				localSerial = st.Serial
			} else if man, ok := blockcdb.ReadSeedManifest(a.dataDir); ok &&
				(man.Policy == p.Name || config.NormalizeName(man.Zone) == zone) {
				localSerial = man.Serial
			}
			remote, master, err := rpz.QuerySOASerialWithTSIG(ctx, zone, p.Masters, auth)

			_, feedErr := os.Stat(feedPath)
			hasFeedFile := feedErr == nil
			// Migrate existing single-policy seed domains.txt (or domains.cdb keys) into this policy's cache seamlessly.
			if !hasFeedFile && len(enabled) == 1 && existing > 0 {
				var base []string
				if _, gerr := os.Stat(globalTxtPath); gerr == nil {
					base, _ = readDomainsTxt(globalTxtPath)
				}
				if len(base) == 0 {
					base, _ = blockcdb.ReadCDBKeys(filepath.Join(blockcdb.Dir(a.dataDir), blockcdb.CDBFile))
				}
				if len(base) > 0 {
					if werr := writeFeedFileAtomic(feedPath, base); werr == nil {
						hasFeedFile = true
					}
				}
			}

			if err == nil && localSerial > 0 && !rpz.SerialGreater(remote, localSerial) && hasFeedFile && existing > 0 {
				_ = state.PutSuccess(p.Name, zone, "skipped", master, remote,
					fmt.Sprintf("SOA unchanged · serial %d · master %s", remote, master))
				a.log.Info("axfr skipped (SOA unchanged)", "policy", p.Name, "serial", remote, "master", master)
				feedFiles = append(feedFiles, feedPath)
				continue
			}

			_ = blockcdb.MarkRebuildPending(a.dataDir)
			var transferSerial uint32
			var mode string
			if localSerial > 0 && hasFeedFile {
				res, perr := rpz.PullZoneWithTSIG(ctx, zone, p.Masters, localSerial, auth)
				if perr != nil {
					_ = state.PutFailure(p.Name, zone, master, perr.Error())
					if existing > 0 {
						a.log.Warn("axfr failed; keeping last-good CDB", "policy", p.Name, "entries", existing, "err", perr)
						return existing, fmt.Errorf("policy %s: %w (serving last CDB %d entries)", p.Name, perr, existing)
					}
					return 0, fmt.Errorf("policy %s: %w", p.Name, perr)
				}
				if res.Master != "" {
					master = res.Master
				}
				transferSerial = res.Serial
				if res.FullReplace {
					mode = "full_axfr"
					if werr := writeFeedFileAtomic(feedPath, res.Names); werr != nil {
						return 0, werr
					}
					a.log.Info("axfr pull ok", "policy", p.Name, "mode", mode, "names", len(res.Names), "serial", res.Serial, "master", master)
				} else {
					_, rerr := mergeFeedFile(feedPath, res.Removed, res.Added)
					if rerr != nil {
						ser, m, cnt, serr := streamAXFRToFeedFile(ctx, zone, p.Masters, auth, feedPath)
						if serr != nil {
							_ = state.PutFailure(p.Name, zone, master, serr.Error())
							if existing > 0 {
								return existing, fmt.Errorf("policy %s: %w (serving last CDB)", p.Name, serr)
							}
							return 0, fmt.Errorf("policy %s: %w", p.Name, serr)
						}
						mode = "full_axfr"
						transferSerial = ser
						if m != "" {
							master = m
						}
						a.log.Info("axfr pull ok", "policy", p.Name, "mode", mode, "names", cnt, "serial", ser, "master", master)
					} else {
						mode = "ixfr"
						a.log.Info("ixfr pull ok", "policy", p.Name, "added", len(res.Added), "removed", len(res.Removed), "serial", res.Serial, "master", master)
					}
				}
			} else {
				ser, m, cnt, serr := streamAXFRToFeedFile(ctx, zone, p.Masters, auth, feedPath)
				if serr != nil {
					_ = state.PutFailure(p.Name, zone, master, serr.Error())
					if existing > 0 {
						a.log.Warn("axfr failed; keeping last-good CDB", "policy", p.Name, "entries", existing, "err", serr)
						return existing, fmt.Errorf("policy %s: %w (serving last CDB %d entries)", p.Name, serr, existing)
					}
					return 0, fmt.Errorf("policy %s: %w", p.Name, serr)
				}
				mode = "full_axfr"
				transferSerial = ser
				if m != "" {
					master = m
				}
				a.log.Info("axfr stream pull ok", "policy", p.Name, "mode", mode, "names", cnt, "serial", ser, "master", master)
			}

			_ = state.PutSuccess(p.Name, zone, mode, master, transferSerial,
				fmt.Sprintf("%s ok · serial %d · master %s", strings.ToUpper(mode), transferSerial, master))
			feedFiles = append(feedFiles, feedPath)
			needRewrite = true

		case "hosts":
			if strings.TrimSpace(p.Source) == "" {
				continue
			}
			_ = blockcdb.MarkRebuildPending(a.dataDir)
			names, err := a.hostsNamesForCDB(p)
			if err != nil {
				if existing > 0 {
					return existing, fmt.Errorf("policy %s: %w (serving last CDB)", p.Name, err)
				}
				return 0, fmt.Errorf("policy %s: %w", p.Name, err)
			}
			if werr := writeFeedFileAtomic(feedPath, names); werr != nil {
				return 0, werr
			}
			feedFiles = append(feedFiles, feedPath)
			needRewrite = true
		}
	}

	if !needRewrite && existing > 0 {
		a.log.Info("dnsdist cdb unchanged (SOA skip)", "entries", existing)
		return existing, nil
	}

	if len(feedFiles) == 0 {
		_ = os.MkdirAll(filepath.Dir(manifestPath), 0o755)
		_ = os.WriteFile(manifestPath, []byte(activeManifest), 0o644)
		blockcdb.ClearRebuildPending(a.dataDir)
		if err := blockcdb.EnsureEmpty(a.dataDir); err != nil {
			return 0, err
		}
		return 0, nil
	}

	// The feed caches stream through the rebuild; their names are never all in memory at once.
	_, cdbN, err := blockcdb.SyncFeedFilesGuardedContext(ctx, a.dataDir, feedFiles)
	if err != nil {
		return 0, err
	}
	_ = os.MkdirAll(filepath.Dir(manifestPath), 0o755)
	_ = os.WriteFile(manifestPath, []byte(activeManifest), 0o644)
	blockcdb.ClearRebuildPending(a.dataDir)
	return cdbN, nil
}

func existingCDBCount(dataDir string) int {
	meta := filepath.Join(blockcdb.Dir(dataDir), "blocklist.meta.json")
	b, err := os.ReadFile(meta)
	if err != nil {
		return 0
	}
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
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ctl := dnsdistctl.DefaultClient()
	if st, err := ctl.Stats(ctx); err == nil {
		_ = ctl.FlushCache(ctx)
		a.log.Info("dnsdist cdb updated & packet cache flushed", "web", ctl.WebURL, "queries", st["queries"])
		return
	}
	addr := strings.TrimSpace(os.Getenv("POWERSVX_DNSDIST_CONTROL"))
	if addr == "" {
		addr = "127.0.0.1:5199"
	}
	a.log.Debug("dnsdist webserver not reachable yet; CDB reloads automatically on interval", "addr", addr)
}

// syncFilterCDBs rebuilds whitelist.cdb (+ banks.lua) and custom_blacklist.cdb immediately
// so dnsdist edge filtering stays live with UI allow/block changes.
func (a *API) syncFilterCDBs() {
	if a == nil || a.srv == nil {
		return
	}
	var wlDomains, blDomains []string
	if wl := a.srv.Allowlist(); wl != nil {
		wlDomains = wl.List()
	}
	if bl := a.srv.Denylist(); bl != nil {
		blDomains = bl.List()
	}
	if n, err := blockcdb.SyncWhitelist(a.dataDir, wlDomains); err != nil {
		a.log.Warn("sync whitelist.cdb failed", "err", err)
	} else {
		a.log.Info("whitelist.cdb synced", "entries", n)
	}
	if n, err := blockcdb.SyncCustomBlacklist(a.dataDir, blDomains); err != nil {
		a.log.Warn("sync custom_blacklist.cdb failed", "err", err)
	} else {
		a.log.Info("custom_blacklist.cdb synced", "entries", n)
	}
	a.tryReloadDNSDist()
}

// syncAuthZonesCDB writes authzones.cdb so dnsdist routes PowerSVX authoritative zones to :5354.
func (a *API) syncAuthZonesCDB() []string {
	var zoneNames []string
	if a.auth != nil {
		for _, z := range a.auth.ListZones() {
			zoneNames = append(zoneNames, z.Name)
		}
	}
	if n, err := blockcdb.SyncAuthZones(a.dataDir, zoneNames); err != nil {
		a.log.Warn("sync authzones.cdb failed", "err", err)
	} else {
		a.log.Info("authzones.cdb synced", "zones", n)
	}
	return zoneNames
}

// SyncSecondaryDataplane updates authzones.cdb, dnsdist, and Unbound routing after a secondary zone changes.
func (a *API) SyncSecondaryDataplane(zone string) {
	if a == nil || a.srv == nil || !config.DNSDistDataplane() {
		return
	}
	zoneNames := a.syncAuthZonesCDB()
	a.tryReloadDNSDist()
	a.syncUnboundRuntime(zoneNames)
	if a.log != nil && zone != "" {
		a.log.Info("secondary dataplane synced", "zone", zone, "auth_zones", len(zoneNames))
	}
}

func (a *API) syncUnboundRuntime(zoneNames []string) {
	if !config.DNSDistDataplane() {
		return
	}

	flags := a.srv.RuntimeFlags()
	authPort := 5354
	if a.cfg != nil && a.cfg.Server.UDPPort > 0 && a.cfg.Server.UDPPort != 53 {
		authPort = a.cfg.Server.UDPPort
	}
	fwd := flags.Forwarders
	if fwd == nil && a.cfg != nil {
		fwd = a.cfg.Resolver.Forwarders
	}
	fz := flags.ForwardZones
	if fz == nil && a.cfg != nil {
		fz = a.cfg.Resolver.ForwardZones
	}
	spec := unboundrpz.RuntimeSyncSpec{
		ResolverMode:  flags.ResolverMode,
		ForwardOnFail: flags.ForwardOnFail,
		Forwarders:    fwd,
		ForwardZones:  fz,
		DNSSECMode:    a.srv.DNSSECMode(),
		ECSEnabled:    flags.ECS,
		AuthZones:     zoneNames,
		AuthAddr:      fmt.Sprintf("127.0.0.1@%d", authPort),
	}
	report, err := unboundrpz.WriteRuntimeConfig(a.dataDir, spec)
	for _, s := range report.SkippedForwarders {
		a.log.Warn("resolver forwarder skipped: it points back into the Dataplane and would make Unbound forward to itself",
			"zone", s.Zone, "forwarder", s.Addr, "points_at", s.Reason)
	}
	if err != nil {
		a.unboundSync.record(report, err, nil)
		a.log.Error("unbound runtime config write failed", "err", err)
		return
	}
	reloadErr := unboundrpz.TryReload()
	gen := a.unboundSync.record(report, nil, reloadErr)
	switch {
	case reloadErr == nil:
		a.log.Info("unbound runtime config synced & reloaded")
	case !hostDeployment():
		// Outside a host deployment no Unbound is expected, so this is not a fault.
		a.log.Debug("unbound reload skipped after runtime sync", "err", reloadErr)
	default:
		a.log.Error("unbound reload failed after writing the runtime config; Unbound keeps its previous configuration",
			"err", reloadErr, "hint", "the control interface must be enabled on 127.0.0.1:8953 in unbound.conf")
		go a.retryReload(gen)
	}
}

// SyncAllDataplanes pushes Control Plane settings, zones, ACLs, filters, and RRL into
// dnsdist CDB/Lua drop-ins and Unbound runtime drop-in configs.
func (a *API) SyncAllDataplanes() {
	if a == nil || a.srv == nil {
		return
	}
	zoneNames := a.syncAuthZonesCDB()
	a.syncFilterCDBs()
	a.SyncDNSDistACL()

	rl := a.srv.RateLimitConfig()
	flags := a.srv.RuntimeFlags()
	_ = dnsdistctl.WriteDynBlockRules(blockcdb.Dir(a.dataDir), dnsdistctl.DynBlockConfig{
		Enabled:      flags.RateLimit,
		QPS:          rl.QPS,
		Burst:        rl.Burst,
		BlockSeconds: rl.BlockDuration,
		Whitelist:    rl.Whitelist,
	})

	a.syncUnboundRuntime(zoneNames)
}
