package unboundrpz

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/powersvx/powersvx/internal/allowlist"
)

const AXFRFile = "axfr.rpz"

// WriteNamesRPZ writes a list of owner names (already relative / FQDN) as RPZ records.
func WriteNamesRPZ(outPath string, names []string, action, target string) (int, error) {
	action = strings.ToLower(strings.TrimSpace(action))
	if action == "" {
		action = "nxdomain"
	}
	target = strings.TrimSpace(target)
	if target == "" {
		target = "139.255.196.196"
	}
	var b strings.Builder
	writeZoneHeader(&b, AXFRZoneName, time.Now().Unix())
	n := 0
	for _, name := range names {
		name = rpzOwner(name)
		if name == "" {
			continue
		}
		if allowlist.OfficialBankName(name) {
			continue
		}
		act := action
		if act == "redirect" && allowlist.BankLikeName(name) {
			act = "nxdomain"
		}
		switch act {
		case "redirect":
			fmt.Fprintf(&b, "%s A %s\n", name, target)
		case "nodata":
			fmt.Fprintf(&b, "%s CNAME rpz-nodata.\n", name)
		case "cname":
			tgt := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(target)), ".")
			if tgt == "" {
				tgt = "lamanlabuh.aduankonten.id"
			}
			fmt.Fprintf(&b, "%s CNAME %s.\n", name, tgt)
		default:
			fmt.Fprintf(&b, "%s CNAME .\n", name)
		}
		n++
	}
	tmp := outPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o644); err != nil {
		return 0, err
	}
	if err := os.Rename(tmp, outPath); err != nil {
		return 0, err
	}
	return n, nil
}

// SyncAXFRNames writes the AXFR-derived name list into axfr.rpz under Dir.
// Respects POWERSVX_RPZ_MAX_ENTRIES (same auto-cap as TrustPositif hosts).
func SyncAXFRNames(dataDir string, names []string, action, target string) (int, error) {
	dir := Dir(dataDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, err
	}
	max := MaxEntriesFromEnv()
	selected := SelectNamesByPriority(names, max)
	n, err := WriteNamesRPZ(filepath.Join(dir, AXFRFile), selected, action, target)
	if err != nil {
		return 0, err
	}
	meta := filepath.Join(dir, "axfr.partial.json")
	if max > 0 && len(names) > n {
		_ = os.WriteFile(meta, []byte(fmt.Sprintf(
			`{"written":%d,"scanned":%d,"max_entries":%d,"capped":true}`+"\n", n, len(names), max)), 0o644)
	} else {
		_ = os.Remove(meta)
	}
	return n, nil
}

// SelectNamesByPriority keeps up to max names, preferring .id/apex over deep trees.
// max <= 0 means unlimited (return names unchanged).
func SelectNamesByPriority(names []string, max int) []string {
	if max <= 0 || len(names) <= max {
		return names
	}
	var buckets [prioN][]string
	for _, name := range names {
		name = rpzOwner(name)
		if name == "" || allowlist.OfficialBankName(name) {
			continue
		}
		p := namePriority(name)
		buckets[p] = append(buckets[p], name)
	}
	out := make([]string, 0, max)
	for p := prioHigh; p < prioN && len(out) < max; p++ {
		for _, name := range buckets[p] {
			if len(out) >= max {
				break
			}
			out = append(out, name)
		}
	}
	return out
}
