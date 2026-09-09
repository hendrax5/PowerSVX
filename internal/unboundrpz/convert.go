package unboundrpz

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/powersvx/powersvx/internal/allowlist"
	"github.com/powersvx/powersvx/internal/config"
)

const (
	TrustZoneName = "rpz.trustpositif."
	BankZoneName  = "rpz.banks."
	AXFRZoneName  = "rpz.axfr."
	TrustFile     = "trustpositif.rpz"
	BankFile      = "banks.rpz"
)

// writeZoneHeader writes TTL/ORIGIN/SOA/NS. zone must end with a trailing dot.
func writeZoneHeader(w io.Writer, zone string, serial int64) {
	zone = strings.TrimSpace(zone)
	if zone != "" && !strings.HasSuffix(zone, ".") {
		zone += "."
	}
	fmt.Fprintf(w, "$TTL 60\n$ORIGIN %s\n@ SOA localhost. root.localhost. %d 3600 600 86400 60\n@ NS localhost.\n", zone, serial)
}

// rpzOwner returns a relative owner name (no trailing dot) so $ORIGIN appends the RPZ apex.
// Unbound requires every RR owner to be a subdomain of the configured rpz name.
func rpzOwner(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// Dir is where Unbound reads RPZ zonefiles (bind-mounted).
func Dir(dataDir string) string {
	if d := strings.TrimSpace(os.Getenv("POWERSVX_UNBOUND_RPZ_DIR")); d != "" {
		return d
	}
	if dataDir == "" {
		dataDir = "./data"
	}
	return filepath.Join(dataDir, "unbound-rpz")
}

// EnsureEmptyZones creates minimal valid RPZ SOA/NS so Unbound can start before first sync.
func EnsureEmptyZones(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, pair := range []struct {
		file string
		zone string
	}{
		{BankFile, BankZoneName},
		{TrustFile, TrustZoneName},
		{AXFRFile, AXFRZoneName},
	} {
		path := filepath.Join(dir, pair.file)
		if _, err := os.Stat(path); err == nil {
			continue
		}
		if err := writeMinimalSOA(path, pair.zone); err != nil {
			return err
		}
	}
	return WriteBankPassthru(filepath.Join(dir, BankFile))
}

func writeMinimalSOA(path, zone string) error {
	var b strings.Builder
	writeZoneHeader(&b, zone, 1)
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

// WriteMinimalTrustZone resets trustpositif.rpz to SOA-only (used when filter moves to axfr.rpz).
func WriteMinimalTrustZone(dataDir string) error {
	dir := Dir(dataDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(dir, "trustpositif.partial.json"))
	return writeMinimalSOA(filepath.Join(dir, TrustFile), TrustZoneName)
}

// WriteBankPassthru writes official bank apexes as rpz-passthru (checked before TrustPositif).
func WriteBankPassthru(path string) error {
	var b strings.Builder
	writeZoneHeader(&b, BankZoneName, time.Now().Unix())
	for _, apex := range allowlist.OfficialBankApexes() {
		apex = rpzOwner(apex)
		b.WriteString(apex)
		b.WriteString(" CNAME rpz-passthru.\n")
		b.WriteString("*.")
		b.WriteString(apex)
		b.WriteString(" CNAME rpz-passthru.\n")
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ConvertHostsFile streams a hosts-style list into an RPZ zonefile with bank-safe actions.
// action: nxdomain | redirect | nodata; target is sinkhole IP for redirect.
// Unlimited (no cap). Prefer ConvertHostsFileOpts / SyncPolicyHosts for production caps.
func ConvertHostsFile(hostsPath, outPath, action, target string) (int, error) {
	n, _, err := ConvertHostsFileOpts(hostsPath, outPath, ConvertHostsOpts{
		Action: action, Target: target, MaxEntries: 0,
	})
	return n, err
}

// ConvertHostsFileOpts converts hosts→RPZ. When MaxEntries > 0, keeps high-priority
// names first (apex / .id), then mid, then low — so partial lists stay useful on small RAM.
func ConvertHostsFileOpts(hostsPath, outPath string, opts ConvertHostsOpts) (written, scanned int, err error) {
	action := strings.ToLower(strings.TrimSpace(opts.Action))
	if action == "" {
		action = "nxdomain"
	}
	target := strings.TrimSpace(opts.Target)
	if target == "" {
		target = "139.255.196.196"
	}
	max := opts.MaxEntries

	if max > 0 {
		return convertHostsCapped(hostsPath, outPath, action, target, max)
	}
	return convertHostsFull(hostsPath, outPath, action, target)
}

func writeRPZAction(w *bufio.Writer, name, action, target string) {
	act := action
	if act == "redirect" && allowlist.BankLikeName(name) {
		act = "nxdomain"
	}
	switch act {
	case "redirect":
		fmt.Fprintf(w, "%s A %s\n", name, target)
	case "nodata":
		fmt.Fprintf(w, "%s CNAME rpz-nodata.\n", name)
	default:
		fmt.Fprintf(w, "%s CNAME .\n", name)
	}
}

func convertHostsFull(hostsPath, outPath, action, target string) (written, scanned int, err error) {
	in, err := os.Open(hostsPath)
	if err != nil {
		return 0, 0, err
	}
	defer in.Close()

	tmp := outPath + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return 0, 0, err
	}
	w := bufio.NewWriterSize(out, 1<<20)
	writeZoneHeader(w, TrustZoneName, time.Now().Unix())

	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		name := parseHostsName(sc.Text())
		if name == "" {
			continue
		}
		scanned++
		writeRPZAction(w, name, action, target)
		written++
	}
	if err := sc.Err(); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return 0, scanned, err
	}
	if err := finishRPZFile(w, out, tmp, outPath); err != nil {
		return 0, scanned, err
	}
	return written, scanned, nil
}

func convertHostsCapped(hostsPath, outPath, action, target string, max int) (written, scanned int, err error) {
	var counts [prioN]int
	scanned, err = scanHostsPriorities(hostsPath, &counts)
	if err != nil {
		return 0, scanned, err
	}
	var quota [prioN]int
	remain := max
	for p := prioHigh; p < prioN; p++ {
		q := counts[p]
		if q > remain {
			q = remain
		}
		quota[p] = q
		remain -= q
	}

	in, err := os.Open(hostsPath)
	if err != nil {
		return 0, scanned, err
	}
	defer in.Close()

	tmp := outPath + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return 0, scanned, err
	}
	w := bufio.NewWriterSize(out, 1<<20)
	writeZoneHeader(w, TrustZoneName, time.Now().Unix())
	fmt.Fprintf(w, "; powersvx-partial max=%d scanned=%d quota_high=%d mid=%d low=%d\n",
		max, scanned, quota[prioHigh], quota[prioMid], quota[prioLow])

	var used [prioN]int
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		name := parseHostsName(sc.Text())
		if name == "" {
			continue
		}
		p := namePriority(name)
		if used[p] >= quota[p] {
			continue
		}
		writeRPZAction(w, name, action, target)
		used[p]++
		written++
		if written >= max {
			break
		}
	}
	if err := sc.Err(); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return 0, scanned, err
	}
	if err := finishRPZFile(w, out, tmp, outPath); err != nil {
		return 0, scanned, err
	}
	return written, scanned, nil
}

func scanHostsPriorities(hostsPath string, counts *[prioN]int) (scanned int, err error) {
	in, err := os.Open(hostsPath)
	if err != nil {
		return 0, err
	}
	defer in.Close()
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		name := parseHostsName(sc.Text())
		if name == "" {
			continue
		}
		scanned++
		counts[namePriority(name)]++
	}
	return scanned, sc.Err()
}

func finishRPZFile(w *bufio.Writer, out *os.File, tmp, outPath string) error {
	if err := w.Flush(); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, outPath)
}

func looksIP(s string) bool {
	dots := 0
	for _, c := range s {
		if c == '.' {
			dots++
		} else if c < '0' || c > '9' {
			return false
		}
	}
	return dots == 3
}

// DownloadHosts fetches an HTTP(S) hosts feed to a temp file.
func DownloadHosts(url string, timeout time.Duration) (path string, cleanup func(), err error) {
	if timeout <= 0 {
		timeout = 15 * time.Minute
	}
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("User-Agent", "PowerSVX-unboundrpz/1.6")
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", nil, fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}
	f, err := os.CreateTemp("", "powersvx-hosts-*.txt")
	if err != nil {
		return "", nil, err
	}
	path = f.Name()
	cleanup = func() { _ = os.Remove(path) }
	if _, err := io.Copy(f, resp.Body); err != nil {
		_ = f.Close()
		cleanup()
		return "", nil, err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", nil, err
	}
	return path, cleanup, nil
}

// SyncPolicyHosts downloads/converts one hosts policy into TrustFile + refreshes banks.
func SyncPolicyHosts(dataDir, source, action, target string, timeout time.Duration) (entries int, err error) {
	dir := Dir(dataDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, err
	}
	_ = WriteBankPassthru(filepath.Join(dir, BankFile))

	var hostsPath string
	var cleanup func()
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		hostsPath, cleanup, err = DownloadHosts(source, timeout)
		if err != nil {
			return 0, err
		}
		if cleanup != nil {
			defer cleanup()
		}
	} else {
		hostsPath = source
	}
	max := MaxEntriesFromEnv()
	written, scanned, err := ConvertHostsFileOpts(hostsPath, filepath.Join(dir, TrustFile), ConvertHostsOpts{
		Action: action, Target: target, MaxEntries: max,
	})
	if err != nil {
		return 0, err
	}
	if max > 0 && scanned > written {
		// Partial list on purpose — caller logs entries=written.
		_ = os.WriteFile(filepath.Join(dir, "trustpositif.partial.json"), []byte(fmt.Sprintf(
			`{"written":%d,"scanned":%d,"max_entries":%d,"capped":true}`+"\n", written, scanned, max)), 0o644)
	} else {
		_ = os.Remove(filepath.Join(dir, "trustpositif.partial.json"))
	}
	return written, nil
}

// SyncFromConfigPolicies converts the first hosts policy (and writes banks). AXFR policies
// should call SyncAXFRNames separately.
func SyncFromConfigPolicies(dataDir string, policies []config.RPZPolicyTOML, timeout time.Duration) (int, error) {
	dir := Dir(dataDir)
	if err := EnsureEmptyZones(dir); err != nil {
		return 0, err
	}
	total := 0
	for _, p := range policies {
		format := strings.ToLower(strings.TrimSpace(p.Format))
		if format == "" {
			format = "hosts"
		}
		if format != "hosts" {
			continue
		}
		n, err := SyncPolicyHosts(dataDir, p.Source, p.Action, p.Target, timeout)
		if err != nil {
			return total, fmt.Errorf("policy %s: %w", p.Name, err)
		}
		total += n
	}
	return total, nil
}
