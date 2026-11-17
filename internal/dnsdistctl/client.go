package dnsdistctl

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Client talks to dnsdist HTTP webserver (:8083) and console control (docker exec / dnsdist CLI)
// and writes file-watched runtime policies synced every <=1s by dnsdist maintenance().
type Client struct {
	WebURL    string
	User      string
	Password  string
	APIKey    string
	Container string
	ConfPath  string
	HTTP      *http.Client
}

// DefaultClient builds a Client from standard PowerSVX environment variables.
func DefaultClient() *Client {
	web := strings.TrimSpace(os.Getenv("POWERSVX_DNSDIST_WEB"))
	if web == "" {
		web = "http://127.0.0.1:8083"
	}
	user := strings.TrimSpace(os.Getenv("POWERSVX_DNSDIST_WEB_USER"))
	if user == "" {
		user = "dontcare"
	}
	pass := strings.TrimSpace(os.Getenv("POWERSVX_DNSDIST_WEB_PASSWORD"))
	if pass == "" {
		pass = "powersvx"
	}
	key := strings.TrimSpace(os.Getenv("POWERSVX_DNSDIST_API_KEY"))
	if key == "" {
		key = "powersvx-api"
	}
	container := strings.TrimSpace(os.Getenv("POWERSVX_DNSDIST_CONTAINER"))
	if container == "" {
		container = "powersvx-dnsdist-1"
	}
	confPath := strings.TrimSpace(os.Getenv("POWERSVX_DNSDIST_CONF"))
	if confPath == "" {
		confPath = "/etc/dnsdist/dnsdist.conf"
	}
	return &Client{
		WebURL:    strings.TrimRight(web, "/"),
		User:      user,
		Password:  pass,
		APIKey:    key,
		Container: container,
		ConfPath:  confPath,
		HTTP:      &http.Client{Timeout: 3 * time.Second},
	}
}

// Stats returns numeric counters from dnsdist /jsonstat?command=stats.
func (c *Client) Stats(ctx context.Context) (map[string]float64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.WebURL+"/jsonstat?command=stats", nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.User, c.Password)
	if c.APIKey != "" {
		req.Header.Set("X-API-Key", c.APIKey)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("dnsdist jsonstat HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}
	out := make(map[string]float64, len(raw))
	for k, v := range raw {
		switch t := v.(type) {
		case float64:
			out[k] = t
		case json.Number:
			f, _ := t.Float64()
			out[k] = f
		}
	}
	return out, nil
}

// Exec runs a Lua expression against the live dnsdist process using local CLI or docker exec.
func (c *Client) Exec(ctx context.Context, luaExpr string) (string, error) {
	luaExpr = strings.TrimSpace(luaExpr)
	if luaExpr == "" {
		return "", fmt.Errorf("empty dnsdist command")
	}
	var errs []string
	if bin, err := exec.LookPath("dnsdist"); err == nil {
		cmd := exec.CommandContext(ctx, bin, "-C", c.ConfPath, "-e", luaExpr)
		out, err := cmd.CombinedOutput()
		if err == nil {
			return strings.TrimSpace(string(out)), nil
		}
		errs = append(errs, fmt.Sprintf("local dnsdist: %v (%s)", err, bytes.TrimSpace(out)))
	}
	if bin, err := exec.LookPath("docker"); err == nil && c.Container != "" {
		cmd := exec.CommandContext(ctx, bin, "exec", c.Container, "dnsdist", "-C", "/etc/dnsdist/dnsdist.conf", "-e", luaExpr)
		out, err := cmd.CombinedOutput()
		if err == nil {
			return strings.TrimSpace(string(out)), nil
		}
		errs = append(errs, fmt.Sprintf("docker exec %s: %v (%s)", c.Container, err, bytes.TrimSpace(out)))
	}
	if len(errs) == 0 {
		return "", fmt.Errorf("neither dnsdist nor docker CLI available")
	}
	return "", fmt.Errorf("%s", strings.Join(errs, "; "))
}

// ExpungeByName removes a domain from dnsdist packet caches immediately.
func (c *Client) ExpungeByName(ctx context.Context, qname string) error {
	qname = sanitizeDNSLabel(qname)
	if qname == "" {
		return fmt.Errorf("invalid domain name")
	}
	lua := fmt.Sprintf(
		`local n = newDNSName("%s."); if getPool(""):getCache() then getPool(""):getCache():expungeByName(n) end; if getPool("auth") and getPool("auth"):getCache() then getPool("auth"):getCache():expungeByName(n) end`,
		qname,
	)
	_, err := c.Exec(ctx, lua)
	return err
}

// FlushCache clears dnsdist packet caches.
func (c *Client) FlushCache(ctx context.Context) error {
	lua := `for _, p in ipairs({"", "auth"}) do local pool = getPool(p); if pool and pool:getCache() then local c = pool:getCache(); c:expunge(c:getEntriesCount()) end end`
	_, err := c.Exec(ctx, lua)
	return err
}

// DynBlockEntry describes a dynamically blocked or manually banned client prefix in dnsdist.
type DynBlockEntry struct {
	Prefix  string `json:"prefix"`
	Reason  string `json:"reason"`
	Seconds int    `json:"seconds,omitempty"`
	Blocks  uint64 `json:"blocks,omitempty"`
	Action  string `json:"action,omitempty"`
	Source  string `json:"source"`
}

// ShowDynBlocks queries /jsonstat?command=dynblocklist or falls back to showDynBlocks().
func (c *Client) ShowDynBlocks(ctx context.Context) ([]DynBlockEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.WebURL+"/jsonstat?command=dynblocklist", nil)
	if err == nil {
		req.SetBasicAuth(c.User, c.Password)
		if c.APIKey != "" {
			req.Header.Set("X-API-Key", c.APIKey)
		}
		if resp, doErr := c.HTTP.Do(req); doErr == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var raw map[string]struct {
					Reason  string `json:"reason"`
					Seconds int    `json:"seconds"`
					Blocks  uint64 `json:"blocks"`
					Action  string `json:"action"`
				}
				if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&raw); err == nil {
					out := make([]DynBlockEntry, 0, len(raw))
					for k, v := range raw {
						out = append(out, DynBlockEntry{
							Prefix:  k,
							Reason:  v.Reason,
							Seconds: v.Seconds,
							Blocks:  v.Blocks,
							Action:  v.Action,
							Source:  "dnsdist_dynblock",
						})
					}
					return out, nil
				}
			}
		}
	}

	out, err := c.Exec(ctx, "showDynBlocks()")
	if err != nil {
		return nil, err
	}
	return ParseShowDynBlocks(out), nil
}

// ParseShowDynBlocks parses the tabular text output of dnsdist showDynBlocks().
func ParseShowDynBlocks(raw string) []DynBlockEntry {
	var entries []DynBlockEntry
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "What") || strings.HasPrefix(line, "-") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		if _, err := netip.ParsePrefix(fields[0]); err != nil {
			if _, err2 := netip.ParseAddr(fields[0]); err2 != nil {
				continue
			}
		}
		sec, _ := strconv.Atoi(fields[1])
		blocks, _ := strconv.ParseUint(fields[2], 10, 64)
		reason := strings.Join(fields[3:], " ")
		entries = append(entries, DynBlockEntry{
			Prefix:  fields[0],
			Seconds: sec,
			Blocks:  blocks,
			Reason:  reason,
			Source:  "dnsdist_dynblock",
		})
	}
	return entries
}

// ClearDynBlocks clears all dynamic blocks in dnsdist immediately.
func (c *Client) ClearDynBlocks(ctx context.Context) error {
	_, err := c.Exec(ctx, "clearDynBlocks()")
	return err
}

// QuerySample represents a recent DNS query observed in dnsdist ring buffers.
type QuerySample struct {
	Timestamp string `json:"timestamp"`
	Client    string `json:"client"`
	ID        string `json:"id,omitempty"`
	QName     string `json:"qname"`
	QType     string `json:"qtype"`
	RCode     string `json:"rcode,omitempty"`
	LatencyMS string `json:"latency_ms,omitempty"`
}

// GrepQueries samples recent queries from dnsdist in-memory ring buffer via grepq("", limit).
func (c *Client) GrepQueries(ctx context.Context, limit int, filter string) ([]QuerySample, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	cleanFilter := sanitizeDNSLabel(filter)
	out, err := c.Exec(ctx, fmt.Sprintf(`grepq(%q, %d)`, cleanFilter, limit))
	if err != nil {
		return nil, err
	}
	return ParseGrepQ(out), nil
}

// ParseGrepQ parses tabular lines returned by dnsdist grepq().
func ParseGrepQ(raw string) []QuerySample {
	var out []QuerySample
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "Time") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		s := QuerySample{
			Timestamp: fields[0],
			Client:    fields[1],
			ID:        fields[2],
			QName:     strings.TrimSuffix(fields[3], "."),
			QType:     fields[4],
		}
		if len(fields) >= 6 {
			s.LatencyMS = fields[5]
		}
		if len(fields) >= 7 {
			s.RCode = strings.Join(fields[6:], " ")
		}
		out = append(out, s)
	}
	return out
}

// WriteManualBans writes persistent blocked CIDRs/IPs for dnsdist maintenance() NMG sync.
func WriteManualBans(blocklistDir string, cidrs []string) error {
	if err := os.MkdirAll(blocklistDir, 0o755); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("# AUTO-GENERATED by PowerSVX - persistent manual edge bans\n")
	for _, raw := range cidrs {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			addr, err := netip.ParseAddr(s)
			if err != nil {
				continue
			}
			s = netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()).String()
		} else {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				continue
			}
			s = p.Masked().String()
		}
		b.WriteString(s)
		b.WriteByte('\n')
	}
	p := filepath.Join(blocklistDir, "bans.txt")
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// DynBlockConfig configures dnsdist dynamic block rules written to dynblock.lua.
type DynBlockConfig struct {
	Enabled      bool
	QPS          int
	Burst        int
	BlockSeconds int
	NXDomainQPS  int
	AnyQPS       int
	Whitelist    []string
}

// WriteDynBlockRules writes dynblock.lua into blocklistDir so dnsdist maintenance()
// applies updated RRL / ANY / NXDOMAIN protections live without restarting dnsdist.
func WriteDynBlockRules(blocklistDir string, cfg DynBlockConfig) error {
	if err := os.MkdirAll(blocklistDir, 0o755); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("-- AUTO-GENERATED by PowerSVX - dynamic RRL / abuse rules\n")
	b.WriteString("dbrg = dynBlockRulesGroup()\n")
	if cfg.Enabled {
		qps := cfg.QPS
		if qps <= 0 {
			qps = 200
		}
		dur := cfg.BlockSeconds
		if dur <= 0 {
			dur = 60
		}
		nxQPS := cfg.NXDomainQPS
		if nxQPS <= 0 {
			nxQPS = qps / 2
			if nxQPS < 20 {
				nxQPS = 20
			}
		}
		anyQPS := cfg.AnyQPS
		if anyQPS <= 0 {
			anyQPS = 20
		}
		fmt.Fprintf(&b, "dbrg:setQueryRate(%d, 10, \"Exceeded query rate limit\", %d, DNSAction.Drop)\n", qps, dur)
		fmt.Fprintf(&b, "dbrg:setRCodeRate(DNSRCode.NXDOMAIN, %d, 10, \"Exceeded NXDOMAIN rate limit\", %d, DNSAction.Refused)\n", nxQPS, dur)
		fmt.Fprintf(&b, "dbrg:setQTypeRate(DNSQType.ANY, %d, 10, \"Exceeded ANY query rate limit\", %d, DNSAction.Drop)\n", anyQPS, dur)
		b.WriteString("dbrg:excludeRange({\"127.0.0.0/8\", \"::1/128\"")
		for _, w := range cfg.Whitelist {
			w = strings.TrimSpace(w)
			if _, err := netip.ParsePrefix(w); err == nil {
				fmt.Fprintf(&b, ", %q", w)
			} else if addr, err := netip.ParseAddr(w); err == nil {
				fmt.Fprintf(&b, ", %q", netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()).String())
			}
		}
		b.WriteString("})\n")
	}
	p := filepath.Join(blocklistDir, "dynblock.lua")
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func sanitizeDNSLabel(s string) string {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.' || r == '_' || r == ':' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
