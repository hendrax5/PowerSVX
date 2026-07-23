// Package aclban rate-limits ACL-denied clients then silent-drops / nft-bans them.
// Only IPs that already failed allow_query are tracked — never customer ACL members.
package aclban

import (
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type Config struct {
	// Threshold ACL-denies per IP within Window before autoban.
	Threshold int
	Window    time.Duration
	// TTL how long silent-drop / nft ban lasts.
	TTL time.Duration
	// NFT enables kernel drop via nftables set (best-effort).
	NFT bool
	// NFTSet name inside table inet powersvx.
	NFTSet string
}

type Guard struct {
	cfg Config
	log *slog.Logger

	mu     sync.Mutex
	hits   map[string]*counter
	banned map[string]time.Time

	nftOnce sync.Once
	nftOK   bool
}

type counter struct {
	n       int
	window0 time.Time
}

func New(cfg Config, log *slog.Logger) *Guard {
	if log == nil {
		log = slog.Default()
	}
	if cfg.Threshold <= 0 {
		cfg.Threshold = 64
	}
	if cfg.Window <= 0 {
		cfg.Window = 30 * time.Second
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 5 * time.Minute
	}
	if cfg.NFTSet == "" {
		cfg.NFTSet = "acl_deny"
	}
	g := &Guard{
		cfg:    cfg,
		log:    log,
		hits:   make(map[string]*counter),
		banned: make(map[string]time.Time),
	}
	if cfg.NFT {
		g.nftOnce.Do(g.initNFT)
	}
	return g
}

// Observe records an ACL deny. silent=true means do not send REFUSED.
// newBan=true on the deny that crosses the threshold.
func (g *Guard) Observe(ipStr string) (silent, newBan bool) {
	if g == nil || ipStr == "" {
		return false, false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false, false
	}

	now := time.Now()
	var justBanned bool
	var ttl time.Duration
	var useNFT bool

	g.mu.Lock()
	if until, ok := g.banned[ipStr]; ok {
		if now.Before(until) {
			g.mu.Unlock()
			return true, false
		}
		delete(g.banned, ipStr)
	}

	c := g.hits[ipStr]
	if c == nil || now.Sub(c.window0) > g.cfg.Window {
		c = &counter{window0: now}
		g.hits[ipStr] = c
	}
	c.n++
	if c.n < g.cfg.Threshold {
		g.mu.Unlock()
		return false, false
	}

	ttl = g.cfg.TTL
	g.banned[ipStr] = now.Add(ttl)
	delete(g.hits, ipStr)
	justBanned = true
	useNFT = g.cfg.NFT && g.nftOK
	g.mu.Unlock()

	if justBanned {
		if useNFT {
			g.addNFT(ip, ttl)
		}
		g.log.Info("acl autoban", "client", ipStr, "ttl_sec", int(ttl.Seconds()), "nft", useNFT)
	}
	return true, true
}

// Reset clears in-memory bans (e.g. after allow_query changes) and flushes nft set.
func (g *Guard) Reset() {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.hits = make(map[string]*counter)
	g.banned = make(map[string]time.Time)
	g.mu.Unlock()
	if g.cfg.NFT {
		g.flushNFT()
	}
}

func (g *Guard) initNFT() {
	if _, err := exec.LookPath("nft"); err != nil {
		g.log.Warn("acl autoban nft disabled: nft binary missing")
		return
	}
	cmds := [][]string{
		{"add", "table", "inet", "powersvx"},
		{"add", "set", "inet", "powersvx", g.cfg.NFTSet, "{", "type", "ipv4_addr;", "flags", "timeout;", "}"},
		{"add", "set", "inet", "powersvx", g.cfg.NFTSet + "6", "{", "type", "ipv6_addr;", "flags", "timeout;", "}"},
		{"add", "chain", "inet", "powersvx", "input", "{", "type", "filter", "hook", "input", "priority", "-10;", "policy", "accept;", "}"},
	}
	for _, args := range cmds {
		_ = exec.Command("nft", args...).Run()
	}
	_ = exec.Command("nft", "add", "rule", "inet", "powersvx", "input", "udp", "dport", "53", "ip", "saddr", "@"+g.cfg.NFTSet, "drop").Run()
	_ = exec.Command("nft", "add", "rule", "inet", "powersvx", "input", "tcp", "dport", "53", "ip", "saddr", "@"+g.cfg.NFTSet, "drop").Run()
	_ = exec.Command("nft", "add", "rule", "inet", "powersvx", "input", "udp", "dport", "53", "ip6", "saddr", "@"+g.cfg.NFTSet+"6", "drop").Run()
	_ = exec.Command("nft", "add", "rule", "inet", "powersvx", "input", "tcp", "dport", "53", "ip6", "saddr", "@"+g.cfg.NFTSet+"6", "drop").Run()
	g.nftOK = true
	g.log.Info("acl autoban nft ready", "table", "inet powersvx", "set", g.cfg.NFTSet)
}

func (g *Guard) addNFT(ip net.IP, ttl time.Duration) {
	sec := int(ttl.Seconds())
	if sec < 1 {
		sec = 1
	}
	set := g.cfg.NFTSet
	if ip.To4() == nil {
		set = g.cfg.NFTSet + "6"
	}
	elem := fmt.Sprintf("%s timeout %ds", ip.String(), sec)
	cmd := exec.Command("nft", "add", "element", "inet", "powersvx", set, "{", elem, "}")
	if out, err := cmd.CombinedOutput(); err != nil {
		_ = exec.Command("nft", "delete", "element", "inet", "powersvx", set, "{", ip.String(), "}").Run()
		cmd = exec.Command("nft", "add", "element", "inet", "powersvx", set, "{", elem, "}")
		if out2, err2 := cmd.CombinedOutput(); err2 != nil {
			g.log.Warn("acl autoban nft add failed", "ip", ip.String(), "err", err2, "out", strings.TrimSpace(string(out2)))
			_ = out
		}
	}
}

func (g *Guard) flushNFT() {
	if !g.nftOK {
		return
	}
	_ = exec.Command("nft", "flush", "set", "inet", "powersvx", g.cfg.NFTSet).Run()
	_ = exec.Command("nft", "flush", "set", "inet", "powersvx", g.cfg.NFTSet+"6").Run()
}
