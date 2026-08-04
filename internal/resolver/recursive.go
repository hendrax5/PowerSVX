package resolver

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// IANA root hints (subset of A/AAAA for root NS).
var rootHints = []struct {
	ns  string
	ips []string
}{
	{"a.root-servers.net.", []string{"198.41.0.4", "2001:503:ba3e::2:30"}},
	{"b.root-servers.net.", []string{"170.247.170.2", "2801:1b8:10::b"}},
	{"c.root-servers.net.", []string{"192.33.4.12", "2001:500:2::c"}},
	{"d.root-servers.net.", []string{"199.7.91.13", "2001:500:2d::d"}},
	{"e.root-servers.net.", []string{"192.203.230.10", "2001:500:a8::e"}},
	{"f.root-servers.net.", []string{"192.5.5.241", "2001:500:2f::f"}},
	{"g.root-servers.net.", []string{"192.112.36.4", "2001:500:12::d0d"}},
	{"h.root-servers.net.", []string{"198.97.190.53", "2001:500:1::53"}},
	{"i.root-servers.net.", []string{"192.36.148.17", "2001:7fe::53"}},
	{"j.root-servers.net.", []string{"192.58.128.30", "2001:503:c27::2:30"}},
	{"k.root-servers.net.", []string{"193.0.14.129", "2001:7fd::1"}},
	{"l.root-servers.net.", []string{"199.7.83.42", "2001:500:9f::42"}},
	{"m.root-servers.net.", []string{"202.12.27.33", "2001:dc3::35"}},
}

var (
	rootAddrsOnce sync.Once
	rootAddrs     []string
)

func getRootAddrs() []string {
	rootAddrsOnce.Do(func() {
		for _, h := range rootHints {
			for _, ip := range h.ips {
				if strings.Contains(ip, ":") {
					continue
				}
				rootAddrs = append(rootAddrs, net.JoinHostPort(ip, "53"))
			}
		}
	})
	return rootAddrs
}

func (r *Resolver) roots() []string {
	base := getRootAddrs()
	if r == nil || len(r.extraRoots) == 0 {
		return base
	}
	out := make([]string, 0, len(base)+len(r.extraRoots))
	out = append(out, r.extraRoots...)
	out = append(out, base...)
	return out
}

func loadRootHintsFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if _, _, err := net.SplitHostPort(line); err != nil {
			line = net.JoinHostPort(line, "53")
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

const (
	maxRecursionDepth = 16
	defaultHopTimeout = 300 * time.Millisecond
	maxNSLookups      = 6
	// raceParallel: 1 under multi-k QPS recursive — parallel NS races amplify
	// UDP/goroutines far more than they cut latency when the box is saturated.
	raceParallel = 1
	// Cap concurrent glue-less NS A/AAAA walks (each is a nested recursive tree).
	nsLookupParallel = 2
)

func (r *Resolver) resolveRecursive(ctx context.Context, qname string, qtype uint16) (*dns.Msg, error) {
	return r.iterate(ctx, qname, qtype, r.roots(), 0)
}

func (r *Resolver) iterate(ctx context.Context, qname string, qtype uint16, servers []string, depth int) (*dns.Msg, error) {
	if depth > maxRecursionDepth {
		return nil, fmt.Errorf("recursion depth exceeded for %s", qname)
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("no servers to query for %s", qname)
	}

	req := new(dns.Msg)
	req.SetQuestion(qname, qtype)
	req.RecursionDesired = false
	setEDNS0(req, r.BufSize, r.WantDO)

	var lastErr error
	// Race servers in batches of raceParallel (first success with usable reply wins).
	for i := 0; i < len(servers); {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		end := i + raceParallel
		if end > len(servers) {
			end = len(servers)
		}
		batch := servers[i:end]
		i = end

		resp, err := r.exchangeRace(ctx, req, batch)
		if err != nil {
			lastErr = err
			continue
		}
		if resp == nil {
			lastErr = fmt.Errorf("empty response")
			continue
		}
		if resp.Rcode == dns.RcodeNameError {
			return resp, nil
		}
		if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
			lastErr = fmt.Errorf("rcode %d", resp.Rcode)
			continue
		}
		if hasAnswer(resp, qname, qtype) {
			return resp, nil
		}
		if cname := extractCNAME(resp, qname); cname != "" {
			cnameMsg, err := r.iterate(ctx, cname, qtype, r.roots(), depth+1)
			if err != nil {
				return nil, err
			}
			out := resp.Copy()
			out.Answer = append(out.Answer, cnameMsg.Answer...)
			out.Authoritative = false
			out.RecursionAvailable = true
			return out, nil
		}
		next := collectReferral(resp)
		if len(next) == 0 {
			next = r.resolveNSAddrs(ctx, collectNSNames(resp), depth)
		}
		if len(next) == 0 {
			lastErr = fmt.Errorf("no referral for %s", qname)
			continue
		}
		return r.iterate(ctx, qname, qtype, next, depth+1)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("resolution failed for %s", qname)
	}
	return nil, lastErr
}

func (r *Resolver) resolveNSAddrs(ctx context.Context, nsNames []string, depth int) []string {
	if len(nsNames) == 0 {
		return nil
	}
	if len(nsNames) > maxNSLookups {
		nsNames = nsNames[:maxNSLookups]
	}

	seen := map[string]bool{}
	var next []string
	var needLookup []string
	for _, ns := range nsNames {
		if addrs := r.nsCache.get(ns); len(addrs) > 0 {
			for _, a := range addrs {
				if !seen[a] {
					seen[a] = true
					next = append(next, a)
				}
			}
			continue
		}
		needLookup = append(needLookup, ns)
	}
	if len(needLookup) == 0 {
		return next
	}

	type result struct {
		name  string
		addrs []string
	}
	ch := make(chan result, len(needLookup))
	sem := make(chan struct{}, nsLookupParallel)
	for _, ns := range needLookup {
		ns := ns
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			defer func() {
				if recover() != nil {
					ch <- result{name: ns}
				}
			}()
			nsMsg, err := r.iterate(ctx, ns, dns.TypeA, r.roots(), depth+1)
			if err != nil || nsMsg == nil {
				ch <- result{name: ns}
				return
			}
			var addrs []string
			for _, rr := range nsMsg.Answer {
				if a, ok := rr.(*dns.A); ok {
					addrs = append(addrs, net.JoinHostPort(a.A.String(), "53"))
				}
			}
			if len(addrs) > 0 {
				r.nsCache.put(ns, addrs, 5*time.Minute)
			}
			ch <- result{name: ns, addrs: addrs}
		}()
	}
	for range needLookup {
		select {
		case <-ctx.Done():
			return next
		case res := <-ch:
			for _, a := range res.addrs {
				if !seen[a] {
					seen[a] = true
					next = append(next, a)
				}
			}
		}
	}
	return next
}

func (r *Resolver) hopTimeout(ctx context.Context) time.Duration {
	timeout := defaultHopTimeout
	if r != nil && r.Timeout > 0 && r.Timeout < timeout {
		timeout = r.Timeout
	}
	if dl, ok := ctx.Deadline(); ok {
		remain := time.Until(dl)
		if remain <= 0 {
			return 0
		}
		if remain < timeout {
			return remain
		}
	}
	return timeout
}

func (r *Resolver) exchangeRace(ctx context.Context, req *dns.Msg, servers []string) (*dns.Msg, error) {
	if len(servers) == 1 {
		return r.exchange(ctx, req, servers[0])
	}
	type result struct {
		resp *dns.Msg
		err  error
	}
	ch := make(chan result, len(servers))
	ctxRace, cancel := context.WithCancel(ctx)
	defer cancel()
	for _, srv := range servers {
		srv := srv
		go func() {
			resp, err := r.exchange(ctxRace, req, srv)
			ch <- result{resp, err}
		}()
	}
	var lastErr error
	for range servers {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case res := <-ch:
			if res.err != nil || res.resp == nil {
				if res.err != nil {
					lastErr = res.err
				}
				continue
			}
			if res.resp.Rcode == dns.RcodeSuccess || res.resp.Rcode == dns.RcodeNameError {
				cancel()
				return res.resp, nil
			}
			lastErr = fmt.Errorf("rcode %d", res.resp.Rcode)
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("all servers failed")
	}
	return nil, lastErr
}

func (r *Resolver) exchange(ctx context.Context, req *dns.Msg, addr string) (*dns.Msg, error) {
	hop := r.hopTimeout(ctx)
	if hop <= 0 {
		return nil, ctx.Err()
	}
	ectx, cancel := context.WithTimeout(ctx, hop)
	defer cancel()

	cli := &dns.Client{Net: "udp", Timeout: hop, UDPSize: r.BufSize}
	resp, _, err := cli.ExchangeContext(ectx, req.Copy(), addr)
	if err == nil && resp != nil && resp.Truncated {
		tcli := &dns.Client{Net: "tcp", Timeout: hop, UDPSize: r.BufSize}
		resp2, _, err2 := tcli.ExchangeContext(ectx, req.Copy(), addr)
		if err2 == nil && resp2 != nil {
			return resp2, nil
		}
	}
	return resp, err
}

func hasAnswer(msg *dns.Msg, qname string, qtype uint16) bool {
	qname = dns.CanonicalName(qname)
	for _, rr := range msg.Answer {
		h := rr.Header()
		if dns.CanonicalName(h.Name) != qname {
			continue
		}
		if h.Rrtype == qtype {
			return true
		}
	}
	return false
}

func extractCNAME(msg *dns.Msg, qname string) string {
	qname = dns.CanonicalName(qname)
	for _, rr := range msg.Answer {
		if c, ok := rr.(*dns.CNAME); ok && dns.CanonicalName(c.Hdr.Name) == qname {
			return dns.CanonicalName(c.Target)
		}
	}
	return ""
}

func collectReferral(msg *dns.Msg) []string {
	glue := map[string][]string{}
	for _, rr := range msg.Extra {
		switch a := rr.(type) {
		case *dns.A:
			name := dns.CanonicalName(a.Hdr.Name)
			glue[name] = append(glue[name], net.JoinHostPort(a.A.String(), "53"))
		}
	}
	var out []string
	seen := map[string]bool{}
	for _, rr := range msg.Ns {
		ns, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		name := dns.CanonicalName(ns.Ns)
		for _, addr := range glue[name] {
			if !seen[addr] {
				seen[addr] = true
				out = append(out, addr)
			}
		}
	}
	return out
}

func collectNSNames(msg *dns.Msg) []string {
	var names []string
	seen := map[string]bool{}
	for _, rr := range msg.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			n := dns.CanonicalName(ns.Ns)
			if !seen[n] {
				seen[n] = true
				names = append(names, n)
			}
		}
	}
	return names
}
