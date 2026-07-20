package resolver

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

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
					continue // prefer IPv4 for Phase 1 simplicity
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

// loadRootHintsFile reads lines of "ip" or "host:port" (comments with #).
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

const maxRecursionDepth = 16

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
	for _, srv := range servers {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		resp, err := r.exchange(ctx, req, srv)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.Rcode == dns.RcodeNameError {
			return resp, nil
		}
		if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
			lastErr = fmt.Errorf("rcode %d from %s", resp.Rcode, srv)
			continue
		}

		// Final answer?
		if hasAnswer(resp, qname, qtype) {
			return resp, nil
		}

		// CNAME chase
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

		// Referral: collect NS + glue
		next := collectReferral(resp)
		if len(next) == 0 {
			// Try to resolve NS names if no glue
			nsNames := collectNSNames(resp)
			for _, ns := range nsNames {
				nsMsg, err := r.iterate(ctx, ns, dns.TypeA, r.roots(), depth+1)
				if err != nil {
					continue
				}
				for _, rr := range nsMsg.Answer {
					if a, ok := rr.(*dns.A); ok {
						next = append(next, net.JoinHostPort(a.A.String(), "53"))
					}
				}
			}
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

func (r *Resolver) exchange(ctx context.Context, req *dns.Msg, addr string) (*dns.Msg, error) {
	type result struct {
		resp *dns.Msg
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		resp, _, err := r.client.Exchange(req.Copy(), addr)
		ch <- result{resp, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		return res.resp, res.err
	}
}

func hasAnswer(msg *dns.Msg, qname string, qtype uint16) bool {
	qname = dns.CanonicalName(qname)
	for _, rr := range msg.Answer {
		h := rr.Header()
		if dns.CanonicalName(h.Name) != qname {
			continue
		}
		if h.Rrtype == qtype || h.Rrtype == dns.TypeCNAME {
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
