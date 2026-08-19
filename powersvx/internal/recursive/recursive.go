// Package recursive is an optional built-in iterative resolver. Instead of
// forwarding to a public resolver, it walks the delegation chain starting from
// the root hints (root -> TLD -> authoritative), following referrals and glue,
// resolving glueless nameservers, and chasing CNAMEs. It is an alternative to
// the upstream forwarding pool.
//
// This is a pragmatic implementation (depth/iteration bounded, best-effort
// CNAME merge). It intentionally does not do DNSSEC validation (performance
// mode) — that is a separate, heavier path.
package recursive

import (
	"errors"
	"math/rand"
	"strings"
	"time"

	"github.com/miekg/dns"

	"powersvx/internal/metrics"
)

// Root hints (IANA, current as of 2024+).
var rootV4 = []string{
	"198.41.0.4:53",     // a
	"170.247.170.2:53",  // b
	"192.33.4.12:53",    // c
	"199.7.91.13:53",    // d
	"192.203.230.10:53", // e
	"192.5.5.241:53",    // f
	"192.112.36.4:53",   // g
	"198.97.190.53:53",  // h
	"192.36.148.17:53",  // i
	"192.58.128.30:53",  // j
	"193.0.14.129:53",   // k
	"199.7.83.42:53",    // l
	"202.12.27.33:53",   // m
}

var rootV6 = []string{
	"[2001:503:ba3e::2:30]:53", // a
	"[2801:1b8:10::b]:53",      // b
	"[2001:500:2::c]:53",       // c
	"[2001:500:2d::d]:53",      // d
	"[2001:500:a8::e]:53",      // e
	"[2001:500:2f::f]:53",      // f
	"[2001:500:12::d0d]:53",    // g
	"[2001:500:1::53]:53",      // h
	"[2001:7fe::53]:53",        // i
	"[2001:503:c27::2:30]:53",  // j
	"[2001:7fd::1]:53",         // k
	"[2001:500:9f::42]:53",     // l
	"[2001:dc3::35]:53",        // m
}

type Recursive struct {
	udp, tcp *dns.Client
	roots    []string
	useV6    bool
	maxDepth int
	maxIter  int
	m        *metrics.Metrics
}

func New(timeout time.Duration, useV6 bool, m *metrics.Metrics) *Recursive {
	roots := append([]string(nil), rootV4...)
	if useV6 {
		roots = append(roots, rootV6...)
	}
	return &Recursive{
		udp:      &dns.Client{Net: "udp", Timeout: timeout},
		tcp:      &dns.Client{Net: "tcp", Timeout: timeout},
		roots:    roots,
		useV6:    useV6,
		maxDepth: 16,
		maxIter:  24,
		m:        m,
	}
}

func (r *Recursive) Resolve(q dns.Question) (*dns.Msg, error) {
	return r.resolve(dns.Fqdn(q.Name), q.Qtype, q.Qclass, 0)
}

func (r *Recursive) resolve(name string, qtype, qclass uint16, depth int) (*dns.Msg, error) {
	if depth > r.maxDepth {
		return nil, errors.New("recursive: max depth exceeded")
	}
	servers := append([]string(nil), r.roots...)

	for iter := 0; iter < r.maxIter; iter++ {
		resp, err := r.query(name, qtype, qclass, servers)
		if err != nil {
			return nil, err
		}

		if len(resp.Answer) > 0 {
			if answerHasType(resp.Answer, qtype) {
				return resp, nil
			}
			if target := cnameTarget(resp.Answer); target != "" && target != name {
				sub, err := r.resolve(target, qtype, qclass, depth+1)
				if err != nil {
					return resp, nil // return partial (CNAME only)
				}
				merged := resp.Copy()
				merged.Answer = append(cnameRecords(resp.Answer), sub.Answer...)
				merged.Ns = sub.Ns
				merged.Extra = nil
				merged.Rcode = sub.Rcode
				return merged, nil
			}
			return resp, nil
		}

		if resp.Rcode == dns.RcodeNameError {
			return resp, nil // authoritative NXDOMAIN
		}

		nsNames := nsList(resp.Ns)
		if len(nsNames) == 0 {
			return resp, nil // NODATA / authoritative empty
		}

		glue := glueList(resp.Extra, nsNames, r.useV6)
		if len(glue) == 0 {
			glue = r.resolveNSAddrs(nsNames, depth+1)
			if len(glue) == 0 {
				return nil, errors.New("recursive: no reachable nameservers")
			}
		}
		servers = glue
	}
	return nil, errors.New("recursive: max iterations exceeded")
}

func (r *Recursive) query(name string, qtype, qclass uint16, servers []string) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.Question[0].Qclass = qclass
	m.RecursionDesired = false
	m.SetEdns0(4096, false)

	var lastErr error = errors.New("recursive: no servers")
	for _, idx := range rand.Perm(len(servers)) {
		srv := servers[idx]
		resp, _, err := r.udp.Exchange(m, srv)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.Truncated {
			if r.m != nil {
				r.m.IncTCP()
			}
			resp2, _, err2 := r.tcp.Exchange(m, srv)
			if err2 != nil {
				lastErr = err2
				continue
			}
			resp = resp2
		}
		return resp, nil
	}
	return nil, lastErr
}

func (r *Recursive) resolveNSAddrs(nsNames []string, depth int) []string {
	var out []string
	limit := 4
	for i, ns := range nsNames {
		if i >= limit {
			break
		}
		if resp, err := r.resolve(ns, dns.TypeA, dns.ClassINET, depth); err == nil {
			for _, rr := range resp.Answer {
				if a, ok := rr.(*dns.A); ok {
					out = append(out, a.A.String()+":53")
				}
			}
		}
		if r.useV6 {
			if resp, err := r.resolve(ns, dns.TypeAAAA, dns.ClassINET, depth); err == nil {
				for _, rr := range resp.Answer {
					if a, ok := rr.(*dns.AAAA); ok {
						out = append(out, "["+a.AAAA.String()+"]:53")
					}
				}
			}
		}
	}
	return out
}

// --- helpers ---

func answerHasType(rrs []dns.RR, qtype uint16) bool {
	for _, rr := range rrs {
		if rr.Header().Rrtype == qtype {
			return true
		}
	}
	return false
}

func cnameTarget(rrs []dns.RR) string {
	t := ""
	for _, rr := range rrs {
		if c, ok := rr.(*dns.CNAME); ok {
			t = c.Target
		}
	}
	return t
}

func cnameRecords(rrs []dns.RR) []dns.RR {
	out := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		if _, ok := rr.(*dns.CNAME); ok {
			out = append(out, rr)
		}
	}
	return out
}

func nsList(ns []dns.RR) []string {
	var out []string
	for _, rr := range ns {
		if n, ok := rr.(*dns.NS); ok {
			out = append(out, strings.ToLower(n.Ns))
		}
	}
	return out
}

func glueList(extra []dns.RR, nsNames []string, useV6 bool) []string {
	set := make(map[string]struct{}, len(nsNames))
	for _, n := range nsNames {
		set[n] = struct{}{}
	}
	var out []string
	for _, rr := range extra {
		switch a := rr.(type) {
		case *dns.A:
			if _, ok := set[strings.ToLower(a.Hdr.Name)]; ok {
				out = append(out, a.A.String()+":53")
			}
		case *dns.AAAA:
			if !useV6 {
				continue
			}
			if _, ok := set[strings.ToLower(a.Hdr.Name)]; ok {
				out = append(out, "["+a.AAAA.String()+"]:53")
			}
		}
	}
	return out
}
