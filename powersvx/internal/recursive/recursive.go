// Package recursive is an optional built-in iterative resolver. Instead of
// forwarding to a public resolver, it walks the delegation chain starting from
// the root hints (or a cached delegation), following referrals and glue,
// resolving glueless nameservers, and chasing CNAMEs.
//
// A delegation cache remembers NS/glue per zone so cold misses don't re-walk
// from the root every time. When DNSSEC validation is enabled it sets the DO
// bit and validates positive answers against the root trust anchor.
package recursive

import (
	"errors"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"powersvx/internal/dnssec"
	"powersvx/internal/metrics"
)

// Root hints (IANA, current as of 2024+).
var rootV4 = []string{
	"198.41.0.4:53", "170.247.170.2:53", "192.33.4.12:53", "199.7.91.13:53",
	"192.203.230.10:53", "192.5.5.241:53", "192.112.36.4:53", "198.97.190.53:53",
	"192.36.148.17:53", "192.58.128.30:53", "193.0.14.129:53", "199.7.83.42:53",
	"202.12.27.33:53",
}

var rootV6 = []string{
	"[2001:503:ba3e::2:30]:53", "[2801:1b8:10::b]:53", "[2001:500:2::c]:53",
	"[2001:500:2d::d]:53", "[2001:500:a8::e]:53", "[2001:500:2f::f]:53",
	"[2001:500:12::d0d]:53", "[2001:500:1::53]:53", "[2001:7fe::53]:53",
	"[2001:503:c27::2:30]:53", "[2001:7fd::1]:53", "[2001:500:9f::42]:53",
	"[2001:dc3::35]:53",
}

type Recursive struct {
	udp, tcp  *dns.Client
	roots     []string
	useV6     bool
	do        bool // set DNSSEC OK bit (needed to fetch RRSIGs)
	maxDepth  int
	maxIter   int
	m         *metrics.Metrics
	deleg     *delegCache
	nsec      *nsecCache
	validator *dnssec.Validator
}

func New(timeout time.Duration, useV6 bool, m *metrics.Metrics, validate bool) *Recursive {
	roots := append([]string(nil), rootV4...)
	if useV6 {
		roots = append(roots, rootV6...)
	}
	r := &Recursive{
		udp:      &dns.Client{Net: "udp", Timeout: timeout},
		tcp:      &dns.Client{Net: "tcp", Timeout: timeout},
		roots:    roots,
		useV6:    useV6,
		maxDepth: 16,
		maxIter:  24,
		m:        m,
		deleg:    newDelegCache(),
		nsec:     newNSECCache(),
	}
	if validate {
		r.do = true
		r.validator = dnssec.NewValidator(func(name string, qtype uint16) (*dns.Msg, error) {
			return r.resolve(dns.Fqdn(name), qtype, dns.ClassINET, 0, nil)
		})
	}
	return r
}

func (r *Recursive) Resolve(q dns.Question, ecs *dns.EDNS0_SUBNET) (*dns.Msg, error) {
	name := dns.Fqdn(q.Name)

	// Aggressive use of validated NSEC (RFC 8198): if a cached, still-valid NSEC
	// proves this name can't exist, synthesize the NXDOMAIN locally without any
	// upstream traffic. This absorbs random-subdomain / NX floods.
	if r.validator != nil {
		if e := r.nsec.cover(name); e != nil {
			if r.m != nil {
				r.m.IncAggressiveNSEC()
			}
			synth := new(dns.Msg)
			synth.Question = []dns.Question{q}
			synth.Response = true
			synth.Rcode = dns.RcodeNameError
			synth.AuthenticatedData = true
			synth.Ns = []dns.RR{dns.Copy(e.rr)}
			return synth, nil
		}
	}

	resp, err := r.resolve(name, q.Qtype, q.Qclass, 0, ecs)
	if err != nil {
		return nil, err
	}
	if r.validator != nil {
		st, _ := r.validator.Validate(resp, name, q.Qtype)
		switch st {
		case dnssec.Secure:
			resp.AuthenticatedData = true
			if r.m != nil {
				r.m.IncDNSSECSecure()
			}
			// Cache validated NSEC records for aggressive reuse.
			if resp.Rcode == dns.RcodeNameError || len(resp.Answer) == 0 {
				r.nsec.addFrom(resp.Ns)
			}
		case dnssec.Bogus:
			if r.m != nil {
				r.m.IncDNSSECBogus()
			}
			sf := new(dns.Msg)
			sf.Question = []dns.Question{q}
			sf.Response = true
			sf.Rcode = dns.RcodeServerFailure
			return sf, nil
		default:
			resp.AuthenticatedData = false
		}
	}
	return resp, nil
}

func (r *Recursive) resolve(name string, qtype, qclass uint16, depth int, ecs *dns.EDNS0_SUBNET) (*dns.Msg, error) {
	if depth > r.maxDepth {
		return nil, errors.New("recursive: max depth exceeded")
	}

	// Start from the closest cached delegation instead of the root when possible.
	// DS records live in the PARENT zone, so a DS query must start one label up
	// (otherwise the child's own servers answer NODATA and it looks insecure).
	lookupName := name
	if qtype == dns.TypeDS {
		lookupName = parentLabel(name)
	}
	fromCache := true
	servers := r.deleg.get(lookupName)
	if len(servers) == 0 {
		servers = append([]string(nil), r.roots...)
		fromCache = false
	}

	for iter := 0; iter < r.maxIter; iter++ {
		resp, err := r.query(name, qtype, qclass, servers, ecs)
		if err != nil {
			if fromCache {
				// Stale/broken cached delegation: fall back to roots once.
				servers = append([]string(nil), r.roots...)
				fromCache = false
				continue
			}
			return nil, err
		}

		if len(resp.Answer) > 0 {
			if answerHasType(resp.Answer, qtype) {
				return resp, nil
			}
			if target := cnameTarget(resp.Answer); target != "" && target != name {
				sub, err := r.resolve(target, qtype, qclass, depth+1, ecs)
				if err != nil {
					return resp, nil
				}
				merged := resp.Copy()
				merged.Answer = append(cnameRecords(resp.Answer), sub.Answer...)
				merged.Ns = sub.Ns
				merged.Extra = nil
				merged.Rcode = sub.Rcode
				merged.AuthenticatedData = false
				return merged, nil
			}
			return resp, nil
		}

		if resp.Rcode == dns.RcodeNameError {
			return resp, nil
		}

		nsNames := nsList(resp.Ns)
		if len(nsNames) == 0 {
			return resp, nil // NODATA
		}
		glue := glueList(resp.Extra, nsNames, r.useV6)
		if len(glue) == 0 {
			glue = r.resolveNSAddrs(nsNames, depth+1)
			if len(glue) == 0 {
				return nil, errors.New("recursive: no reachable nameservers")
			}
		}
		if zone := referralZone(resp.Ns); zone != "" {
			r.deleg.put(zone, glue, minNSTTL(resp.Ns))
		}
		servers = glue
		fromCache = false
	}
	return nil, errors.New("recursive: max iterations exceeded")
}

func (r *Recursive) query(name string, qtype, qclass uint16, servers []string, ecs *dns.EDNS0_SUBNET) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.Question[0].Qclass = qclass
	m.RecursionDesired = false
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	opt.SetUDPSize(4096)
	opt.SetDo(r.do)
	if ecs != nil {
		opt.Option = append(opt.Option, ecs)
	}
	m.Extra = append(m.Extra, opt)

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
	const limit = 4
	for i, ns := range nsNames {
		if i >= limit {
			break
		}
		if resp, err := r.resolve(ns, dns.TypeA, dns.ClassINET, depth, nil); err == nil {
			for _, rr := range resp.Answer {
				if a, ok := rr.(*dns.A); ok {
					out = append(out, a.A.String()+":53")
				}
			}
		}
		if r.useV6 {
			if resp, err := r.resolve(ns, dns.TypeAAAA, dns.ClassINET, depth, nil); err == nil {
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

// --- delegation cache ---

type delegEntry struct {
	addrs  []string
	expiry int64
}

type delegCache struct {
	mu sync.RWMutex
	m  map[string]delegEntry
}

func newDelegCache() *delegCache { return &delegCache{m: make(map[string]delegEntry)} }

// parentLabel strips the leftmost label ("a.example.com." -> "example.com.").
func parentLabel(name string) string {
	name = dns.Fqdn(strings.ToLower(name))
	if name == "." {
		return "."
	}
	i := strings.IndexByte(name, '.')
	if i < 0 || i+1 >= len(name) {
		return "."
	}
	return name[i+1:]
}

// get returns cached nameserver addresses for the closest cached ancestor zone.
func (d *delegCache) get(name string) []string {
	name = dns.Fqdn(strings.ToLower(name))
	now := time.Now().Unix()
	d.mu.RLock()
	defer d.mu.RUnlock()
	n := name
	for {
		if e, ok := d.m[n]; ok && e.expiry > now {
			return e.addrs
		}
		i := strings.IndexByte(n, '.')
		if i < 0 || i+1 >= len(n) {
			break
		}
		n = n[i+1:]
	}
	return nil
}

func (d *delegCache) put(zone string, addrs []string, ttl uint32) {
	if len(addrs) == 0 || ttl == 0 {
		return
	}
	zone = dns.Fqdn(strings.ToLower(zone))
	cp := append([]string(nil), addrs...)
	d.mu.Lock()
	if len(d.m) > 100000 { // crude cap to bound memory
		d.m = make(map[string]delegEntry)
	}
	d.m[zone] = delegEntry{addrs: cp, expiry: time.Now().Unix() + int64(ttl)}
	d.mu.Unlock()
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

func referralZone(ns []dns.RR) string {
	for _, rr := range ns {
		if _, ok := rr.(*dns.NS); ok {
			return strings.ToLower(rr.Header().Name)
		}
	}
	return ""
}

func minNSTTL(ns []dns.RR) uint32 {
	var m uint32
	first := true
	for _, rr := range ns {
		if _, ok := rr.(*dns.NS); ok {
			t := rr.Header().Ttl
			if first || t < m {
				m = t
				first = false
			}
		}
	}
	if first {
		return 0
	}
	if m < 60 {
		m = 60
	}
	if m > 21600 {
		m = 21600
	}
	return m
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
