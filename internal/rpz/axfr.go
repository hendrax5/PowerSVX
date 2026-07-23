package rpz

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/config"
)

const (
	defaultAXFRTimeout = 30 * time.Minute
	xferDialTimeout    = 10 * time.Second
	xferReadTimeout    = 60 * time.Second
)

// TransferResult is the outcome of an AXFR or IXFR pull.
type TransferResult struct {
	Serial      uint32
	Names       []string // set when FullReplace (complete name set, zone-relative)
	Added       []string
	Removed     []string
	FullReplace bool
}

// relativeOwner strips the RPZ zone apex so Lookup(qname) matches client queries.
// evil.com.trustpositifkominfo. → evil.com.
func relativeOwner(owner, zone string) (string, bool) {
	owner = config.NormalizeName(owner)
	zone = config.NormalizeName(zone)
	if owner == "" || zone == "" || zone == "." {
		return "", false
	}
	if owner == zone {
		return "", false
	}
	if !strings.HasSuffix(owner, zone) {
		return "", false
	}
	rel := strings.TrimSuffix(owner, zone)
	if rel == "" {
		return "", false
	}
	return config.NormalizeName(rel), true
}

func collectOwner(owner, zone string, rr dns.RR, into map[string]struct{}) {
	switch rr.(type) {
	case *dns.A, *dns.AAAA, *dns.CNAME, *dns.NS, *dns.TXT:
	default:
		return
	}
	rel, ok := relativeOwner(owner, zone)
	if !ok {
		return
	}
	into[rel] = struct{}{}
}

func masterAddr(master string) string {
	addr := master
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(master, "53")
	}
	return addr
}

// QuerySOASerial asks the first reachable master for the zone SOA serial.
func QuerySOASerial(ctx context.Context, zone string, masters []string) (uint32, string, error) {
	zone = config.NormalizeName(zone)
	var lastErr error
	for _, master := range masters {
		addr := masterAddr(master)
		m := new(dns.Msg)
		m.SetQuestion(zone, dns.TypeSOA)
		c := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
		type result struct {
			msg *dns.Msg
			err error
		}
		ch := make(chan result, 1)
		go func() {
			r, _, err := c.Exchange(m, addr)
			ch <- result{r, err}
		}()
		var r *dns.Msg
		select {
		case <-ctx.Done():
			return 0, "", ctx.Err()
		case res := <-ch:
			if res.err != nil {
				lastErr = res.err
				continue
			}
			r = res.msg
		}
		if r == nil || r.Rcode != dns.RcodeSuccess {
			lastErr = fmt.Errorf("soa rcode from %s", addr)
			continue
		}
		for _, rr := range r.Answer {
			if soa, ok := rr.(*dns.SOA); ok {
				return soa.Serial, addr, nil
			}
		}
		lastErr = fmt.Errorf("no SOA in answer from %s", addr)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("all masters failed SOA")
	}
	return 0, "", lastErr
}

// streamAXFR pulls a zone from masters and inserts zone-relative owner names into the trie.
func streamAXFR(zone string, masters []string, hit Hit, timeout time.Duration, t *trie) (names []string, serial uint32, err error) {
	zone = config.NormalizeName(zone)
	if zone == "" || zone == "." {
		return nil, 0, fmt.Errorf("axfr zone required")
	}
	if len(masters) == 0 {
		return nil, 0, fmt.Errorf("axfr masters required")
	}
	if timeout <= 0 {
		timeout = defaultAXFRTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	res, err := PullZone(ctx, zone, masters, 0)
	if err != nil {
		return nil, 0, err
	}
	if hit.Action == "" {
		hit.Action = ActionNXDOMAIN
	}
	hit.Target = strings.TrimSpace(hit.Target)
	for _, n := range res.Names {
		t.insertHit(n, hit)
	}
	return res.Names, res.Serial, nil
}

// PullZone transfers the zone. serial==0 forces AXFR; otherwise tries IXFR first and
// falls back to AXFR on failure or when the master returns a full zone.
func PullZone(ctx context.Context, zone string, masters []string, serial uint32) (TransferResult, error) {
	zone = config.NormalizeName(zone)
	var lastErr error
	if serial > 0 {
		for _, master := range masters {
			res, err := ixfrPull(ctx, zone, master, serial)
			if err != nil {
				lastErr = err
				continue
			}
			return res, nil
		}
	}
	for _, master := range masters {
		res, err := axfrPull(ctx, zone, master)
		if err != nil {
			lastErr = err
			continue
		}
		return res, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("all masters failed")
	}
	return TransferResult{}, lastErr
}

// PullAXFRNames is kept for tests: full AXFR returning zone-relative names.
func PullAXFRNames(ctx context.Context, zone string, masters []string) ([]string, uint32, error) {
	res, err := PullZone(ctx, zone, masters, 0)
	if err != nil {
		return nil, 0, err
	}
	return res.Names, res.Serial, nil
}

func axfrPull(ctx context.Context, zone, master string) (TransferResult, error) {
	addr := masterAddr(master)
	m := new(dns.Msg)
	m.SetAxfr(zone)
	tr := &dns.Transfer{DialTimeout: xferDialTimeout, ReadTimeout: xferReadTimeout}
	env, err := tr.In(m, addr)
	if err != nil {
		return TransferResult{}, err
	}
	seen := map[string]struct{}{}
	var serial uint32
	seenSOA := 0
	for e := range env {
		if e.Error != nil {
			return TransferResult{}, e.Error
		}
		select {
		case <-ctx.Done():
			return TransferResult{}, ctx.Err()
		default:
		}
		for _, rr := range e.RR {
			if soa, ok := rr.(*dns.SOA); ok {
				seenSOA++
				serial = soa.Serial
				continue
			}
			collectOwner(rr.Header().Name, zone, rr, seen)
		}
	}
	if seenSOA < 2 {
		return TransferResult{}, fmt.Errorf("incomplete AXFR from %s", addr)
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	return TransferResult{Serial: serial, Names: names, FullReplace: true}, nil
}

func ixfrPull(ctx context.Context, zone, master string, serial uint32) (TransferResult, error) {
	addr := masterAddr(master)
	m := new(dns.Msg)
	m.SetIxfr(zone, serial, "ns.", "hostmaster.")
	tr := &dns.Transfer{DialTimeout: xferDialTimeout, ReadTimeout: xferReadTimeout}
	env, err := tr.In(m, addr)
	if err != nil {
		return TransferResult{}, err
	}

	var rrs []dns.RR
	for e := range env {
		if e.Error != nil {
			return TransferResult{}, e.Error
		}
		select {
		case <-ctx.Done():
			return TransferResult{}, ctx.Err()
		default:
		}
		rrs = append(rrs, e.RR...)
	}
	return parseIXFR(zone, serial, rrs)
}

// parseIXFR interprets an IXFR (or AXFR-style) RR stream per RFC 1995.
func parseIXFR(zone string, clientSerial uint32, rrs []dns.RR) (TransferResult, error) {
	if len(rrs) == 0 {
		return TransferResult{}, fmt.Errorf("empty IXFR")
	}
	first, ok := rrs[0].(*dns.SOA)
	if !ok {
		return TransferResult{}, fmt.Errorf("IXFR missing leading SOA")
	}
	newSerial := first.Serial
	if newSerial == clientSerial {
		return TransferResult{Serial: newSerial, FullReplace: false}, nil
	}

	// AXFR-style: after first SOA, non-SOA RRs until final SOA.
	if len(rrs) > 1 {
		if _, isSOA := rrs[1].(*dns.SOA); !isSOA {
			seen := map[string]struct{}{}
			soaCount := 0
			var serial uint32
			for _, rr := range rrs {
				if soa, ok := rr.(*dns.SOA); ok {
					soaCount++
					serial = soa.Serial
					continue
				}
				collectOwner(rr.Header().Name, zone, rr, seen)
			}
			if soaCount < 2 {
				return TransferResult{}, fmt.Errorf("incomplete AXFR-style IXFR")
			}
			names := make([]string, 0, len(seen))
			for n := range seen {
				names = append(names, n)
			}
			return TransferResult{Serial: serial, Names: names, FullReplace: true}, nil
		}
	}

	removed := map[string]struct{}{}
	added := map[string]struct{}{}
	// state: 0=expect diff-old SOA or final; 1=deletes; 2=adds
	state := 0
	for i := 1; i < len(rrs); i++ {
		rr := rrs[i]
		if soa, ok := rr.(*dns.SOA); ok {
			switch state {
			case 0:
				// start of delete section (older serial)
				state = 1
			case 1:
				// switch to adds (newer serial for this chunk)
				_ = soa
				state = 2
			case 2:
				if soa.Serial == newSerial {
					// either another delete section or final SOA
					// peek: if this is last RR, done
					if i == len(rrs)-1 {
						state = 0
					} else {
						state = 1
					}
				} else {
					state = 1
				}
			}
			continue
		}
		switch state {
		case 1:
			tmp := map[string]struct{}{}
			collectOwner(rr.Header().Name, zone, rr, tmp)
			for n := range tmp {
				removed[n] = struct{}{}
				delete(added, n)
			}
		case 2:
			tmp := map[string]struct{}{}
			collectOwner(rr.Header().Name, zone, rr, tmp)
			for n := range tmp {
				added[n] = struct{}{}
				delete(removed, n)
			}
		}
	}

	outAdd := make([]string, 0, len(added))
	for n := range added {
		outAdd = append(outAdd, n)
	}
	outRem := make([]string, 0, len(removed))
	for n := range removed {
		outRem = append(outRem, n)
	}
	return TransferResult{
		Serial:      newSerial,
		Added:       outAdd,
		Removed:     outRem,
		FullReplace: false,
	}, nil
}
