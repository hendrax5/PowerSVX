package rpz

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/tsig"
)

const (
	defaultAXFRTimeout = 30 * time.Minute
	xferDialTimeout    = 10 * time.Second
	xferReadTimeout    = 60 * time.Second
)

// SerialGreater compares two 32-bit SOA serials using RFC 1982 serial number arithmetic.
func SerialGreater(a, b uint32) bool {
	return tsig.SerialGreater(a, b)
}

// TSIGAuth holds optional RFC 2845 TSIG credentials for outbound SOA/IXFR/AXFR queries.
type TSIGAuth = tsig.Auth

func applyTSIG(m *dns.Msg, auth TSIGAuth) map[string]string {
	return tsig.Apply(m, auth)
}

// TransferResult is the outcome of an AXFR or IXFR pull.
type TransferResult struct {
	Serial      uint32
	Master      string   // actual master address that answered the transfer
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

// QuerySOASerial asks masters (in order) for the zone SOA serial.
// Tries UDP then TCP per master; returns the first successful serial.
func QuerySOASerial(ctx context.Context, zone string, masters []string) (uint32, string, error) {
	return QuerySOASerialWithTSIG(ctx, zone, masters, TSIGAuth{})
}

// QuerySOASerialWithTSIG asks masters for the zone SOA serial with optional TSIG authentication.
func QuerySOASerialWithTSIG(ctx context.Context, zone string, masters []string, auth TSIGAuth) (uint32, string, error) {
	zone = config.NormalizeName(zone)
	var errs []string
	for _, master := range masters {
		addr := masterAddr(master)
		for _, netw := range []string{"udp", "tcp"} {
			select {
			case <-ctx.Done():
				return 0, "", ctx.Err()
			default:
			}
			m := new(dns.Msg)
			m.SetQuestion(zone, dns.TypeSOA)
			tsigSecret := applyTSIG(m, auth)
			c := &dns.Client{Net: netw, Timeout: 5 * time.Second, TsigSecret: tsigSecret}
			r, _, err := c.Exchange(m, addr)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s/%s: %v", addr, netw, err))
				continue
			}
			if r == nil {
				errs = append(errs, fmt.Sprintf("%s/%s: empty reply", addr, netw))
				continue
			}
			if r.Rcode != dns.RcodeSuccess {
				errs = append(errs, fmt.Sprintf("%s/%s: %s", addr, netw, dns.RcodeToString[r.Rcode]))
				continue
			}
			for _, rr := range r.Answer {
				if soa, ok := rr.(*dns.SOA); ok {
					return soa.Serial, addr, nil
				}
			}
			errs = append(errs, fmt.Sprintf("%s/%s: no SOA in answer", addr, netw))
		}
	}
	if len(errs) == 0 {
		return 0, "", fmt.Errorf("all masters failed SOA for zone %s", zone)
	}
	hint := ""
	if strings.Contains(zone, "trustkominfo") && !strings.Contains(zone, "trustpositifkominfo") {
		hint = " (Komdigi zone is usually trustpositifkominfo — check spelling)"
	}
	return 0, "", fmt.Errorf("all masters failed SOA for zone %s%s: %s", zone, hint, strings.Join(errs, "; "))
}

// streamAXFR pulls a zone from masters and inserts zone-relative owner names into the trie.
func streamAXFR(zone string, masters []string, hit Hit, timeout time.Duration, t *trie) (names []string, serial uint32, err error) {
	return streamAXFRWithTSIG(zone, masters, hit, timeout, t, TSIGAuth{})
}

func streamAXFRWithTSIG(zone string, masters []string, hit Hit, timeout time.Duration, t *trie, auth TSIGAuth) (names []string, serial uint32, err error) {
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

	res, err := PullZoneWithTSIG(ctx, zone, masters, 0, auth)
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
	return PullZoneWithTSIG(ctx, zone, masters, serial, TSIGAuth{})
}

// PullZoneWithTSIG transfers the zone with optional TSIG authentication.
func PullZoneWithTSIG(ctx context.Context, zone string, masters []string, serial uint32, auth TSIGAuth) (TransferResult, error) {
	zone = config.NormalizeName(zone)
	var lastErr error
	if serial > 0 {
		for _, master := range masters {
			res, err := ixfrPull(ctx, zone, master, serial, auth)
			if err != nil {
				lastErr = err
				continue
			}
			return res, nil
		}
	}
	for _, master := range masters {
		res, err := axfrPull(ctx, zone, master, auth)
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

func axfrPull(ctx context.Context, zone, master string, auth TSIGAuth) (TransferResult, error) {
	addr := masterAddr(master)
	m := new(dns.Msg)
	m.SetAxfr(zone)
	tsigSecret := applyTSIG(m, auth)
	tr := &dns.Transfer{DialTimeout: xferDialTimeout, ReadTimeout: xferReadTimeout, TsigSecret: tsigSecret}
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
	return TransferResult{Serial: serial, Master: addr, Names: names, FullReplace: true}, nil
}

// StreamAXFRNames streams zone-relative owner names to emit without buffering all entries in a giant map.
func StreamAXFRNames(ctx context.Context, zone string, masters []string, auth TSIGAuth, emit func(rel string) error) (serial uint32, masterUsed string, count int, err error) {
	zone = config.NormalizeName(zone)
	if zone == "" || zone == "." {
		return 0, "", 0, fmt.Errorf("axfr zone required")
	}
	if len(masters) == 0 {
		return 0, "", 0, fmt.Errorf("axfr masters required")
	}
	var lastErr error
	for _, master := range masters {
		addr := masterAddr(master)
		m := new(dns.Msg)
		m.SetAxfr(zone)
		tsigSecret := applyTSIG(m, auth)
		tr := &dns.Transfer{DialTimeout: xferDialTimeout, ReadTimeout: xferReadTimeout, TsigSecret: tsigSecret}
		env, err := tr.In(m, addr)
		if err != nil {
			lastErr = err
			continue
		}
		var ser uint32
		seenSOA := 0
		n := 0
		var streamErr error
		for e := range env {
			if e.Error != nil {
				streamErr = e.Error
				break
			}
			select {
			case <-ctx.Done():
				streamErr = ctx.Err()
			default:
			}
			if streamErr != nil {
				break
			}
			for _, rr := range e.RR {
				if soa, ok := rr.(*dns.SOA); ok {
					seenSOA++
					ser = soa.Serial
					continue
				}
				switch rr.(type) {
				case *dns.A, *dns.AAAA, *dns.CNAME, *dns.NS, *dns.TXT:
				default:
					continue
				}
				rel, ok := relativeOwner(rr.Header().Name, zone)
				if !ok {
					continue
				}
				if err := emit(rel); err != nil {
					streamErr = err
					break
				}
				n++
			}
			if streamErr != nil {
				break
			}
		}
		if streamErr != nil {
			lastErr = streamErr
			continue
		}
		if seenSOA < 2 {
			lastErr = fmt.Errorf("incomplete AXFR from %s", addr)
			continue
		}
		return ser, addr, n, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("all masters failed")
	}
	return 0, "", 0, lastErr
}

// streamAXFRToSink transfers the zone and writes each relative owner into sink (no giant names slice retained by caller).
func streamAXFRToSink(ctx context.Context, zone string, masters []string, hit Hit, sink domainSink) (serial uint32, count int, err error) {
	return streamAXFRToSinkWithTSIG(ctx, zone, masters, hit, sink, TSIGAuth{})
}

func streamAXFRToSinkWithTSIG(ctx context.Context, zone string, masters []string, hit Hit, sink domainSink, auth TSIGAuth) (serial uint32, count int, err error) {
	zone = config.NormalizeName(zone)
	if zone == "" || zone == "." {
		return 0, 0, fmt.Errorf("axfr zone required")
	}
	if len(masters) == 0 {
		return 0, 0, fmt.Errorf("axfr masters required")
	}
	if hit.Action == "" {
		hit.Action = ActionNXDOMAIN
	}
	hit.Target = strings.TrimSpace(hit.Target)
	var lastErr error
	for _, master := range masters {
		ser, n, err := axfrStreamToSink(ctx, zone, master, hit, sink, auth)
		if err != nil {
			lastErr = err
			continue
		}
		return ser, n, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("all masters failed")
	}
	return 0, 0, lastErr
}

func axfrStreamToSink(ctx context.Context, zone, master string, hit Hit, sink domainSink, auth TSIGAuth) (uint32, int, error) {
	addr := masterAddr(master)
	m := new(dns.Msg)
	m.SetAxfr(zone)
	tsigSecret := applyTSIG(m, auth)
	tr := &dns.Transfer{DialTimeout: xferDialTimeout, ReadTimeout: xferReadTimeout, TsigSecret: tsigSecret}
	env, err := tr.In(m, addr)
	if err != nil {
		return 0, 0, err
	}
	var serial uint32
	seenSOA := 0
	n := 0
	for e := range env {
		if e.Error != nil {
			return 0, 0, e.Error
		}
		select {
		case <-ctx.Done():
			return 0, 0, ctx.Err()
		default:
		}
		for _, rr := range e.RR {
			if soa, ok := rr.(*dns.SOA); ok {
				seenSOA++
				serial = soa.Serial
				continue
			}
			switch rr.(type) {
			case *dns.A, *dns.AAAA, *dns.CNAME, *dns.NS, *dns.TXT:
			default:
				continue
			}
			rel, ok := relativeOwner(rr.Header().Name, zone)
			if !ok {
				continue
			}
			if err := sink.Put(rel, hit); err != nil {
				return 0, 0, err
			}
			n++
		}
	}
	if seenSOA < 2 {
		return 0, 0, fmt.Errorf("incomplete AXFR from %s", addr)
	}
	return serial, n, nil
}

func ixfrPull(ctx context.Context, zone, master string, serial uint32, auth TSIGAuth) (TransferResult, error) {
	addr := masterAddr(master)
	m := new(dns.Msg)
	m.SetIxfr(zone, serial, "ns."+zone, "hostmaster."+zone)
	tsigSecret := applyTSIG(m, auth)
	tr := &dns.Transfer{DialTimeout: xferDialTimeout, ReadTimeout: xferReadTimeout, TsigSecret: tsigSecret}
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
	res, err := parseIXFR(zone, serial, rrs)
	if err != nil {
		return TransferResult{}, err
	}
	res.Master = addr
	return res, nil
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
	if newSerial == clientSerial || !SerialGreater(newSerial, clientSerial) {
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
