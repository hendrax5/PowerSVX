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

// streamAXFR pulls a zone from masters (in order) and inserts non-apex owner names into the trie.
func streamAXFR(zone string, masters []string, hit Hit, timeout time.Duration, t *trie) error {
	zone = config.NormalizeName(zone)
	if zone == "" || zone == "." {
		return fmt.Errorf("axfr zone required")
	}
	if len(masters) == 0 {
		return fmt.Errorf("axfr masters required")
	}
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	names, _, err := PullAXFRNames(ctx, zone, masters)
	if err != nil {
		return err
	}
	if hit.Action == "" {
		hit.Action = ActionNXDOMAIN
	}
	hit.Target = strings.TrimSpace(hit.Target)
	for _, n := range names {
		t.insertHit(n, hit)
	}
	return nil
}

// PullAXFRNames transfers the zone from the first successful master and returns unique
// owner names for A/AAAA/CNAME/NS/TXT RRs, excluding the apex zone name.
func PullAXFRNames(ctx context.Context, zone string, masters []string) ([]string, uint32, error) {
	zone = config.NormalizeName(zone)
	var lastErr error
	for _, master := range masters {
		names, serial, err := axfrPullNames(ctx, zone, master)
		if err != nil {
			lastErr = err
			continue
		}
		return names, serial, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("all masters failed")
	}
	return nil, 0, lastErr
}

func axfrPullNames(ctx context.Context, zone, master string) ([]string, uint32, error) {
	addr := master
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(master, "53")
	}
	m := new(dns.Msg)
	m.SetAxfr(zone)
	tr := &dns.Transfer{DialTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second}
	env, err := tr.In(m, addr)
	if err != nil {
		return nil, 0, err
	}

	seen := map[string]struct{}{}
	var names []string
	var serial uint32
	seenSOA := 0
	for e := range env {
		if e.Error != nil {
			return nil, 0, e.Error
		}
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		default:
		}
		for _, rr := range e.RR {
			if soa, ok := rr.(*dns.SOA); ok {
				seenSOA++
				serial = soa.Serial
				if seenSOA > 1 {
					continue
				}
			}
			owner := config.NormalizeName(rr.Header().Name)
			if owner == zone {
				continue // skip apex SOA/NS/etc.
			}
			switch rr.(type) {
			case *dns.A, *dns.AAAA, *dns.CNAME, *dns.NS, *dns.TXT:
				if _, ok := seen[owner]; ok {
					continue
				}
				seen[owner] = struct{}{}
				names = append(names, owner)
			}
		}
	}
	if seenSOA < 2 {
		return nil, 0, fmt.Errorf("incomplete AXFR from %s", addr)
	}
	return names, serial, nil
}
