package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type dnsLookupRequest struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Target   string `json:"target"`   // local | dnsdist | unbound | auth | IP[:port] | https://... | tls://...
	Protocol string `json:"protocol"` // udp | tcp | dot | doh
	DO       *bool  `json:"do"`
	CD       bool   `json:"cd"`
	RD       *bool  `json:"rd"`
}

func rrStrings(rrs []dns.RR) []string {
	out := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		out = append(out, rr.String())
	}
	return out
}

func resolveTargetEndpoint(target, proto string) (kind, addr string, useTLS bool) {
	t := strings.TrimSpace(target)
	p := strings.ToLower(strings.TrimSpace(proto))
	if strings.HasPrefix(t, "https://") {
		return "doh", t, true
	}
	if strings.HasPrefix(t, "tls://") {
		host := strings.TrimPrefix(t, "tls://")
		if _, _, err := net.SplitHostPort(host); err != nil {
			host = net.JoinHostPort(host, "853")
		}
		return "dot", host, true
	}
	switch strings.ToLower(t) {
	case "", "local", "default":
		if p == "" || p == "internal" {
			return "local", "", false
		}
		addr = "127.0.0.1:53"
	case "dnsdist":
		addr = "127.0.0.1:53"
	case "unbound":
		addr = "127.0.0.1:5353"
	case "auth":
		addr = "127.0.0.1:5354"
	default:
		if _, _, err := net.SplitHostPort(t); err == nil {
			addr = t
		} else {
			port := "53"
			if p == "dot" {
				port = "853"
			}
			addr = net.JoinHostPort(t, port)
		}
	}
	switch p {
	case "tcp":
		return "tcp", addr, false
	case "dot":
		return "dot", addr, true
	case "doh":
		return "doh", "https://" + addr + "/dns-query", true
	default:
		return "udp", addr, false
	}
}

func exchangeMsg(ctx context.Context, msg *dns.Msg, target, proto string) (*dns.Msg, time.Duration, string, error) {
	kind, addr, _ := resolveTargetEndpoint(target, proto)
	start := time.Now()
	if kind == "doh" {
		wire, err := msg.Pack()
		if err != nil {
			return nil, 0, addr, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, addr, bytes.NewReader(wire))
		if err != nil {
			return nil, 0, addr, err
		}
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")
		cli := &http.Client{Timeout: 5 * time.Second}
		resp, err := cli.Do(req)
		if err != nil {
			return nil, time.Since(start), addr, err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			return nil, time.Since(start), addr, fmt.Errorf("DoH HTTP %d", resp.StatusCode)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		if err != nil {
			return nil, time.Since(start), addr, err
		}
		out := new(dns.Msg)
		if err := out.Unpack(body); err != nil {
			return nil, time.Since(start), addr, err
		}
		return out, time.Since(start), addr, nil
	}
	netType := "udp"
	if kind == "tcp" {
		netType = "tcp"
	} else if kind == "dot" {
		netType = "tcp-tls"
	}
	c := &dns.Client{Net: netType, Timeout: 4 * time.Second, UDPSize: 4096}
	out, rtt, err := c.ExchangeContext(ctx, msg, addr)
	return out, rtt, addr, err
}

func (a *API) handleLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body dnsLookupRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Name) == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}
	qtype := dns.TypeA
	if body.Type != "" {
		if t, ok := dns.StringToType[strings.ToUpper(strings.TrimSpace(body.Type))]; ok {
			qtype = t
		}
	}
	wantDO := true
	if body.DO != nil {
		wantDO = *body.DO
	}
	wantRD := true
	if body.RD != nil {
		wantRD = *body.RD
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(strings.TrimSpace(body.Name)), qtype)
	msg.RecursionDesired = wantRD
	msg.CheckingDisabled = body.CD
	msg.SetEdns0(4096, wantDO)

	var (
		resp *dns.Msg
		rtt  time.Duration
		via  string
		err  error
	)
	kind, _, _ := resolveTargetEndpoint(body.Target, body.Protocol)
	if kind == "local" {
		start := time.Now()
		resp, _, err = a.srv.ServeDNSMsg(msg)
		rtt = time.Since(start)
		via = "powersvx-local"
	} else {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		resp, rtt, via, err = exchangeMsg(ctx, msg, body.Target, body.Protocol)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"question":   dns.Fqdn(strings.TrimSpace(body.Name)) + " " + dns.TypeToString[qtype],
		"target":     via,
		"rcode":      dns.RcodeToString[resp.Rcode],
		"latency_ms": float64(rtt.Microseconds()) / 1000.0,
		"flags": map[string]bool{
			"aa": resp.Authoritative,
			"tc": resp.Truncated,
			"rd": resp.RecursionDesired,
			"ra": resp.RecursionAvailable,
			"ad": resp.AuthenticatedData,
			"cd": resp.CheckingDisabled,
		},
		"ad":         resp.AuthenticatedData,
		"answers":    rrStrings(resp.Answer),
		"authority":  rrStrings(resp.Ns),
		"additional": rrStrings(resp.Extra),
	})
}

type traceHop struct {
	Depth         int      `json:"depth"`
	Zone          string   `json:"zone"`
	Server        string   `json:"server"`
	IP            string   `json:"ip"`
	RCode         string   `json:"rcode"`
	LatencyMS     float64  `json:"latency_ms"`
	Authoritative bool     `json:"authoritative"`
	ReferralNS    []string `json:"referral_ns,omitempty"`
	Answers       []string `json:"answers,omitempty"`
	Error         string   `json:"error,omitempty"`
}

var ianaRoots = []struct{ name, ip string }{
	{"a.root-servers.net.", "198.41.0.4"},
	{"b.root-servers.net.", "170.247.170.2"},
	{"d.root-servers.net.", "199.7.91.13"},
	{"h.root-servers.net.", "198.97.190.53"},
}

func (a *API) handleTrace(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Name) == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}
	qname := dns.Fqdn(strings.TrimSpace(body.Name))
	qtype := dns.TypeA
	if body.Type != "" {
		if t, ok := dns.StringToType[strings.ToUpper(strings.TrimSpace(body.Type))]; ok {
			qtype = t
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	cli := &dns.Client{Net: "udp", Timeout: 2500 * time.Millisecond, UDPSize: 4096}

	curName := ianaRoots[0].name
	curIP := ianaRoots[0].ip
	zone := "."
	hops := make([]traceHop, 0, 8)

	for depth := 0; depth < 12; depth++ {
		msg := new(dns.Msg)
		msg.SetQuestion(qname, qtype)
		msg.RecursionDesired = false
		msg.SetEdns0(4096, true)

		resp, rtt, err := cli.ExchangeContext(ctx, msg, net.JoinHostPort(curIP, "53"))
		if err != nil {
			hops = append(hops, traceHop{
				Depth:  depth,
				Zone:   zone,
				Server: curName,
				IP:     curIP,
				Error:  err.Error(),
			})
			break
		}
		hop := traceHop{
			Depth:         depth,
			Zone:          zone,
			Server:        curName,
			IP:            curIP,
			RCode:         dns.RcodeToString[resp.Rcode],
			LatencyMS:     float64(rtt.Microseconds()) / 1000.0,
			Authoritative: resp.Authoritative,
			Answers:       rrStrings(resp.Answer),
		}

		if len(resp.Answer) > 0 || resp.Authoritative || resp.Rcode != dns.RcodeSuccess {
			hops = append(hops, hop)
			break
		}

		// Collect referral NS + glue A/AAAA
		glue := make(map[string]string)
		for _, rr := range resp.Extra {
			switch v := rr.(type) {
			case *dns.A:
				glue[strings.ToLower(v.Hdr.Name)] = v.A.String()
			case *dns.AAAA:
				if _, exists := glue[strings.ToLower(v.Hdr.Name)]; !exists {
					glue[strings.ToLower(v.Hdr.Name)] = v.AAAA.String()
				}
			}
		}
		nextServer, nextIP, nextZone := "", "", ""
		for _, rr := range resp.Ns {
			if ns, ok := rr.(*dns.NS); ok {
				hop.ReferralNS = append(hop.ReferralNS, ns.Ns)
				if nextZone == "" {
					nextZone = ns.Hdr.Name
				}
				if ip, ok := glue[strings.ToLower(ns.Ns)]; ok && nextIP == "" {
					nextServer = ns.Ns
					nextIP = ip
				}
			}
		}
		hops = append(hops, hop)
		if len(hop.ReferralNS) == 0 {
			break
		}
		if nextIP == "" {
			// Resolve glueless NS IP locally
			nextServer = hop.ReferralNS[0]
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(nextServer), dns.TypeA)
			m.RecursionDesired = true
			if rmsg, _, rerr := a.srv.ServeDNSMsg(m); rerr == nil {
				for _, rr := range rmsg.Answer {
					if aRec, ok := rr.(*dns.A); ok {
						nextIP = aRec.A.String()
						break
					}
				}
			}
		}
		if nextIP == "" {
			break
		}
		curName = nextServer
		curIP = nextIP
		zone = nextZone
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"question": qname + " " + dns.TypeToString[qtype],
		"hops":     hops,
	})
}
