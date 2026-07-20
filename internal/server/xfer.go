package server

import (
	"net"
	"strings"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/metrics"
)

// handleTransfer serves AXFR (and IXFR-as-AXFR). Returns true if the query was handled.
func (s *Server) handleTransfer(w dns.ResponseWriter, req *dns.Msg, clientIP string) bool {
	if len(req.Question) == 0 {
		return false
	}
	q := req.Question[0]
	if q.Qtype != dns.TypeAXFR && q.Qtype != dns.TypeIXFR {
		return false
	}
	if s.cfg == nil || !s.cfg.Transfer.AllowAXFR {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeRefused)
		_ = w.WriteMsg(m)
		metrics.QueriesTotal.WithLabelValues(protocolFromWriter(w), "xfer_denied").Inc()
		return true
	}
	if !transferAllowedFrom(s.cfg.Transfer.AllowFrom, clientIP) {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeRefused)
		_ = w.WriteMsg(m)
		metrics.QueriesTotal.WithLabelValues(protocolFromWriter(w), "xfer_acl").Inc()
		return true
	}
	if s.cfg.Transfer.RequireTSIG {
		if status := w.TsigStatus(); status != nil {
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeNotAuth)
			_ = w.WriteMsg(m)
			metrics.QueriesTotal.WithLabelValues(protocolFromWriter(w), "xfer_tsig").Inc()
			return true
		}
	}

	zone := config.NormalizeName(q.Name)
	recs, ok := s.auth.GetRecords(zone)
	if !ok {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeNameError)
		_ = w.WriteMsg(m)
		return true
	}

	soa := findOrSynthSOA(zone, recs)
	rrs := make([]dns.RR, 0, len(recs)+2)
	rrs = append(rrs, soa)
	for _, rec := range recs {
		if rec.Type == dns.TypeSOA {
			continue
		}
		if rr := authoritative.RecordToRR(rec); rr != nil {
			rrs = append(rrs, rr)
		}
	}
	rrs = append(rrs, soa)

	// Multi-message AXFR over TCP is ideal; for simplicity send one packed answer stream.
	ch := make(chan *dns.Envelope)
	tr := new(dns.Transfer)
	go func() {
		ch <- &dns.Envelope{RR: rrs}
		close(ch)
	}()
	if err := tr.Out(w, req, ch); err != nil {
		s.log.Warn("axfr failed", "zone", zone, "err", err)
	}
	metrics.QueriesTotal.WithLabelValues(protocolFromWriter(w), "axfr").Inc()
	return true
}

func transferAllowedFrom(cidrs []string, ipStr string) bool {
	if len(cidrs) == 0 {
		return true
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if !strings.Contains(c, "/") {
			if net.ParseIP(c) != nil && net.ParseIP(c).Equal(ip) {
				return true
			}
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

func findOrSynthSOA(zone string, recs []authoritative.Record) dns.RR {
	for _, rec := range recs {
		if rec.Type == dns.TypeSOA {
			if rr := authoritative.RecordToRR(rec); rr != nil {
				return rr
			}
		}
	}
	return &dns.SOA{
		Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:  "ns1." + zone, Mbox: "hostmaster." + zone,
		Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: 300,
	}
}

// NotifySecondaries sends DNS NOTIFY for zone to configured remotes (best-effort).
func (s *Server) NotifySecondaries(zone string) {
	if s == nil || s.cfg == nil || len(s.cfg.Transfer.Notify) == 0 {
		return
	}
	zone = config.NormalizeName(zone)
	m := new(dns.Msg)
	m.SetNotify(zone)
	c := &dns.Client{Net: "udp", Timeout: s.res.Timeout}
	for _, addr := range s.cfg.Transfer.Notify {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr = net.JoinHostPort(addr, "53")
		}
		go func(a string) {
			_, _, err := c.Exchange(m, a)
			if err != nil && s.log != nil {
				s.log.Warn("notify failed", "zone", zone, "addr", a, "err", err)
			}
		}(addr)
	}
}
