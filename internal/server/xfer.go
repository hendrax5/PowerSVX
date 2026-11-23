package server

import (
	"time"
	"net"
	"strings"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/metrics"
)

// handleTransfer serves AXFR. IXFR is answered as a full-zone AXFR (no journal).
func (s *Server) handleTransfer(w dns.ResponseWriter, req *dns.Msg, clientIP string) bool {
	if len(req.Question) == 0 {
		return false
	}
	q := req.Question[0]
	if q.Qtype != dns.TypeAXFR && q.Qtype != dns.TypeIXFR {
		return false
	}
	if s.cfg == nil || !s.cfg.Transfer.AllowAXFR {
		// Kominfo sync may allow AXFR only for its secondaries without global allow_axfr.
		if s.kominfo == nil || !s.kominfo.IsTargetIP(clientIP) {
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeRefused)
			_ = w.WriteMsg(m)
			metrics.QueriesTotal.WithLabelValues(protocolFromWriter(w), "xfer_denied").Inc()
			return true
		}
	}
	allowFrom := []string(nil)
	requireTSIG := false
	if s.cfg != nil {
		allowFrom = s.cfg.Transfer.AllowFrom
		requireTSIG = s.cfg.Transfer.RequireTSIG
	}
	if !transferAllowedFrom(allowFrom, clientIP) {
		if s.kominfo == nil || !s.kominfo.IsTargetIP(clientIP) {
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeRefused)
			_ = w.WriteMsg(m)
			metrics.QueriesTotal.WithLabelValues(protocolFromWriter(w), "xfer_acl").Inc()
			return true
		}
	}
	if requireTSIG {
		if s.kominfo == nil || !s.kominfo.IsTargetIP(clientIP) {
			if status := w.TsigStatus(); status != nil {
				m := new(dns.Msg)
				m.SetRcode(req, dns.RcodeNotAuth)
				_ = w.WriteMsg(m)
				metrics.QueriesTotal.WithLabelValues(protocolFromWriter(w), "xfer_tsig").Inc()
				return true
			}
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
	// NSEC3PARAM is published from the signing policy, not stored; a zone that has
	// one is always sent in full so a secondary never misses a parameter change.
	np := s.nsec3param(zone, zone, 0, "", "")
	var rrs []dns.RR
	if q.Qtype == dns.TypeIXFR && len(req.Ns) > 0 {
		if clientSOA, isSOA := req.Ns[0].(*dns.SOA); isSOA {
			if deltas, curSerial, ok := s.auth.IXFRDeltas(zone, clientSOA.Serial); ok {
				if curSerial == clientSOA.Serial || int32(curSerial-clientSOA.Serial) <= 0 {
					rrs = []dns.RR{soa}
				} else if np == nil {
					rrs = make([]dns.RR, 0, 16)
					rrs = append(rrs, soa)
					for _, d := range deltas {
						oldSOA := *soa.(*dns.SOA)
						oldSOA.Serial = d.FromSerial
						rrs = append(rrs, &oldSOA)
						for _, rem := range d.Removed {
							if rem.Type == dns.TypeSOA {
								continue
							}
							if rr := authoritative.RecordToRR(rem); rr != nil {
								rrs = append(rrs, rr)
							}
						}
						newSOA := *soa.(*dns.SOA)
						newSOA.Serial = d.ToSerial
						rrs = append(rrs, &newSOA)
						for _, add := range d.Added {
							if add.Type == dns.TypeSOA {
								continue
							}
							if rr := authoritative.RecordToRR(add); rr != nil {
								rrs = append(rrs, rr)
							}
						}
					}
					rrs = append(rrs, soa)
				}
			}
		}
	}
	if len(rrs) == 0 {
		rrs = make([]dns.RR, 0, len(recs)+2)
		rrs = append(rrs, soa)
		for _, rec := range recs {
			if rec.Type == dns.TypeSOA {
				continue
			}
			if rr := authoritative.RecordToRR(rec); rr != nil {
				rrs = append(rrs, rr)
			}
		}
		if np != nil {
			rrs = append(rrs, np)
		}
		rrs = append(rrs, soa)
	}

	// Multi-message AXFR/IXFR transfer stream over TCP.
	ch := make(chan *dns.Envelope)
	tr := new(dns.Transfer)
	go func() {
		ch <- &dns.Envelope{RR: rrs}
		close(ch)
	}()
	if err := tr.Out(w, req, ch); err != nil {
		s.log.Warn("xfer failed", "zone", zone, "qtype", dns.TypeToString[q.Qtype], "err", err)
	} else if s.kominfo != nil {
		s.kominfo.RecordAXFRPull(zone, clientIP)
	}
	metrics.QueriesTotal.WithLabelValues(protocolFromWriter(w), dns.TypeToString[q.Qtype]).Inc()
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
// notifyTimeout bounds each outgoing NOTIFY exchange.
const notifyTimeout = 2 * time.Second

func (s *Server) NotifySecondaries(zone string) {
	if s == nil {
		return
	}
	zone = config.NormalizeName(zone)
	if s.kominfo != nil && s.kominfo.Enabled() {
		go s.kominfo.NotifyZone(zone)
	}
	if s.cfg == nil || len(s.cfg.Transfer.Notify) == 0 {
		return
	}
	m := new(dns.Msg)
	m.SetNotify(zone)
	c := &dns.Client{Net: "udp", Timeout: notifyTimeout}
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

// nsec3param returns the NSEC3PARAM record that belongs at the apex of zone when
// qname/qtype ask for it (qtype NSEC3PARAM at the apex; any qtype when qtype is
// 0), and the zone is signed with NSEC3. Nil otherwise.
func (s *Server) nsec3param(zone, qname string, qtype uint16, viewName, geoTag string) *dns.NSEC3PARAM {
	if s.signer == nil || qtype != dns.TypeNSEC3PARAM && qtype != 0 || qname != zone {
		return nil
	}
	return s.signer.NSEC3PARAM(zone, s.apexNegativeTTL(zone, viewName, geoTag))
}

// apexNegativeTTL is the zone's SOA minimum capped by the SOA TTL (RFC 2308
// section 5), the TTL RFC 5155 section 4 gives NSEC3PARAM.
func (s *Server) apexNegativeTTL(zone, viewName, geoTag string) uint32 {
	if soaRRs, ok := s.auth.LookupScoped(zone, dns.TypeSOA, viewName, geoTag); ok && len(soaRRs) > 0 {
		if soa, ok := soaRRs[0].(*dns.SOA); ok {
			if soa.Minttl < soa.Hdr.Ttl {
				return soa.Minttl
			}
			return soa.Hdr.Ttl
		}
	}
	return 300
}
