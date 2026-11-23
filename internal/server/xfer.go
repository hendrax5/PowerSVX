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

// handleTransfer serves AXFR and IXFR. Both carry the zone as the requesting
// address would be answered (see transferScope); an IXFR is the whole zone, or the
// lone SOA when the client is current.
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
			if rcode, deny := tsigDenial(w, req); deny {
				m := new(dns.Msg)
				m.SetRcode(req, rcode)
				_ = w.WriteMsg(m)
				metrics.QueriesTotal.WithLabelValues(protocolFromWriter(w), "xfer_tsig").Inc()
				return true
			}
		}
	}

	zone := config.NormalizeName(q.Name)
	signed := s.signsLocally(zone)
	// A transfer carries what the primary would answer to the requesting address
	// (its split-horizon view, its GeoDNS answer), for a signed and an unsigned
	// zone alike, never the union of all views and geo tags.
	view, geoTag := s.transferScope(clientIP)
	recs, ok := s.auth.RecordsScoped(zone, view, geoTag)
	if !ok {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeNameError)
		_ = w.WriteMsg(m)
		return true
	}

	soa := findOrSynthSOA(zone, recs)
	var rrs []dns.RR
	if q.Qtype == dns.TypeIXFR && len(req.Ns) > 0 {
		if clientSOA, isSOA := req.Ns[0].(*dns.SOA); isSOA {
			// The stored deltas are not per view or geo tag, and a signed zone's
			// signatures change without any record changing, so a delta could carry
			// records the client may not see or leave it with stale ones. RFC 1995
			// section 4 lets the server answer with the whole zone; only "you are
			// current" is short.
			if clientSOA.Serial != 0 && int32(soa.(*dns.SOA).Serial-clientSOA.Serial) <= 0 {
				rrs = []dns.RR{soa}
			}
		}
	}
	var produce func(emit func(dns.RR) error) error
	if len(rrs) == 0 {
		if signed {
			produce = s.signedZoneStream(zone, soa, recs, time.Now().UTC())
		} else {
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
			rrs = append(rrs, soa)
		}
	}

	if err := s.sendTransfer(w, req, rrs, produce); err != nil {
		s.log.Warn("xfer failed", "zone", zone, "qtype", dns.TypeToString[q.Qtype], "err", err)
	} else if s.kominfo != nil {
		s.kominfo.RecordAXFRPull(zone, clientIP)
	}
	metrics.QueriesTotal.WithLabelValues(protocolFromWriter(w), dns.TypeToString[q.Qtype]).Inc()
	return true
}

// transferScope is the view and GeoDNS tag a transfer to clientIP is made for:
// the ones a query from that address is answered with. A transfer has no client
// subnet option, so the geo tag follows the address itself.
func (s *Server) transferScope(clientIP string) (view, geoTag string) {
	view, geoTag = "default", "default"
	if s.views != nil {
		view = s.views.Match(clientIP)
	}
	if s.geo != nil && s.geo.Enabled() {
		geoTag = s.geo.Lookup(clientIP).Tag
	}
	return view, geoTag
}

// tsigDenial decides whether a request fails a configured TSIG requirement.
// w.TsigStatus() is nil both for a verified signature and for a request that has
// no TSIG record at all, so the record's presence is checked separately.
// A signature that fails verification is NOTAUTH; a request without any TSIG
// record is REFUSED (it never attempted to authenticate).
func tsigDenial(w dns.ResponseWriter, req *dns.Msg) (rcode int, deny bool) {
	if w.TsigStatus() != nil {
		return dns.RcodeNotAuth, true
	}
	if req.IsTsig() == nil {
		return dns.RcodeRefused, true
	}
	return dns.RcodeSuccess, false
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
	if !s.signsLocally(zone) || qtype != dns.TypeNSEC3PARAM && qtype != 0 || qname != zone {
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
