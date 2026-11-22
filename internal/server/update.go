package server

import (
	"strings"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/metrics"
)

// handleUpdate applies RFC 2136 dynamic updates when [update] enabled.
func (s *Server) handleUpdate(w dns.ResponseWriter, req *dns.Msg, clientIP string) bool {
	if req == nil || req.Opcode != dns.OpcodeUpdate {
		return false
	}
	proto := protocolFromWriter(w)
	if s.cfg == nil || !s.cfg.Update.Enabled {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeRefused)
		_ = w.WriteMsg(m)
		metrics.QueriesTotal.WithLabelValues(proto, "update_disabled").Inc()
		return true
	}
	if !transferAllowedFrom(s.cfg.Update.AllowFrom, clientIP) {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeRefused)
		_ = w.WriteMsg(m)
		metrics.QueriesTotal.WithLabelValues(proto, "update_acl").Inc()
		return true
	}
	if s.cfg.Update.RequireTSIG {
		// w.TsigStatus() is nil both for a verified TSIG and for a request with no TSIG
		// record, so an unsigned request is refused explicitly (REFUSED); a failed
		// signature stays NOTAUTH.
		if req.IsTsig() == nil || w.TsigStatus() != nil {
			rcode := dns.RcodeNotAuth
			if req.IsTsig() == nil {
				rcode = dns.RcodeRefused
			}
			m := new(dns.Msg)
			m.SetRcode(req, rcode)
			_ = w.WriteMsg(m)
			metrics.QueriesTotal.WithLabelValues(proto, "update_tsig").Inc()
			return true
		}
	}

	zone := updateZoneName(req)
	if zone == "" || s.auth == nil {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeNotZone)
		_ = w.WriteMsg(m)
		return true
	}
	if _, ok := s.auth.GetRecords(zone); !ok {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeNotAuth)
		_ = w.WriteMsg(m)
		return true
	}
	if !updatePolicyAllows(s.cfg.Update.Policies, tsigKeyName(req), zone) {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeRefused)
		_ = w.WriteMsg(m)
		metrics.QueriesTotal.WithLabelValues(proto, "update_policy").Inc()
		return true
	}

	if rc := checkUpdatePrereqs(s.auth, zone, req.Answer); rc != dns.RcodeSuccess {
		m := new(dns.Msg)
		m.SetRcode(req, rc)
		_ = w.WriteMsg(m)
		metrics.QueriesTotal.WithLabelValues(proto, "update_prereq").Inc()
		return true
	}
	if rc := applyUpdateSection(s.auth, zone, req.Ns); rc != dns.RcodeSuccess {
		m := new(dns.Msg)
		m.SetRcode(req, rc)
		_ = w.WriteMsg(m)
		metrics.QueriesTotal.WithLabelValues(proto, "update_fail").Inc()
		return true
	}
	_, _ = s.auth.BumpSOASerial(zone)
	go s.NotifySecondaries(zone)

	m := new(dns.Msg)
	m.SetReply(req)
	_ = w.WriteMsg(m)
	metrics.QueriesTotal.WithLabelValues(proto, "UPDATE").Inc()
	return true
}

func updateZoneName(req *dns.Msg) string {
	if len(req.Question) > 0 {
		return config.NormalizeName(req.Question[0].Name)
	}
	return ""
}

func tsigKeyName(req *dns.Msg) string {
	if req == nil || req.IsTsig() == nil {
		return ""
	}
	return strings.ToLower(req.IsTsig().Hdr.Name)
}

func updatePolicyAllows(policies []config.UpdatePolicyTOML, key, zone string) bool {
	if len(policies) == 0 {
		return true
	}
	key = strings.ToLower(dns.Fqdn(key))
	zone = config.NormalizeName(zone)
	for _, p := range policies {
		pk := strings.ToLower(dns.Fqdn(strings.TrimSpace(p.Key)))
		if pk == "" || (key != "" && pk != key) {
			continue
		}
		if key == "" && p.Key != "" {
			continue
		}
		if len(p.Zones) == 0 {
			return true
		}
		for _, z := range p.Zones {
			if config.NormalizeName(z) == zone {
				return true
			}
		}
	}
	return false
}

func checkUpdatePrereqs(auth *authoritative.Store, zone string, prereqs []dns.RR) int {
	for _, rr := range prereqs {
		h := rr.Header()
		name := config.NormalizeName(h.Name)
		switch h.Class {
		case dns.ClassANY:
			// name / RRset must exist
			if h.Rrtype == dns.TypeANY {
				if !auth.NameExists(zone, name) {
					return dns.RcodeNameError // NXDOMAIN for name prereq
				}
			} else if !auth.RRSetExists(zone, name, h.Rrtype) {
				return dns.RcodeNXRrset
			}
		case dns.ClassNONE:
			// name / RRset must NOT exist
			if h.Rrtype == dns.TypeANY {
				if auth.NameExists(zone, name) {
					return dns.RcodeYXDomain
				}
			} else if auth.RRSetExists(zone, name, h.Rrtype) {
				return dns.RcodeYXRrset
			}
		case dns.ClassINET:
			rec, ok := authoritative.RecordFromRR(rr)
			if !ok {
				continue
			}
			if !rrExactExists(auth, zone, rec) {
				return dns.RcodeNXRrset
			}
		}
	}
	return dns.RcodeSuccess
}

func rrExactExists(auth *authoritative.Store, zone string, want authoritative.Record) bool {
	recs, ok := auth.GetRecords(zone)
	if !ok {
		return false
	}
	want.Name = config.NormalizeName(want.Name)
	want.Content = strings.TrimSpace(want.Content)
	for _, r := range recs {
		if config.NormalizeName(r.Name) == want.Name &&
			r.Type == want.Type &&
			strings.EqualFold(strings.TrimSpace(r.Content), want.Content) &&
			r.Prio == want.Prio {
			return true
		}
	}
	return false
}

func applyUpdateSection(auth *authoritative.Store, zone string, updates []dns.RR) int {
	for _, rr := range updates {
		h := rr.Header()
		name := config.NormalizeName(h.Name)
		if !dns.IsSubDomain(zone, name) && name != zone {
			return dns.RcodeNotZone
		}
		switch h.Class {
		case dns.ClassANY:
			// delete RRset or all at name
			if h.Rrtype == dns.TypeANY {
				auth.DeleteRecord(zone, name, 0)
			} else if h.Rrtype != dns.TypeSOA && h.Rrtype != dns.TypeNS {
				auth.DeleteRecord(zone, name, h.Rrtype)
			}
		case dns.ClassNONE:
			rec, ok := authoritative.RecordFromRR(rr)
			if !ok {
				continue
			}
			auth.DeleteRecordExact(zone, rec)
		case dns.ClassINET:
			rec, ok := authoritative.RecordFromRR(rr)
			if !ok {
				continue
			}
			if rec.Type == dns.TypeCNAME {
				auth.DeleteRecord(zone, rec.Name, 0)
			} else {
				// replace conflicting CNAME at name
				auth.DeleteRecord(zone, rec.Name, dns.TypeCNAME)
			}
			auth.AddRecord(zone, rec)
		default:
			return dns.RcodeFormatError
		}
	}
	return dns.RcodeSuccess
}
