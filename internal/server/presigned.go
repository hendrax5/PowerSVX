package server

import (
	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/dnssec"
)

// A Secondary Zone is served as received (ADR-0004): the DNSKEY, RRSIG, NSEC and
// NSEC3 records its primary sent are zone data, and nothing here signs. When the
// query has DO set, the stored signatures are added to the answer, and the stored
// NSEC or NSEC3 records that prove a negative answer to its authority section.

// presigned reports whether zone is a Secondary Zone, served from its primary's
// signatures and never signed with this process's keys.
func (s *Server) presigned(zone string) bool {
	return s.secondaryMgr != nil && s.secondaryMgr.Has(zone)
}

// signsLocally reports whether this process signs the answers of zone with its
// own keys: it holds keys for the zone and the zone is one it is the primary of.
func (s *Server) signsLocally(zone string) bool {
	return s.signer != nil && s.signer.Enabled(zone) && !s.presigned(zone)
}

func wantsDO(req *dns.Msg) bool {
	if req == nil {
		return false
	}
	opt := req.IsEdns0()
	return opt != nil && opt.Do()
}

// withStoredSignatures returns rrs with the zone's stored RRSIGs after each of
// its RRsets. wildcard is the owner the RRsets were synthesized from, whose
// signatures cover them; the RRSIGs go out with the query name as owner.
func (s *Server) withStoredSignatures(zone, wildcard string, rrs []dns.RR) []dns.RR {
	type set struct {
		key authoritative.SetKey
		rrs []dns.RR
	}
	var order []authoritative.SetKey
	sets := map[authoritative.SetKey]*set{}
	want := map[authoritative.SetKey]bool{}
	sigKey := func(k authoritative.SetKey) authoritative.SetKey {
		if wildcard != "" {
			k.Name = dns.CanonicalName(wildcard)
		}
		return k
	}
	for _, rr := range rrs {
		h := rr.Header()
		k := authoritative.SetKey{Name: dns.CanonicalName(h.Name), Type: h.Rrtype}
		if sets[k] == nil {
			sets[k] = &set{key: k}
			order = append(order, k)
		}
		sets[k].rrs = append(sets[k].rrs, rr)
		want[sigKey(k)] = true
	}
	sigs := s.auth.SignaturesFor(zone, want)
	out := make([]dns.RR, 0, len(rrs)+len(order))
	for _, k := range order {
		st := sets[k]
		out = append(out, st.rrs...)
		for _, sig := range sigs[sigKey(k)] {
			c := dns.Copy(sig)
			c.Header().Name = st.rrs[0].Header().Name
			out = append(out, c)
		}
	}
	return out
}

// addStoredProof adds to the authority section of m the stored records that
// prove a negative answer for qname, or the expansion of a wildcard, and the
// signatures over them. A negative answer's SOA gets its stored signature too.
func (s *Server) addStoredProof(zone, qname string, kind dnssec.ProofKind, m *dns.Msg) {
	names, chain := s.auth.DenialData(zone)
	proof := dnssec.PresignedProof(zone, qname, kind, names, chain)

	var add []dns.RR
	if kind != dnssec.ProofWildcardExpansion {
		for _, rr := range m.Ns {
			if rr.Header().Rrtype == dns.TypeSOA {
				add = append(add, rr)
			}
		}
	}
	have := map[string]bool{}
	for _, rr := range m.Ns {
		have[dns.CanonicalName(rr.Header().Name)+"/"+dns.TypeToString[rr.Header().Rrtype]] = true
	}
	for _, rr := range proof {
		if k := dns.CanonicalName(rr.Header().Name) + "/" + dns.TypeToString[rr.Header().Rrtype]; !have[k] {
			have[k] = true
			add = append(add, rr)
		}
	}
	if len(add) == 0 {
		return
	}
	signed := s.withStoredSignatures(zone, "", add)
	// The SOA is already in the section; only what follows it is new.
	for _, rr := range signed {
		if rr.Header().Rrtype == dns.TypeSOA {
			continue
		}
		m.Ns = append(m.Ns, rr)
	}
}
