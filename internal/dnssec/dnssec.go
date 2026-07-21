package dnssec

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Mode controls DNSSEC behavior.
type Mode string

const (
	ModeOff           Mode = "off"
	ModeValidate      Mode = "validate"      // SERVFAIL on bogus
	ModeOpportunistic Mode = "opportunistic" // set AD when possible, never SERVFAIL for DNSSEC
)

func ParseMode(s string, legacyEnabled bool) Mode {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "validate", "yes", "true", "on":
		return ModeValidate
	case "opportunistic":
		return ModeOpportunistic
	case "off", "no", "false", "":
		if legacyEnabled {
			return ModeValidate
		}
		return ModeOff
	default:
		return ModeOff
	}
}

// Result of applying DNSSEC policy to a response.
type Result struct {
	Authenticated bool
	Bogus         bool
	Reason        string
}

// Validator applies DNSSEC policy to resolved answers.
type Validator struct {
	Mode Mode
}

func New(mode Mode) *Validator {
	return &Validator{Mode: mode}
}

func (v *Validator) Enabled() bool {
	return v != nil && v.Mode != ModeOff
}

// WantDO reports whether outbound queries should set the DO bit.
func (v *Validator) WantDO() bool {
	return v.Enabled()
}

// Apply mutates resp according to policy. Returns whether the caller should SERVFAIL.
func (v *Validator) Apply(resp *dns.Msg) (servfail bool, res Result) {
	if v == nil || v.Mode == ModeOff || resp == nil {
		return false, Result{}
	}

	res = evaluate(resp)
	resp.AuthenticatedData = false
	resp.CheckingDisabled = false

	switch v.Mode {
	case ModeValidate:
		if res.Bogus {
			return true, res
		}
		if res.Authenticated {
			resp.AuthenticatedData = true
		}
		return false, res
	case ModeOpportunistic:
		if res.Authenticated {
			resp.AuthenticatedData = true
		}
		return false, res
	default:
		return false, res
	}
}

func evaluate(msg *dns.Msg) Result {
	// Prefer upstream AD when DO was honored (common with validating forwarders).
	if msg.AuthenticatedData && (msg.Rcode == dns.RcodeSuccess || msg.Rcode == dns.RcodeNameError) {
		return Result{Authenticated: true, Reason: "upstream AD"}
	}
	if msg.Rcode == dns.RcodeServerFailure {
		return Result{Reason: "upstream SERVFAIL"}
	}

	// NXDOMAIN / NODATA: verify NSEC3 (or NSEC) denial proofs when present.
	if msg.Rcode == dns.RcodeNameError || (msg.Rcode == dns.RcodeSuccess && len(msg.Answer) == 0) {
		if res, ok := evaluateDenial(msg); ok {
			return res
		}
	}

	keys := collectDNSKEYs(msg)
	if len(keys) == 0 {
		return Result{Reason: "no DNSKEY in message"}
	}

	rrsets := groupByOwnerType(msg.Answer)
	verifiedAny := false
	for _, set := range rrsets {
		if len(set.rrsig) == 0 || len(set.rrs) == 0 {
			continue
		}
		ok := false
		var lastErr error
		for _, sig := range set.rrsig {
			key := keys[sig.KeyTag]
			if key == nil {
				lastErr = fmt.Errorf("missing DNSKEY tag %d", sig.KeyTag)
				continue
			}
			if err := sig.Verify(key, set.rrs); err != nil {
				lastErr = err
				continue
			}
			if !sig.ValidityPeriod(time.Now().UTC()) {
				lastErr = fmt.Errorf("rrsig outside validity period")
				continue
			}
			ok = true
			break
		}
		if !ok {
			return Result{Bogus: true, Reason: fmt.Sprintf("rrsig verify failed: %v", lastErr)}
		}
		verifiedAny = true
	}
	if verifiedAny {
		return Result{Authenticated: true, Reason: "local RRSIG"}
	}
	return Result{Reason: "no RRSIG verified"}
}

// evaluateDenial checks authority NSEC3/NSEC covers for NXDOMAIN/NODATA.
// ok=false means no usable denial RRs (fall through to other checks).
func evaluateDenial(msg *dns.Msg) (Result, bool) {
	if msg == nil || len(msg.Question) == 0 {
		return Result{}, false
	}
	qname := dns.CanonicalName(msg.Question[0].Name)
	qtype := msg.Question[0].Qtype

	var nsec3s []*dns.NSEC3
	var nsecs []*dns.NSEC
	for _, rr := range msg.Ns {
		switch v := rr.(type) {
		case *dns.NSEC3:
			nsec3s = append(nsec3s, v)
		case *dns.NSEC:
			nsecs = append(nsecs, v)
		}
	}
	if len(nsec3s) == 0 && len(nsecs) == 0 {
		return Result{}, false
	}

	if len(nsec3s) > 0 {
		nameCovered := false
		wildcardCovered := false
		typeDenied := false
		for _, n := range nsec3s {
			if n.Match(qname) {
				// Closest encloser / exact owner match: NODATA if type absent
				if !typeBitmapHas(n.TypeBitMap, qtype) {
					typeDenied = true
				}
				nameCovered = true
			}
			if n.Cover(qname) {
				nameCovered = true
			}
			// Wildcard denial at *.closest-encloser is approximated via Cover on \052.<labels>
			labels := dns.SplitDomainName(qname)
			if len(labels) >= 1 {
				wild := "*." + strings.Join(labels[1:], ".") + "."
				if len(labels) == 1 {
					wild = "*."
				}
				if n.Cover(dns.Fqdn(wild)) || n.Match(dns.Fqdn(wild)) {
					wildcardCovered = true
				}
			}
		}
		if msg.Rcode == dns.RcodeNameError {
			if nameCovered && wildcardCovered {
				return Result{Authenticated: true, Reason: "nsec3 nxdomain cover"}, true
			}
			// Incomplete proof → treat as insecure, not bogus (avoid SERVFAIL on partial upstreams)
			return Result{Reason: "incomplete nsec3 nxdomain proof"}, true
		}
		// NODATA
		if typeDenied || nameCovered {
			return Result{Authenticated: true, Reason: "nsec3 nodata"}, true
		}
		return Result{Reason: "incomplete nsec3 nodata proof"}, true
	}

	// Plain NSEC: owner exists without type, or covers name.
	for _, n := range nsecs {
		owner := dns.CanonicalName(n.Hdr.Name)
		if owner == qname {
			if !typeBitmapHas(n.TypeBitMap, qtype) {
				return Result{Authenticated: true, Reason: "nsec nodata"}, true
			}
		}
		if nsecCovers(n, qname) {
			return Result{Authenticated: true, Reason: "nsec nxdomain cover"}, true
		}
	}
	return Result{Reason: "incomplete nsec proof"}, true
}

func typeBitmapHas(types []uint16, qtype uint16) bool {
	for _, t := range types {
		if t == qtype {
			return true
		}
	}
	return false
}

func nsecCovers(n *dns.NSEC, name string) bool {
	if n == nil {
		return false
	}
	owner := dns.CanonicalName(n.Hdr.Name)
	next := dns.CanonicalName(n.NextDomain)
	name = dns.CanonicalName(name)
	// Canonical order: owner < name < next (wrap-around if next <= owner)
	if next <= owner {
		return name > owner || name < next
	}
	return name > owner && name < next
}

type rrset struct {
	rrs   []dns.RR
	rrsig []*dns.RRSIG
}

func groupByOwnerType(rrs []dns.RR) map[string]*rrset {
	out := map[string]*rrset{}
	for _, rr := range rrs {
		h := rr.Header()
		if h.Rrtype == dns.TypeRRSIG {
			sig, ok := rr.(*dns.RRSIG)
			if !ok {
				continue
			}
			key := dns.CanonicalName(h.Name) + "/" + dns.TypeToString[sig.TypeCovered]
			s := out[key]
			if s == nil {
				s = &rrset{}
				out[key] = s
			}
			s.rrsig = append(s.rrsig, sig)
			continue
		}
		key := dns.CanonicalName(h.Name) + "/" + dns.TypeToString[h.Rrtype]
		s := out[key]
		if s == nil {
			s = &rrset{}
			out[key] = s
		}
		s.rrs = append(s.rrs, rr)
	}
	return out
}

func collectDNSKEYs(msg *dns.Msg) map[uint16]*dns.DNSKEY {
	keys := map[uint16]*dns.DNSKEY{}
	add := func(rrs []dns.RR) {
		for _, rr := range rrs {
			if k, ok := rr.(*dns.DNSKEY); ok {
				keys[k.KeyTag()] = k
			}
		}
	}
	add(msg.Answer)
	add(msg.Ns)
	add(msg.Extra)
	return keys
}
