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
