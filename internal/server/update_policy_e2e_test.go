package server

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/config"
)

var policyKeyed = []config.UpdatePolicyTOML{{Key: "good.example.com.", Zones: []string{"example.com"}}}

func policyHarness(requireTSIG bool, policies []config.UpdatePolicyTOML, t *testing.T) *harness {
	t.Helper()
	h := newHarness(t, withConfig(func(c *config.Config) {
		c.Update.Enabled = true
		c.Update.RequireTSIG = requireTSIG
		c.Update.Policies = policies
	}))
	h.addZone(zoneName, rec("www.example.com.", dns.TypeA, "192.0.2.10"))
	return h
}

// policyUpdateFrom sends an update carrying a TSIG record for key (none when
// key is empty) and reports the rcode and whether the record was applied.
func policyUpdateFrom(t *testing.T, h *harness, key string, tsigErr error) (int, bool) {
	t.Helper()
	req := updateReq(zoneName, nil, []dns.RR{mustRR(t, "added.example.com. 120 IN A 192.0.2.77")})
	if key != "" {
		req.SetTsig(key, dns.HmacSHA256, 300, time.Now().Unix())
	}
	w := newWriter(anyClientIP)
	w.tsigErr = tsigErr
	msgs := h.send(w, req)
	if len(msgs) != 1 {
		t.Fatalf("want exactly 1 reply, got %d", len(msgs))
	}
	return msgs[0].Rcode, h.auth.RRSetExists(zoneName, "added.example.com.", dns.TypeA)
}

func TestUnsignedUpdateIsRefusedForAZoneWithAnUpdatePolicy(t *testing.T) {
	for name, pol := range map[string][]config.UpdatePolicyTOML{
		"keyed policy":       policyKeyed,
		"keyless policy":     {{Zones: []string{"example.com"}}},
		"keyless, all zones": {{}},
	} {
		h := policyHarness(false, pol, t)
		if rc, applied := policyUpdateFrom(t, h, "", nil); rc != dns.RcodeRefused || applied {
			t.Fatalf("%s: unsigned update rcode=%s applied=%v, want REFUSED and not applied", name, dns.RcodeToString[rc], applied)
		}
	}
}

func TestSignedUpdateWithAKeyThePolicyAllowsIsAccepted(t *testing.T) {
	h := policyHarness(false, policyKeyed, t)
	if rc, applied := policyUpdateFrom(t, h, "good.example.com.", nil); rc != dns.RcodeSuccess || !applied {
		t.Fatalf("rcode=%s applied=%v, want NOERROR and applied", dns.RcodeToString[rc], applied)
	}
	wantA(t, h.q("added.example.com.", dns.TypeA), "192.0.2.77")
}

func TestSignedUpdateWithAKeyThePolicyDoesNotAllowIsRefused(t *testing.T) {
	h := policyHarness(false, policyKeyed, t)
	if rc, applied := policyUpdateFrom(t, h, "other.example.com.", nil); rc != dns.RcodeRefused || applied {
		t.Fatalf("other key: rcode=%s applied=%v, want REFUSED and not applied", dns.RcodeToString[rc], applied)
	}
	h = policyHarness(false, []config.UpdatePolicyTOML{{Key: "good.example.com.", Zones: []string{"other.org"}}}, t)
	if rc, applied := policyUpdateFrom(t, h, "good.example.com.", nil); rc != dns.RcodeRefused || applied {
		t.Fatalf("allowed key for another zone: rcode=%s applied=%v, want REFUSED", dns.RcodeToString[rc], applied)
	}
}

func TestUpdateForAZoneWithoutPoliciesBehavesAsBefore(t *testing.T) {
	h := policyHarness(false, nil, t)
	if rc, applied := policyUpdateFrom(t, h, "", nil); rc != dns.RcodeSuccess || !applied {
		t.Fatalf("unsigned: rcode=%s applied=%v, want applied", dns.RcodeToString[rc], applied)
	}
	h = policyHarness(false, nil, t)
	if rc, applied := policyUpdateFrom(t, h, "any.example.com.", nil); rc != dns.RcodeSuccess || !applied {
		t.Fatalf("signed: rcode=%s applied=%v, want applied", dns.RcodeToString[rc], applied)
	}
}

func TestUpdatePoliciesWithRequiredTSIGKeepTheTSIGBehaviour(t *testing.T) {
	h := policyHarness(true, policyKeyed, t)
	if rc, applied := policyUpdateFrom(t, h, "good.example.com.", dns.ErrSig); rc != dns.RcodeNotAuth || applied {
		t.Fatalf("bad signature: rcode=%s applied=%v, want NOTAUTH", dns.RcodeToString[rc], applied)
	}
	if rc, applied := policyUpdateFrom(t, h, "other.example.com.", nil); rc != dns.RcodeRefused || applied {
		t.Fatalf("key outside the policy: rcode=%s applied=%v, want REFUSED", dns.RcodeToString[rc], applied)
	}
	if rc, applied := policyUpdateFrom(t, h, "good.example.com.", nil); rc != dns.RcodeSuccess || !applied {
		t.Fatalf("allowed key: rcode=%s applied=%v, want applied", dns.RcodeToString[rc], applied)
	}
}
