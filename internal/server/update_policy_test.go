package server

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/config"
)

type policyWriter struct {
	tsigErr error
	msgs    []*dns.Msg
}

func (w *policyWriter) LocalAddr() net.Addr  { return &net.TCPAddr{IP: net.IPv4zero} }
func (w *policyWriter) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 5300} }
func (w *policyWriter) WriteMsg(m *dns.Msg) error {
	w.msgs = append(w.msgs, m)
	return nil
}
func (w *policyWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *policyWriter) Close() error                { return nil }
func (w *policyWriter) TsigStatus() error           { return w.tsigErr }
func (w *policyWriter) TsigTimersOnly(bool)         {}
func (w *policyWriter) Hijack()                     {}

func (w *policyWriter) rcode() int {
	if len(w.msgs) == 0 {
		return -1
	}
	return w.msgs[0].Rcode
}

func policyServer(t *testing.T, requireTSIG bool, policies []config.UpdatePolicyTOML) *Server {
	t.Helper()
	cfg := config.Default()
	cfg.Update.Enabled = true
	cfg.Update.RequireTSIG = requireTSIG
	cfg.Update.Policies = policies
	auth := authoritative.NewStore()
	auth.UpsertZone("example.com.")
	auth.AddRecord("example.com.", authoritative.Record{
		Name: "example.com.", Type: dns.TypeSOA, TTL: 60,
		Content: "ns.example.com. hostmaster.example.com. 1 3600 600 86400 60",
	})
	return New(cfg, Deps{Auth: auth}, nil)
}

func policyUpdate(key string) *dns.Msg {
	m := new(dns.Msg)
	m.SetUpdate("example.com.")
	rr, _ := dns.NewRR("added.example.com. 300 IN A 192.0.2.66")
	m.Insert([]dns.RR{rr})
	if key != "" {
		m.SetTsig(key, dns.HmacSHA256, 300, time.Now().Unix())
	}
	return m
}

func runPolicyUpdate(s *Server, key string) (int, bool) {
	w := &policyWriter{}
	s.handleUpdate(w, policyUpdate(key), "192.0.2.10")
	return w.rcode(), s.auth.RRSetExists("example.com.", "added.example.com.", dns.TypeA)
}

var keyPolicy = []config.UpdatePolicyTOML{{Key: "good.example.com.", Zones: []string{"example.com"}}}

func TestUpdatePolicyRefusesUnsignedUpdateForAZoneWithAPolicy(t *testing.T) {
	// A policy entry without a key name, and a zone list, must not admit unsigned clients.
	for name, pol := range map[string][]config.UpdatePolicyTOML{
		"keyed policy":   keyPolicy,
		"keyless policy": {{Zones: []string{"example.com"}}},
		"keyless, all zones": {{}},
	} {
		s := policyServer(t, false, pol)
		rc, applied := runPolicyUpdate(s, "")
		if rc != dns.RcodeRefused || applied {
			t.Fatalf("%s: unsigned update rcode=%d applied=%v, want REFUSED and not applied", name, rc, applied)
		}
	}
}

func TestUpdatePolicyAcceptsSignedUpdateWithAKeyThePolicyAllows(t *testing.T) {
	s := policyServer(t, false, keyPolicy)
	if rc, applied := runPolicyUpdate(s, "good.example.com."); rc != dns.RcodeSuccess || !applied {
		t.Fatalf("rcode=%d applied=%v, want NOERROR and applied", rc, applied)
	}
}

func TestUpdatePolicyRefusesSignedUpdateWithAKeyThePolicyDoesNotAllow(t *testing.T) {
	s := policyServer(t, false, keyPolicy)
	if rc, applied := runPolicyUpdate(s, "other.example.com."); rc != dns.RcodeRefused || applied {
		t.Fatalf("rcode=%d applied=%v, want REFUSED and not applied", rc, applied)
	}
	s = policyServer(t, false, []config.UpdatePolicyTOML{{Key: "good.example.com.", Zones: []string{"other.org"}}})
	if rc, applied := runPolicyUpdate(s, "good.example.com."); rc != dns.RcodeRefused || applied {
		t.Fatalf("allowed key, other zone: rcode=%d applied=%v, want REFUSED", rc, applied)
	}
}

func TestUpdateWithoutPoliciesBehavesAsBefore(t *testing.T) {
	s := policyServer(t, false, nil)
	if rc, applied := runPolicyUpdate(s, ""); rc != dns.RcodeSuccess || !applied {
		t.Fatalf("unsigned, no policies, requirement off: rcode=%d applied=%v, want applied", rc, applied)
	}
	s = policyServer(t, false, nil)
	if rc, applied := runPolicyUpdate(s, "any.example.com."); rc != dns.RcodeSuccess || !applied {
		t.Fatalf("signed, no policies: rcode=%d applied=%v, want applied", rc, applied)
	}
}

func TestUpdatePolicyWithRequiredTSIGKeepsTheTSIGBehaviour(t *testing.T) {
	s := policyServer(t, true, keyPolicy)
	w := &policyWriter{tsigErr: dns.ErrSig}
	s.handleUpdate(w, policyUpdate("good.example.com."), "192.0.2.10")
	if w.rcode() != dns.RcodeNotAuth {
		t.Fatalf("bad signature rcode=%d, want NOTAUTH", w.rcode())
	}
	if rc, applied := runPolicyUpdate(s, "good.example.com."); rc != dns.RcodeSuccess || !applied {
		t.Fatalf("allowed key: rcode=%d applied=%v, want applied", rc, applied)
	}
}

func TestUpdatePolicyAllowsUnitCases(t *testing.T) {
	if updatePolicyAllows(keyPolicy, "", "example.com.") {
		t.Fatal("unsigned must not match a policy")
	}
	if updatePolicyAllows([]config.UpdatePolicyTOML{{Zones: []string{"example.com"}}}, "", "example.com.") {
		t.Fatal("a keyless policy entry must not match unsigned")
	}
	if !updatePolicyAllows(nil, "", "example.com.") {
		t.Fatal("no policies allows")
	}
}
