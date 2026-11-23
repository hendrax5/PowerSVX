package server

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/config"
)

// These tests drive the handler over a real loopback TCP listener with TSIG
// keys loaded, so the TSIG status the handler sees is the one the DNS library
// computes for a request: nil for no TSIG record, nil for a verified one,
// non-nil for a failed one.

const xferKey = "xfer-key."

func tsigHarness(t *testing.T, requireXfer, requireUpdate bool) (*harness, string) {
	t.Helper()
	h := newHarness(t, withTSIG(xferKey, tsigSecret), withConfig(func(c *config.Config) {
		c.Transfer.AllowAXFR = true
		c.Transfer.RequireTSIG = requireXfer
		c.Update.Enabled = true
		c.Update.RequireTSIG = requireUpdate
	}))
	h.addZone(zoneName, rec("www.example.com.", dns.TypeA, "192.0.2.10"))
	return h, startTCPWithProductionAccept(t, h.srv)
}

func pullIXFR(addr, zone string, serial uint32, keyName, secret string) ([]dns.RR, error) {
	m := new(dns.Msg)
	m.SetIxfr(zone, serial, "ns1."+zone, "hostmaster."+zone)
	tr := &dns.Transfer{DialTimeout: 2 * time.Second, ReadTimeout: 2 * time.Second}
	if keyName != "" {
		tr.TsigSecret = map[string]string{keyName: secret}
		m.SetTsig(keyName, dns.HmacSHA256, 300, time.Now().Unix())
	}
	env, err := tr.In(m, addr)
	if err != nil {
		return nil, err
	}
	var rrs []dns.RR
	for e := range env {
		if e.Error != nil {
			return rrs, e.Error
		}
		rrs = append(rrs, e.RR...)
	}
	return rrs, nil
}

func sendUpdateTCP(t *testing.T, addr string, keyName, secret string) *dns.Msg {
	t.Helper()
	m := updateReq(zoneName, nil, []dns.RR{mustRR(t, "added.example.com. 120 IN A 192.0.2.77")})
	c := &dns.Client{Net: "tcp", Timeout: 2 * time.Second}
	if keyName != "" {
		c.TsigSecret = map[string]string{keyName: secret}
		m.SetTsig(keyName, dns.HmacSHA256, 300, time.Now().Unix())
	}
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("update exchange: %v", err)
	}
	return r
}

func TestUnsignedAXFRIsRefusedWhenTSIGIsRequired(t *testing.T) {
	_, addr := tsigHarness(t, true, true)
	rrs, err := pullAXFR(addr, zoneName, "", "")
	if err == nil {
		t.Fatalf("unsigned AXFR must not succeed, got %v", rrs)
	}
	if len(rrsOfType(rrs, dns.TypeA)) != 0 {
		t.Fatalf("unsigned AXFR leaked zone data: %v", rrs)
	}
}

func TestUnsignedAXFRRepliesRefusedWhenTSIGIsRequired(t *testing.T) {
	h, _ := tsigHarness(t, true, true)
	_, msgs := h.transfer(newWriter(anyClientIP), zoneName, dns.TypeAXFR, 0)
	if len(msgs) != 1 || msgs[0].Rcode != dns.RcodeRefused || len(msgs[0].Answer) != 0 {
		t.Fatalf("want a lone REFUSED, got %v", msgs)
	}
}

func TestUnsignedIXFRIsRefusedWhenTSIGIsRequired(t *testing.T) {
	h, addr := tsigHarness(t, true, true)
	h.auth.AddRecord(zoneName, rec("new.example.com.", dns.TypeA, "192.0.2.55"))
	rrs, err := pullIXFR(addr, zoneName, 1, "", "")
	if err == nil {
		t.Fatalf("unsigned IXFR must not succeed, got %v", rrs)
	}
	if len(rrsOfType(rrs, dns.TypeA)) != 0 {
		t.Fatalf("unsigned IXFR leaked zone data: %v", rrs)
	}
	_, msgs := h.transfer(newWriter(anyClientIP), zoneName, dns.TypeIXFR, 1)
	if len(msgs) != 1 || msgs[0].Rcode != dns.RcodeRefused {
		t.Fatalf("want a lone REFUSED, got %v", msgs)
	}
}

func TestSignedAXFRSucceedsWhenTSIGIsRequired(t *testing.T) {
	_, addr := tsigHarness(t, true, true)
	rrs, err := pullAXFR(addr, zoneName, xferKey, tsigSecret)
	if err != nil {
		t.Fatalf("signed AXFR failed: %v", err)
	}
	if len(rrsOfType(rrs, dns.TypeA)) != 1 || len(soaSerials(rrs)) != 2 {
		t.Fatalf("signed AXFR content wrong: %v", rrs)
	}
}

func TestSignedIXFRSucceedsWhenTSIGIsRequired(t *testing.T) {
	h, addr := tsigHarness(t, true, true)
	start := h.auth.CurrentSOASerial(zoneName)
	h.auth.AddRecord(zoneName, rec("new.example.com.", dns.TypeA, "192.0.2.55"))
	rrs, err := pullIXFR(addr, zoneName, start, xferKey, tsigSecret)
	if err != nil {
		t.Fatalf("signed IXFR failed: %v", err)
	}
	as := rrsOfType(rrs, dns.TypeA)
	if len(as) != 1 || as[0].(*dns.A).A.String() != "192.0.2.55" {
		t.Fatalf("signed IXFR should carry the added A record, got %v", as)
	}
}

func TestAXFRAndIXFRSignedWithTheWrongKeyFailWhenTSIGIsRequired(t *testing.T) {
	_, addr := tsigHarness(t, true, true)
	if _, err := pullAXFR(addr, zoneName, "other-key.", tsigSecret); err == nil {
		t.Fatal("AXFR signed with an unknown key must not succeed")
	}
	if _, err := pullAXFR(addr, zoneName, xferKey, "d3Jvbmctd3Jvbmctd3Jvbmc="); err == nil {
		t.Fatal("AXFR signed with the wrong secret must not succeed")
	}
	if _, err := pullIXFR(addr, zoneName, 1, "other-key.", tsigSecret); err == nil {
		t.Fatal("IXFR signed with an unknown key must not succeed")
	}
}

func TestUnsignedAXFRAndIXFRAreServedWhenTSIGIsNotRequired(t *testing.T) {
	_, addr := tsigHarness(t, false, false)
	rrs, err := pullAXFR(addr, zoneName, "", "")
	if err != nil || len(rrsOfType(rrs, dns.TypeA)) != 1 {
		t.Fatalf("unsigned AXFR with the requirement off: rrs=%v err=%v", rrs, err)
	}
	rrs, err = pullIXFR(addr, zoneName, 1, "", "")
	if err != nil || len(rrsOfType(rrs, dns.TypeA)) != 1 {
		t.Fatalf("unsigned IXFR with the requirement off: rrs=%v err=%v", rrs, err)
	}
}

func TestUnsignedDynamicUpdateIsRefusedWhenTSIGIsRequired(t *testing.T) {
	h, addr := tsigHarness(t, true, true)
	r := sendUpdateTCP(t, addr, "", "")
	if r.Rcode != dns.RcodeRefused {
		t.Fatalf("want REFUSED, got %s", dns.RcodeToString[r.Rcode])
	}
	wantRcode(t, h.q("added.example.com.", dns.TypeA), dns.RcodeNameError)
}

func TestSignedDynamicUpdateIsAppliedWhenTSIGIsRequired(t *testing.T) {
	h, addr := tsigHarness(t, true, true)
	r := sendUpdateTCP(t, addr, xferKey, tsigSecret)
	if r.Rcode != dns.RcodeSuccess {
		t.Fatalf("want NOERROR, got %s", dns.RcodeToString[r.Rcode])
	}
	wantA(t, h.q("added.example.com.", dns.TypeA), "192.0.2.77")
}

func TestDynamicUpdateSignedWithTheWrongKeyIsNotAppliedWhenTSIGIsRequired(t *testing.T) {
	h, addr := tsigHarness(t, true, true)
	r := sendUpdateTCP(t, addr, "other-key.", tsigSecret)
	if r.Rcode == dns.RcodeSuccess {
		t.Fatal("update signed with an unknown key must not succeed")
	}
	wantRcode(t, h.q("added.example.com.", dns.TypeA), dns.RcodeNameError)
}

func TestUnsignedDynamicUpdateIsAppliedWhenTSIGIsNotRequired(t *testing.T) {
	h, addr := tsigHarness(t, false, false)
	r := sendUpdateTCP(t, addr, "", "")
	if r.Rcode != dns.RcodeSuccess {
		t.Fatalf("want NOERROR, got %s", dns.RcodeToString[r.Rcode])
	}
	wantA(t, h.q("added.example.com.", dns.TypeA), "192.0.2.77")
}

func TestTSIGRequirementsForTransferAndUpdateAreIndependent(t *testing.T) {
	_, addr := tsigHarness(t, true, false)
	if _, err := pullAXFR(addr, zoneName, "", ""); err == nil {
		t.Fatal("unsigned AXFR must fail when only the transfer requirement is on")
	}
	if r := sendUpdateTCP(t, addr, "", ""); r.Rcode != dns.RcodeSuccess {
		t.Fatalf("unsigned update must pass when the update requirement is off, got %s", dns.RcodeToString[r.Rcode])
	}
	_, addr = tsigHarness(t, false, true)
	if rrs, err := pullAXFR(addr, zoneName, "", ""); err != nil || len(rrsOfType(rrs, dns.TypeA)) != 1 {
		t.Fatalf("unsigned AXFR must pass when the transfer requirement is off: %v %v", rrs, err)
	}
	if r := sendUpdateTCP(t, addr, "", ""); r.Rcode != dns.RcodeRefused {
		t.Fatalf("unsigned update must be refused when only the update requirement is on, got %s", dns.RcodeToString[r.Rcode])
	}
}

// startTCPWithProductionAccept is startTCP with the message accept function
// ListenAndServe uses, which (unlike miekg's default) lets UPDATE through.
func startTCPWithProductionAccept(t *testing.T, s *Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{Listener: ln, Net: "tcp", Handler: dns.HandlerFunc(s.ServeDNS), TsigSecret: s.tsig.Map(), MsgAcceptFunc: msgAcceptFunc}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown() })
	return ln.Addr().String()
}
