package rpz

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestQuerySOASerialHintWrongKomdigiZone(t *testing.T) {
	_, _, err := QuerySOASerial(context.Background(), "trustkominfo.", []string{"127.0.0.1:1"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "trustpositifkominfo") {
		t.Fatalf("want spelling hint, got %v", err)
	}
}

func TestRelativeOwner(t *testing.T) {
	rel, ok := relativeOwner("evil.com.trustpositifkominfo.", "trustpositifkominfo.")
	if !ok || rel != "evil.com." {
		t.Fatalf("got %q ok=%v", rel, ok)
	}
	rel, ok = relativeOwner("*.evil.com.trustpositifkominfo.", "trustpositifkominfo.")
	if !ok || rel != "*.evil.com." {
		t.Fatalf("wild got %q ok=%v", rel, ok)
	}
	if _, ok := relativeOwner("trustpositifkominfo.", "trustpositifkominfo."); ok {
		t.Fatal("apex should be false")
	}
	if _, ok := relativeOwner("other.example.", "trustpositifkominfo."); ok {
		t.Fatal("outside zone should be false")
	}
}

func TestParseIXFRDeltaAndFull(t *testing.T) {
	zone := "block.test."
	soaNew := &dns.SOA{
		Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns: "ns." + zone, Mbox: "h." + zone, Serial: 2,
	}
	soaOld := &dns.SOA{
		Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns: "ns." + zone, Mbox: "h." + zone, Serial: 1,
	}
	del := &dns.A{
		Hdr: dns.RR_Header{Name: "gone." + zone, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP("127.0.0.1").To4(),
	}
	add := &dns.A{
		Hdr: dns.RR_Header{Name: "new." + zone, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP("127.0.0.2").To4(),
	}
	res, err := parseIXFR(zone, 1, []dns.RR{soaNew, soaOld, del, soaNew, add, soaNew})
	if err != nil {
		t.Fatal(err)
	}
	if res.FullReplace || res.Serial != 2 {
		t.Fatalf("delta: %+v", res)
	}
	if len(res.Removed) != 1 || res.Removed[0] != "gone." {
		t.Fatalf("removed=%v", res.Removed)
	}
	if len(res.Added) != 1 || res.Added[0] != "new." {
		t.Fatalf("added=%v", res.Added)
	}

	// AXFR-style response to IXFR
	full := []dns.RR{
		soaNew,
		&dns.A{Hdr: dns.RR_Header{Name: "bad." + zone, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("127.0.0.1").To4()},
		soaNew,
	}
	res, err = parseIXFR(zone, 1, full)
	if err != nil {
		t.Fatal(err)
	}
	if !res.FullReplace || len(res.Names) != 1 || res.Names[0] != "bad." {
		t.Fatalf("full: %+v", res)
	}
}

func TestPullAXFRNamesAndLoadPolicies(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc("block.test.", func(w dns.ResponseWriter, req *dns.Msg) {
		if len(req.Question) == 0 {
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeRefused)
			_ = w.WriteMsg(m)
			return
		}
		zone := req.Question[0].Name
		soa := &dns.SOA{
			Hdr:     dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
			Ns:      "ns." + zone,
			Mbox:    "hostmaster." + zone,
			Serial:  7,
			Refresh: 3600,
			Retry:   600,
			Expire:  86400,
			Minttl:  60,
		}
		if req.Question[0].Qtype == dns.TypeSOA {
			m := new(dns.Msg)
			m.SetReply(req)
			m.Answer = []dns.RR{soa}
			_ = w.WriteMsg(m)
			return
		}
		if req.Question[0].Qtype != dns.TypeAXFR && req.Question[0].Qtype != dns.TypeIXFR {
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeRefused)
			_ = w.WriteMsg(m)
			return
		}
		ns := &dns.NS{
			Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
			Ns:  "ns." + zone,
		}
		a := &dns.A{
			Hdr: dns.RR_Header{Name: "bad." + zone, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("127.0.0.1").To4(),
		}
		ch := make(chan *dns.Envelope)
		go func() {
			ch <- &dns.Envelope{RR: []dns.RR{soa, ns, a, soa}}
			close(ch)
		}()
		tr := new(dns.Transfer)
		_ = tr.Out(w, req, ch)
	})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpLn, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		_ = pc.Close()
		t.Fatal(err)
	}
	addr := tcpLn.Addr().String()
	udpSrv := &dns.Server{PacketConn: pc, Handler: mux}
	tcpSrv := &dns.Server{Listener: tcpLn, Handler: mux}
	go func() { _ = udpSrv.ActivateAndServe() }()
	go func() { _ = tcpSrv.ActivateAndServe() }()
	defer func() {
		_ = udpSrv.Shutdown()
		_ = tcpSrv.Shutdown()
	}()
	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	names, serial, err := PullAXFRNames(ctx, "block.test.", []string{addr})
	if err != nil {
		t.Fatal(err)
	}
	if serial != 7 {
		t.Fatalf("serial=%d", serial)
	}
	found := false
	for _, n := range names {
		if n == "bad." {
			found = true
		}
		if n == "block.test." || n == "bad.block.test." {
			t.Fatalf("unexpected name %q", n)
		}
	}
	if !found {
		t.Fatalf("names=%v", names)
	}

	dir := t.TempDir()
	eng := New(true)
	if err := eng.OpenDisk(dir); err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	eng.SetAxfrState(LoadAxfrState(AxfrStatePath(dir)))

	n, err := eng.LoadPolicies([]PolicyConfig{{
		Name:    "kominfo-axfr",
		Format:  "axfr",
		Zone:    "block.test.",
		Masters: []string{addr},
		Action:  ActionNXDOMAIN,
	}}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatalf("entries=%d", n)
	}
	hit, ok := eng.Lookup("bad.")
	if !ok || hit.Action != ActionNXDOMAIN {
		t.Fatalf("lookup: ok=%v hit=%+v", ok, hit)
	}

	// SOA unchanged → RefreshAXFR skips transfer
	n2, err := eng.RefreshAXFR([]PolicyConfig{{
		Name:    "kominfo-axfr",
		Format:  "axfr",
		Zone:    "block.test.",
		Masters: []string{addr},
		Action:  ActionNXDOMAIN,
	}}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if n2 < 1 {
		t.Fatalf("refresh entries=%d", n2)
	}
}
