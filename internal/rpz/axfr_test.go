package rpz

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestPullAXFRNamesAndLoadPolicies(t *testing.T) {
	mux := dns.NewServeMux()
	mux.HandleFunc("block.test.", func(w dns.ResponseWriter, req *dns.Msg) {
		if len(req.Question) == 0 || req.Question[0].Qtype != dns.TypeAXFR {
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
		if n == "bad.block.test." {
			found = true
		}
		if n == "block.test." {
			t.Fatal("apex should be skipped")
		}
	}
	if !found {
		t.Fatalf("names=%v", names)
	}

	eng := New(true)
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
	hit, ok := eng.Lookup("bad.block.test.")
	if !ok || hit.Action != ActionNXDOMAIN {
		t.Fatalf("lookup: ok=%v hit=%+v", ok, hit)
	}

	_, err = eng.LoadPolicies([]PolicyConfig{{
		Name:    "redir",
		Format:  "axfr",
		Zone:    "block.test.",
		Masters: []string{addr},
		Action:  ActionRedirect,
		Target:  "127.0.0.9",
	}}, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	hit, ok = eng.Lookup("bad.block.test.")
	if !ok || hit.Action != ActionRedirect || hit.Target != "127.0.0.9" {
		t.Fatalf("redirect: %+v ok=%v", hit, ok)
	}
}
