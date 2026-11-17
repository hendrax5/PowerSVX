package secondary

import (
	"context"
	"encoding/base64"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/tsig"
)

func TestUpsertListDeletePersist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secondary-zones.json")
	auth := authoritative.NewStore()
	m := New(path, auth, nil)

	if err := m.Upsert(Zone{Name: "Slave.Example.com", Masters: []string{"10.0.0.1"}}); err != nil {
		t.Fatal(err)
	}
	list := m.List()
	if len(list) != 1 || list[0].Name != "slave.example.com." || list[0].Masters[0] != "10.0.0.1:53" {
		t.Fatalf("list=%+v", list)
	}
	if !m.Has("slave.example.com") {
		t.Fatal("Has expected true")
	}

	m2 := New(path, auth, nil)
	if err := m2.Load(); err != nil {
		t.Fatal(err)
	}
	if len(m2.List()) != 1 {
		t.Fatalf("reload got %d", len(m2.List()))
	}
	if !m2.Delete("slave.example.com") {
		t.Fatal("delete failed")
	}
	if m2.Has("slave.example.com") {
		t.Fatal("still present")
	}
}

func TestNormalizeRejectsEmptyMasters(t *testing.T) {
	_, err := normalizeZones([]Zone{{Name: "a.example", Masters: nil}})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestHandleNotifyUnknown(t *testing.T) {
	m := New("", authoritative.NewStore(), nil)
	if m.HandleNotify("unknown.example") {
		t.Fatal("unknown should not trigger")
	}
}

func TestHandleNotifyFromAuthorization(t *testing.T) {
	dir := t.TempDir()
	m := New(filepath.Join(dir, "secondary-zones.json"), authoritative.NewStore(), nil)
	if err := m.Upsert(Zone{Name: "slave.example.", Masters: []string{"192.0.2.10:53"}}); err != nil {
		t.Fatal(err)
	}
	if m.HandleNotifyFrom("slave.example.", "198.51.100.99", false) {
		t.Fatal("spoofed client IP without TSIG must be rejected")
	}
	if !m.HandleNotifyFrom("slave.example.", "192.0.2.10", false) {
		t.Fatal("authorized master IP should be accepted")
	}
	if !m.HandleNotifyFrom("slave.example.", "198.51.100.99", true) {
		t.Fatal("valid TSIG should authorize NOTIFY even from secondary NAT IP")
	}
}

type mockMasterState struct {
	mu          sync.Mutex
	serial      uint32
	records     []dns.RR
	requireTSIG bool
	refuseIXFR  bool
	axfrCalls   int
	ixfrCalls   int
}

func startMockMaster(t *testing.T, zone string, tsigSecret map[string]string, st *mockMasterState) (string, func()) {
	t.Helper()
	mux := dns.NewServeMux()
	mux.HandleFunc(zone, func(w dns.ResponseWriter, req *dns.Msg) {
		if len(req.Question) == 0 {
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeRefused)
			_ = w.WriteMsg(m)
			return
		}
		if st.requireTSIG && (req.IsTsig() == nil || w.TsigStatus() != nil) {
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeRefused)
			_ = w.WriteMsg(m)
			return
		}
		q := req.Question[0]
		st.mu.Lock()
		curSerial := st.serial
		recs := append([]dns.RR(nil), st.records...)
		refuseIXFR := st.refuseIXFR
		st.mu.Unlock()

		soa := func(serial uint32) *dns.SOA {
			return &dns.SOA{
				Hdr:     dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
				Ns:      "ns1." + zone,
				Mbox:    "hostmaster." + zone,
				Serial:  serial,
				Refresh: 900,
				Retry:   120,
				Expire:  604800,
				Minttl:  60,
			}
		}

		switch q.Qtype {
		case dns.TypeSOA:
			m := new(dns.Msg)
			m.SetReply(req)
			m.Answer = []dns.RR{soa(curSerial)}
			if req.IsTsig() != nil {
				m.SetTsig(req.IsTsig().Hdr.Name, dns.HmacSHA256, 300, time.Now().Unix())
			}
			_ = w.WriteMsg(m)
		case dns.TypeIXFR:
			if refuseIXFR {
				m := new(dns.Msg)
				m.SetRcode(req, dns.RcodeNotImplemented)
				_ = w.WriteMsg(m)
				return
			}
			st.mu.Lock()
			st.ixfrCalls++
			st.mu.Unlock()

			var clientSerial uint32
			if len(req.Ns) > 0 {
				if csoa, ok := req.Ns[0].(*dns.SOA); ok {
					clientSerial = csoa.Serial
				}
			}
			tr := new(dns.Transfer)
			ch := make(chan *dns.Envelope)
			go func() {
				if clientSerial == curSerial {
					ch <- &dns.Envelope{RR: []dns.RR{soa(curSerial)}}
				} else {
					// Delta from clientSerial -> curSerial: delete old.example., add new.example.
					delA := &dns.A{
						Hdr: dns.RR_Header{Name: "old." + zone, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
						A:   net.ParseIP("192.0.2.10").To4(),
					}
					addA := &dns.A{
						Hdr: dns.RR_Header{Name: "new." + zone, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
						A:   net.ParseIP("192.0.2.20").To4(),
					}
					ch <- &dns.Envelope{RR: []dns.RR{soa(curSerial), soa(clientSerial), delA, soa(curSerial), addA, soa(curSerial)}}
				}
				close(ch)
			}()
			_ = tr.Out(w, req, ch)
		case dns.TypeAXFR:
			st.mu.Lock()
			st.axfrCalls++
			st.mu.Unlock()
			tr := new(dns.Transfer)
			ch := make(chan *dns.Envelope)
			go func() {
				out := make([]dns.RR, 0, len(recs)+2)
				out = append(out, soa(curSerial))
				out = append(out, recs...)
				out = append(out, soa(curSerial))
				ch <- &dns.Envelope{RR: out}
				close(ch)
			}()
			_ = tr.Out(w, req, ch)
		default:
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeRefused)
			_ = w.WriteMsg(m)
		}
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
	udpSrv := &dns.Server{PacketConn: pc, Handler: mux, TsigSecret: tsigSecret}
	tcpSrv := &dns.Server{Listener: tcpLn, Handler: mux, TsigSecret: tsigSecret}
	go func() { _ = udpSrv.ActivateAndServe() }()
	go func() { _ = tcpSrv.ActivateAndServe() }()
	time.Sleep(40 * time.Millisecond)

	return addr, func() {
		_ = udpSrv.Shutdown()
		_ = tcpSrv.Shutdown()
	}
}

func TestSecondarySOASkipIXFRFallbackTSIGAndDiskRestore(t *testing.T) {
	zone := "isp-slave.test."
	secret := base64.StdEncoding.EncodeToString([]byte("super-secret-tsig-key-material"))
	tsigStore := tsig.New()
	if err := tsigStore.Set("slave-tsig.", secret); err != nil {
		t.Fatal(err)
	}

	st := &mockMasterState{
		serial:      10,
		requireTSIG: true,
		records: []dns.RR{
			&dns.NS{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "ns1." + zone},
			&dns.A{Hdr: dns.RR_Header{Name: "old." + zone, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("192.0.2.10").To4()},
			&dns.A{Hdr: dns.RR_Header{Name: "keep." + zone, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("192.0.2.11").To4()},
		},
	}
	addr, stopMaster := startMockMaster(t, zone, map[string]string{"slave-tsig.": secret}, st)
	defer stopMaster()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secondary-zones.json")
	auth := authoritative.NewStore()
	m := New(cfgPath, auth, nil)
	m.SetTSIGStore(tsigStore)

	var changes []string
	var changeMu sync.Mutex
	m.SetOnChange(func(z string) {
		changeMu.Lock()
		changes = append(changes, z)
		changeMu.Unlock()
	})

	// Missing TSIG key first must fail because requireTSIG=true.
	if err := m.Upsert(Zone{Name: zone, Masters: []string{addr}}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := m.Transfer(ctx, zone); err == nil {
		t.Fatal("expected error without TSIG key")
	}

	// Configure matching TSIG key -> initial AXFR succeeds.
	if err := m.Upsert(Zone{Name: zone, Masters: []string{addr}, TSIGKey: "slave-tsig"}); err != nil {
		t.Fatal(err)
	}
	if err := m.Transfer(ctx, zone); err != nil {
		t.Fatalf("initial TSIG AXFR failed: %v", err)
	}

	list := m.List()
	if len(list) != 1 || list[0].Serial != 10 || list[0].LastMode != "axfr" || list[0].SOARefresh != 900 || list[0].SOARetry != 120 || list[0].SOAExpire != 604800 {
		t.Fatalf("unexpected metadata after AXFR: %+v", list)
	}
	if got := auth.CurrentSOASerial(zone); got != 10 {
		t.Fatalf("auth serial=%d want 10", got)
	}
	if ans, ok := auth.Lookup("old."+zone, dns.TypeA); !ok || len(ans) != 1 {
		t.Fatalf("expected old.%s after AXFR, got ok=%v len=%d", zone, ok, len(ans))
	}

	// Reboot simulation: new Manager + empty authoritative store loads zone records from disk cache!
	auth2 := authoritative.NewStore()
	m2 := New(cfgPath, auth2, nil)
	m2.SetTSIGStore(tsigStore)
	if err := m2.Load(); err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	if got := auth2.CurrentSOASerial(zone); got != 10 {
		t.Fatalf("restored auth serial=%d want 10", got)
	}
	if ans, ok := auth2.Lookup("old."+zone, dns.TypeA); !ok || len(ans) != 1 {
		t.Fatalf("expected disk-restored old.%s", zone)
	}

	// Transfer with same SOA serial -> must skip without invoking AXFR or IXFR.
	axfrBefore, ixfrBefore := st.axfrCalls, st.ixfrCalls
	if err := m2.Transfer(ctx, zone); err != nil {
		t.Fatalf("SOA-unchanged transfer err: %v", err)
	}
	if st.axfrCalls != axfrBefore || st.ixfrCalls != ixfrBefore {
		t.Fatalf("expected SOA precheck skip, axfr=%d->%d ixfr=%d->%d", axfrBefore, st.axfrCalls, ixfrBefore, st.ixfrCalls)
	}
	if m2.List()[0].LastMode != "skipped" {
		t.Fatalf("expected LastMode=skipped, got %q", m2.List()[0].LastMode)
	}

	// Bump serial on master to 11 -> must use RFC 1995 IXFR delta (delete old., add new., preserve keep.).
	st.mu.Lock()
	st.serial = 11
	st.mu.Unlock()
	if err := m2.Transfer(ctx, zone); err != nil {
		t.Fatalf("IXFR failed: %v", err)
	}
	if m2.List()[0].LastMode != "ixfr" || m2.List()[0].Serial != 11 {
		t.Fatalf("expected ixfr serial 11, got %+v", m2.List()[0])
	}
	if ans, ok := auth2.Lookup("old."+zone, dns.TypeA); ok && len(ans) > 0 {
		t.Fatalf("expected old.%s deleted by IXFR", zone)
	}
	if ans, ok := auth2.Lookup("new."+zone, dns.TypeA); !ok || len(ans) != 1 {
		t.Fatalf("expected new.%s added by IXFR", zone)
	}
	if ans, ok := auth2.Lookup("keep."+zone, dns.TypeA); !ok || len(ans) != 1 {
		t.Fatalf("expected keep.%s preserved by IXFR", zone)
	}

	// Bump serial to 12 and disable IXFR on master -> must fall back cleanly to AXFR.
	st.mu.Lock()
	st.serial = 12
	st.refuseIXFR = true
	st.records = append(st.records, &dns.A{
		Hdr: dns.RR_Header{Name: "fallback." + zone, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("192.0.2.30").To4(),
	})
	st.mu.Unlock()
	if err := m2.Transfer(ctx, zone); err != nil {
		t.Fatalf("AXFR fallback failed: %v", err)
	}
	if m2.List()[0].LastMode != "axfr" || m2.List()[0].Serial != 12 {
		t.Fatalf("expected axfr fallback serial 12, got %+v", m2.List()[0])
	}
	if ans, ok := auth2.Lookup("fallback."+zone, dns.TypeA); !ok || len(ans) != 1 {
		t.Fatalf("expected fallback.%s from AXFR fallback", zone)
	}

	changeMu.Lock()
	nChanges := len(changes)
	changeMu.Unlock()
	if nChanges == 0 {
		t.Fatal("expected SetOnChange callback to fire")
	}
}
