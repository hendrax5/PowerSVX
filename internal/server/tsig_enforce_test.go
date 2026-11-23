package server

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/config"
)

// tsigWriter is a dns.ResponseWriter whose TSIG verification result is set by the test.
// A nil tsigErr mirrors miekg/dns for both "no TSIG record" and "TSIG verified".
type tsigWriter struct {
	tsigErr error
	msgs    []*dns.Msg
}

func (w *tsigWriter) LocalAddr() net.Addr  { return &net.TCPAddr{IP: net.IPv4zero} }
func (w *tsigWriter) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 5300} }
func (w *tsigWriter) WriteMsg(m *dns.Msg) error {
	w.msgs = append(w.msgs, m)
	return nil
}
func (w *tsigWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *tsigWriter) Close() error                { return nil }
func (w *tsigWriter) TsigStatus() error           { return w.tsigErr }
func (w *tsigWriter) TsigTimersOnly(bool)         {}
func (w *tsigWriter) Hijack()                     {}

func (w *tsigWriter) rcode() int {
	if len(w.msgs) == 0 {
		return -1
	}
	return w.msgs[0].Rcode
}

func tsigTestServer(t *testing.T, requireXfer, requireUpdate bool) *Server {
	t.Helper()
	cfg := config.Default()
	cfg.Transfer.AllowAXFR = true
	cfg.Transfer.AllowFrom = []string{"192.0.2.0/24"}
	cfg.Transfer.RequireTSIG = requireXfer
	cfg.Update.Enabled = true
	cfg.Update.AllowFrom = []string{"192.0.2.0/24"}
	cfg.Update.RequireTSIG = requireUpdate
	auth := authoritative.NewStore()
	auth.UpsertZone("example.com.")
	auth.AddRecord("example.com.", authoritative.Record{
		Name: "example.com.", Type: dns.TypeSOA, TTL: 60,
		Content: "ns.example.com. hostmaster.example.com. 1 3600 600 86400 60",
	})
	auth.AddRecord("example.com.", authoritative.Record{
		Name: "www.example.com.", Type: dns.TypeA, TTL: 60, Content: "192.0.2.1",
	})
	return New(cfg, Deps{Auth: auth}, nil)
}

func signed(m *dns.Msg) *dns.Msg {
	m.SetTsig("key.example.com.", dns.HmacSHA256, 300, time.Now().Unix())
	return m
}

func xferReq(qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	if qtype == dns.TypeIXFR {
		m.SetIxfr("example.com.", 0, "ns.example.com.", "hostmaster.example.com.")
	} else {
		m.SetAxfr("example.com.")
	}
	return m
}

func updateReq() *dns.Msg {
	m := new(dns.Msg)
	m.SetUpdate("example.com.")
	rr, _ := dns.NewRR("evil.example.com. 300 IN A 192.0.2.66")
	m.Insert([]dns.RR{rr})
	return m
}

func TestTransferRequireTSIG(t *testing.T) {
	for _, qt := range []uint16{dns.TypeAXFR, dns.TypeIXFR} {
		name := dns.TypeToString[qt]
		t.Run(name+"/unsigned refused", func(t *testing.T) {
			s := tsigTestServer(t, true, true)
			w := &tsigWriter{}
			if !s.handleTransfer(w, xferReq(qt), "192.0.2.10") {
				t.Fatal("not handled")
			}
			if len(w.msgs) != 1 || w.rcode() != dns.RcodeRefused {
				t.Fatalf("unsigned %s: msgs=%d rcode=%d want one REFUSED", name, len(w.msgs), w.rcode())
			}
		})
		t.Run(name+"/bad signature notauth", func(t *testing.T) {
			s := tsigTestServer(t, true, true)
			w := &tsigWriter{tsigErr: dns.ErrSig}
			s.handleTransfer(w, signed(xferReq(qt)), "192.0.2.10")
			if len(w.msgs) != 1 || w.rcode() != dns.RcodeNotAuth {
				t.Fatalf("bad sig %s: msgs=%d rcode=%d want one NOTAUTH", name, len(w.msgs), w.rcode())
			}
		})
		t.Run(name+"/valid signature served", func(t *testing.T) {
			s := tsigTestServer(t, true, true)
			w := &tsigWriter{}
			s.handleTransfer(w, signed(xferReq(qt)), "192.0.2.10")
			if len(w.msgs) == 0 || w.rcode() != dns.RcodeSuccess || len(w.msgs[0].Answer) < 2 {
				t.Fatalf("valid %s: not served (msgs=%d rcode=%d)", name, len(w.msgs), w.rcode())
			}
		})
		t.Run(name+"/requirement off unchanged", func(t *testing.T) {
			s := tsigTestServer(t, false, false)
			w := &tsigWriter{}
			s.handleTransfer(w, xferReq(qt), "192.0.2.10")
			if len(w.msgs) == 0 || w.rcode() != dns.RcodeSuccess || len(w.msgs[0].Answer) < 2 {
				t.Fatalf("off %s: unsigned not served (msgs=%d rcode=%d)", name, len(w.msgs), w.rcode())
			}
		})
	}
}

func TestUpdateRequireTSIG(t *testing.T) {
	t.Run("unsigned refused and not applied", func(t *testing.T) {
		s := tsigTestServer(t, true, true)
		w := &tsigWriter{}
		s.handleUpdate(w, updateReq(), "192.0.2.10")
		if w.rcode() != dns.RcodeRefused {
			t.Fatalf("rcode=%d want REFUSED", w.rcode())
		}
		if s.auth.RRSetExists("example.com.", "evil.example.com.", dns.TypeA) {
			t.Fatal("unsigned update was applied")
		}
	})
	t.Run("bad signature notauth", func(t *testing.T) {
		s := tsigTestServer(t, true, true)
		w := &tsigWriter{tsigErr: dns.ErrSig}
		s.handleUpdate(w, signed(updateReq()), "192.0.2.10")
		if w.rcode() != dns.RcodeNotAuth {
			t.Fatalf("rcode=%d want NOTAUTH", w.rcode())
		}
		if s.auth.RRSetExists("example.com.", "evil.example.com.", dns.TypeA) {
			t.Fatal("badly signed update was applied")
		}
	})
	t.Run("valid signature applied", func(t *testing.T) {
		s := tsigTestServer(t, true, true)
		w := &tsigWriter{}
		s.handleUpdate(w, signed(updateReq()), "192.0.2.10")
		if w.rcode() != dns.RcodeSuccess || !s.auth.RRSetExists("example.com.", "evil.example.com.", dns.TypeA) {
			t.Fatalf("valid update not applied (rcode=%d)", w.rcode())
		}
	})
	t.Run("requirement off unchanged", func(t *testing.T) {
		s := tsigTestServer(t, false, false)
		w := &tsigWriter{}
		s.handleUpdate(w, updateReq(), "192.0.2.10")
		if w.rcode() != dns.RcodeSuccess || !s.auth.RRSetExists("example.com.", "evil.example.com.", dns.TypeA) {
			t.Fatalf("off: unsigned update not applied (rcode=%d)", w.rcode())
		}
	})
}
