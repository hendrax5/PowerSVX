package resolver

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/config"
)

func TestLoadShedSkipsRecursiveToForward(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	addr := pc.LocalAddr().String()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			req := new(dns.Msg)
			if err := req.Unpack(buf[:n]); err != nil {
				continue
			}
			resp := new(dns.Msg)
			resp.SetReply(req)
			if len(req.Question) > 0 && req.Question[0].Qtype == dns.TypeA {
				rr, _ := dns.NewRR(req.Question[0].Name + " 60 IN A 9.9.9.9")
				resp.Answer = []dns.RR{rr}
			}
			out, _ := resp.Pack()
			_, _ = pc.WriteTo(out, from)
		}
	}()

	r := New(config.ResolverConfig{
		Mode:              "recursive",
		ForwardOnFail:     true,
		Forwarders:        []string{addr},
		TimeoutMS:         2000,
		FallbackTimeoutMS: 500,
		MaxInflight:       4,
	})
	r.inflight.Store(3)

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	msg, path, err := r.ResolveWithECS(ctx, req, nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if path != "fallback" {
		t.Fatalf("want path fallback under load-shed, got %q", path)
	}
	if msg == nil || len(msg.Answer) == 0 {
		t.Fatal("expected answer from forwarder")
	}
}
