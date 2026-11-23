package api

import (
	"context"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/blockcdb"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/rpz"
	"github.com/powersvx/powersvx/internal/server"
)

func TestMultiPolicyCDBPreservesUnchangedAXFRAndHostsFeeds(t *testing.T) {
	dir := t.TempDir()
	zone := "axfr-feed.test."

	// Start a mock SOA/AXFR server for the AXFR feed with fixed serial 100.
	mux := dns.NewServeMux()
	mux.HandleFunc(zone, func(w dns.ResponseWriter, req *dns.Msg) {
		soa := &dns.SOA{
			Hdr:    dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
			Ns:     "ns." + zone,
			Mbox:   "h." + zone,
			Serial: 100,
		}
		if len(req.Question) > 0 && req.Question[0].Qtype == dns.TypeSOA {
			m := new(dns.Msg)
			m.SetReply(req)
			m.Answer = []dns.RR{soa}
			_ = w.WriteMsg(m)
			return
		}
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeRefused)
		_ = w.WriteMsg(m)
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	udpSrv := &dns.Server{PacketConn: pc, Handler: mux}
	go func() { _ = udpSrv.ActivateAndServe() }()
	defer func() { _ = udpSrv.Shutdown() }()
	time.Sleep(30 * time.Millisecond)

	hostsFile := filepath.Join(dir, "local-hosts.txt")
	if err := os.WriteFile(hostsFile, []byte("0.0.0.0 custom-ad.example\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Pre-seed per-policy AXFR cache and state at serial 100 so SOA check skips cleanly.
	axfrCache := feedCachePath(dir, "trustpositifkominfo")
	if err := writeFeedFileAtomic(axfrCache, []string{"blocked-gambling.example"}); err != nil {
		t.Fatal(err)
	}
	st := rpz.LoadAxfrState(rpz.AxfrStatePath(dir))
	_ = st.PutSuccess("trustpositifkominfo", zone, "full_axfr", addr, 100, "seeded")
	// Ensure existing CDB exists (>0 entries in metadata).
	if _, _, err := blockcdb.SyncNames(dir, []string{"blocked-gambling.example"}); err != nil {
		t.Fatal(err)
	}

	a := &API{dataDir: dir, log: slog.Default(), srv: &server.Server{}}
	policies := []rpz.PolicyConfig{
		{
			Name:    "trustpositifkominfo",
			Format:  "axfr",
			Zone:    zone,
			Masters: []string{addr},
		},
		{
			Name:   "custom-hosts",
			Format: "hosts",
			Source: hostsFile,
		},
	}

	n, err := a.pullAndWriteBlockCDB(context.Background(), policies)
	if err != nil {
		t.Fatalf("pullAndWriteBlockCDB failed: %v", err)
	}
	if n != 2 {
		t.Fatalf("merged CDB entries=%d want 2", n)
	}
	mergedRaw, err := os.ReadFile(filepath.Join(blockcdb.Dir(dir), blockcdb.DomainsFile))
	if err != nil {
		t.Fatal(err)
	}
	merged := string(mergedRaw)
	if !strings.Contains(merged, "blocked-gambling.example") || !strings.Contains(merged, "custom-ad.example") {
		t.Fatalf("merged CDB missing preserved AXFR or hosts domain: %s", merged)
	}
}

func TestHandleRPZNotifyMasterAuthorization(t *testing.T) {
	cfg := &config.Config{
		RPZ: config.RPZConfig{
			Enabled: true,
			Policies: []config.RPZPolicyTOML{
				{
					Name:    "kominfo",
					Format:  "axfr",
					Zone:    "trustpositifkominfo.",
					Masters: []string{"192.0.2.50:53"},
				},
			},
		},
	}
	a := &API{cfg: cfg, srv: &server.Server{}}
	if !notifyMasterMatch("192.0.2.50", []string{"192.0.2.50:53"}) {
		t.Fatal("expected exact master IP to match")
	}
	if notifyMasterMatch("198.51.100.7", []string{"192.0.2.50:53"}) {
		t.Fatal("unexpected IP match")
	}
	// Unauthorized source without TSIG must be refused (false).
	if a.HandleRPZNotify("trustpositifkominfo.", "198.51.100.7", false) {
		t.Fatal("unauthorized NOTIFY must be refused")
	}
}
