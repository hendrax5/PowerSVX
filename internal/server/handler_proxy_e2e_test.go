package server

// End-to-end tests for the client address the Dataplane passes in a PROXY protocol v2
// header (ticket #36): views, GeoDNS, NOTIFY master checks and the allow lists judge the
// client the header names, a header is believed only from a loopback peer, and ECS is an
// extra GeoDNS input. The first group drives the handler with the address types the
// listeners produce; the second runs the real listeners on loopback sockets.

import (
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/proxyproto"
)

// proxiedWriter is a writer whose connection came from peer and whose PROXY header named client.
func proxiedWriter(client, peer string) *fakeWriter {
	c := netip.AddrPortFrom(netip.MustParseAddr(client), 40000)
	return &fakeWriter{remote: &proxyproto.Addr{
		AddrPort: c, Net: "udp",
		Peer: &net.UDPAddr{IP: net.ParseIP(peer), Port: 49200},
	}}
}

func (h *harness) askVia(w *fakeWriter, name string, qtype uint16, opts ...queryOpt) *dns.Msg {
	h.t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(name, qtype)
	for _, o := range opts {
		o(req)
	}
	h.srv.serveFromDataplane(w, req)
	if len(w.msgs) != 1 {
		h.t.Fatalf("%s: want exactly 1 reply, got %d", name, len(w.msgs))
	}
	return w.msgs[0]
}

func TestViewsFollowTheClientTheDataplaneNamesNotTheDataplane(t *testing.T) {
	h := newHarness(t, withViews(map[string][]string{"internal": {"10.0.0.0/8"}}))
	h.addZone(zoneName,
		authoritative.Record{Name: "app.example.com.", Type: dns.TypeA, TTL: 300, Content: "10.0.0.1", View: "internal"},
		authoritative.Record{Name: "app.example.com.", Type: dns.TypeA, TTL: 300, Content: "192.0.2.1", View: "default"},
	)
	for _, peer := range []string{"127.0.0.1", "::1"} {
		wantA(t, h.askVia(proxiedWriter("10.1.2.3", peer), "app.example.com.", dns.TypeA), "10.0.0.1")
		wantA(t, h.askVia(proxiedWriter("203.0.113.9", peer), "app.example.com.", dns.TypeA), "192.0.2.1")
		wantA(t, h.askVia(proxiedWriter("2001:db8::9", peer), "app.example.com.", dns.TypeA), "192.0.2.1")
	}
	// A plain query from the Dataplane (no header, a node mid-update) is judged on loopback.
	wantA(t, h.askVia(newWriter("127.0.0.1"), "app.example.com.", dns.TypeA), "192.0.2.1")
}

func TestGeoFollowsTheClientTheDataplaneNames(t *testing.T) {
	h := newHarness(t, withGeo(map[string]string{"198.51.100.20": "ID", "198.51.100.30": "US"}))
	h.addZone(zoneName,
		authoritative.Record{Name: "cdn.example.com.", Type: dns.TypeA, TTL: 300, Content: "192.0.2.100", GeoTag: "ID"},
		authoritative.Record{Name: "cdn.example.com.", Type: dns.TypeA, TTL: 300, Content: "192.0.2.200", GeoTag: "US"},
		authoritative.Record{Name: "cdn.example.com.", Type: dns.TypeA, TTL: 300, Content: "192.0.2.254", GeoTag: "default"},
	)
	wantA(t, h.askVia(proxiedWriter("198.51.100.20", "127.0.0.1"), "cdn.example.com.", dns.TypeA), "192.0.2.100")
	wantA(t, h.askVia(proxiedWriter("198.51.100.30", "127.0.0.1"), "cdn.example.com.", dns.TypeA), "192.0.2.200")
	wantA(t, h.askVia(proxiedWriter("203.0.113.9", "127.0.0.1"), "cdn.example.com.", dns.TypeA), "192.0.2.254")
}

func TestAHeaderNamingALoopbackClientFromAStrangerIsRefused(t *testing.T) {
	// If a header from a non-loopback peer ever reached the handler as an address, the peer
	// decides, not the client it names.
	h := newHarness(t)
	h.addZone(zoneName, rec("www.example.com.", dns.TypeA, "192.0.2.10"))
	w := proxiedWriter("127.0.0.1", "203.0.113.50")
	m := h.askVia(w, "www.example.com.", dns.TypeA)
	wantRcode(t, m, dns.RcodeRefused)
	if len(m.Answer) != 0 {
		t.Fatalf("a stranger got an answer: %v", m)
	}
}

func TestTransferAndUpdateAllowListsJudgeTheClientTheDataplaneNames(t *testing.T) {
	h := newHarness(t, withConfig(func(c *config.Config) {
		allowTransfer(c)
		c.Transfer.AllowFrom = []string{"198.51.100.0/24"}
		enableUpdate(c)
		c.Update.AllowFrom = []string{"198.51.100.0/24"}
	}))
	h.addZone(zoneName, rec("www.example.com.", dns.TypeA, "192.0.2.10"))

	// Both clients reach the handler from the same Dataplane on loopback.
	_, msgs := h.transfer(proxiedWriter("203.0.113.50", "127.0.0.1"), zoneName, dns.TypeAXFR, 0)
	if len(msgs) != 1 || msgs[0].Rcode != dns.RcodeRefused {
		t.Fatalf("AXFR from a client outside the list: want REFUSED, got %v", msgs)
	}
	rrs, _ := h.transfer(proxiedWriter("198.51.100.7", "127.0.0.1"), zoneName, dns.TypeAXFR, 0)
	if len(rrs) < 3 {
		t.Fatalf("AXFR from a client inside the list: want the zone, got %v", rrs)
	}

	add := []dns.RR{mustRR(t, "added.example.com. 120 IN A 192.0.2.77")}
	if got := h.send(proxiedWriter("203.0.113.9", "127.0.0.1"), updateReq(zoneName, nil, add)); len(got) != 1 || got[0].Rcode != dns.RcodeRefused {
		t.Fatalf("UPDATE from a client outside the list: want REFUSED, got %v", got)
	}
	if got := h.send(proxiedWriter("198.51.100.9", "127.0.0.1"), updateReq(zoneName, nil, add)); len(got) != 1 || got[0].Rcode != dns.RcodeSuccess {
		t.Fatalf("UPDATE from a client inside the list: want NOERROR, got %v", got)
	}
}

func TestNOTIFYMasterCheckJudgesTheClientTheDataplaneNames(t *testing.T) {
	h := secondaryHarness(t, "sec.test.", "198.51.100.7")
	msgs := h.send(proxiedWriter("198.51.100.7", "127.0.0.1"), notifyReq("sec.test.", false))
	if len(msgs) != 1 || msgs[0].Rcode != dns.RcodeSuccess {
		t.Fatalf("NOTIFY from the configured master: want NOERROR without TSIG, got %v", msgs)
	}
	msgs = h.send(proxiedWriter("203.0.113.66", "127.0.0.1"), notifyReq("sec.test.", false))
	if len(msgs) != 1 || msgs[0].Rcode != dns.RcodeRefused {
		t.Fatalf("NOTIFY from another host: want REFUSED, got %v", msgs)
	}
}

// ---- ECS as an additional GeoDNS input

func geoHarness(t *testing.T, opts ...option) *harness {
	t.Helper()
	opts = append([]option{withGeo(map[string]string{"198.51.100.20": "ID", "198.51.100.30": "US", "203.0.113.9": "US"})}, opts...)
	h := newHarness(t, opts...)
	h.addZone(zoneName,
		authoritative.Record{Name: "cdn.example.com.", Type: dns.TypeA, TTL: 300, Content: "192.0.2.100", GeoTag: "ID"},
		authoritative.Record{Name: "cdn.example.com.", Type: dns.TypeA, TTL: 300, Content: "192.0.2.200", GeoTag: "US"},
		authoritative.Record{Name: "cdn.example.com.", Type: dns.TypeA, TTL: 300, Content: "192.0.2.254", GeoTag: "default"},
	)
	return h
}

func ecsOf(m *dns.Msg) *dns.EDNS0_SUBNET {
	if o := m.IsEdns0(); o != nil {
		for _, op := range o.Option {
			if e, ok := op.(*dns.EDNS0_SUBNET); ok {
				return e
			}
		}
	}
	return nil
}

func TestGeoUsesTheClientSubnetOfAQueryFromTheDataplane(t *testing.T) {
	h := geoHarness(t)
	// The resolver at 198.51.100.30 (US) sends its end user's subnet, which is in ID.
	m := h.askVia(proxiedWriter("198.51.100.30", "127.0.0.1"), "cdn.example.com.", dns.TypeA, withECSOption("198.51.100.20/32"))
	wantA(t, m, "192.0.2.100")
	// The answer says which subnet it was chosen for, with the scope RFC 7871 asks for.
	e := ecsOf(m)
	if e == nil || e.SourceNetmask != 32 || e.SourceScope != 32 || e.Address.String() != "198.51.100.20" {
		t.Fatalf("want the ECS option echoed with scope 32, got %+v", e)
	}
	// Without ECS the client address decides.
	wantA(t, h.askVia(proxiedWriter("198.51.100.30", "127.0.0.1"), "cdn.example.com.", dns.TypeA), "192.0.2.200")
	if e := ecsOf(h.askVia(proxiedWriter("198.51.100.30", "127.0.0.1"), "cdn.example.com.", dns.TypeA, withDO())); e != nil {
		t.Fatalf("no ECS was sent, none may come back: %+v", e)
	}
	// A subnet of length 0 asks for no steering by it.
	wantA(t, h.askVia(proxiedWriter("198.51.100.30", "127.0.0.1"), "cdn.example.com.", dns.TypeA, withECSOption("0.0.0.0/0")), "192.0.2.200")
}

func TestGeoIgnoresTheClientSubnetFromAPeerThatIsNotTheDataplane(t *testing.T) {
	h := geoHarness(t)
	// ServeDNS is what serveFromDataplane calls after the loopback check; a peer that is not
	// loopback must not steer by ECS even when something calls it directly.
	req := new(dns.Msg)
	req.SetQuestion("cdn.example.com.", dns.TypeA)
	withECSOption("198.51.100.20/32")(req)
	w := proxiedWriter("198.51.100.30", "203.0.113.50")
	h.srv.ServeDNS(w, req)
	wantA(t, w.msgs[0], "192.0.2.200")
	if e := ecsOf(w.msgs[0]); e != nil {
		t.Fatalf("ECS echoed to an untrusted peer: %+v", e)
	}
}

func TestGeoIgnoresTheClientSubnetWhenConfiguredTo(t *testing.T) {
	h := geoHarness(t, withConfig(func(c *config.Config) { c.GeoDNS.IgnoreClientSubnet = true }))
	m := h.askVia(proxiedWriter("198.51.100.30", "127.0.0.1"), "cdn.example.com.", dns.TypeA, withECSOption("198.51.100.20/32"))
	wantA(t, m, "192.0.2.200")
	if e := ecsOf(m); e != nil {
		t.Fatalf("ignore_client_subnet set, none may be echoed: %+v", e)
	}
}

func TestViewsAreNeverChosenByTheClientSubnet(t *testing.T) {
	// A query can carry any ECS it likes; only the client address picks the view.
	h := newHarness(t, withViews(map[string][]string{"internal": {"10.0.0.0/8"}}))
	h.addZone(zoneName,
		authoritative.Record{Name: "app.example.com.", Type: dns.TypeA, TTL: 300, Content: "10.0.0.1", View: "internal"},
		authoritative.Record{Name: "app.example.com.", Type: dns.TypeA, TTL: 300, Content: "192.0.2.1", View: "default"},
	)
	m := h.askVia(proxiedWriter("203.0.113.9", "127.0.0.1"), "app.example.com.", dns.TypeA, withECSOption("10.1.2.0/24"))
	wantA(t, m, "192.0.2.1")
}

func TestMalformedClientSubnetIsIgnored(t *testing.T) {
	h := geoHarness(t)
	for name, e := range map[string]*dns.EDNS0_SUBNET{
		"unknown family":       {Code: dns.EDNS0SUBNET, Family: 3, SourceNetmask: 24, Address: net.IPv4(198, 51, 100, 20).To4()},
		"prefix beyond family": {Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 40, Address: net.IPv4(198, 51, 100, 20).To4()},
		"short address":        {Code: dns.EDNS0SUBNET, Family: 2, SourceNetmask: 56, Address: net.IP{0x20, 0x01}},
	} {
		req := new(dns.Msg)
		req.SetQuestion("cdn.example.com.", dns.TypeA)
		req.SetEdns0(1232, false)
		req.IsEdns0().Option = append(req.IsEdns0().Option, e)
		w := proxiedWriter("198.51.100.30", "127.0.0.1")
		h.srv.serveFromDataplane(w, req)
		if len(w.msgs) != 1 {
			t.Fatalf("%s: no reply", name)
		}
		wantA(t, w.msgs[0], "192.0.2.200")
	}
}

// ---- the real listeners

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback sockets:", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// startListeners runs the Auth Backend on 127.0.0.1 with the given proxy_protocol setting.
func startListeners(t *testing.T, mode string, opts ...option) (*harness, string) {
	t.Helper()
	port := freePort(t)
	opts = append(opts, withConfig(func(c *config.Config) {
		c.Server.BindAddress = "127.0.0.1"
		c.Server.UDPPort, c.Server.TCPPort = port, port
		c.Server.ProxyProtocol = mode
	}))
	h := newHarness(t, opts...)
	go func() { _ = h.srv.ListenAndServe() }()
	t.Cleanup(func() { _ = h.srv.Shutdown() })
	addr := net.JoinHostPort("127.0.0.1", itoa(port))
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the listeners did not come up on %s", addr)
		}
		time.Sleep(50 * time.Millisecond)
	}
	return h, addr
}

func itoa(n int) string { return strconv.Itoa(n) }

func hdr(client string, tr proxyproto.Transport) []byte {
	return proxyproto.Encode(proxyproto.Header{Transport: tr,
		Src: netip.AddrPortFrom(netip.MustParseAddr(client), 40000), Dst: netip.MustParseAddrPort("192.0.2.1:53")})
}

// udpExchange sends one datagram (header, then the DNS message) and returns the reply the
// sender's own socket receives, which is how dnsdist gets it.
func udpExchange(t *testing.T, addr string, header []byte, q *dns.Msg) (*dns.Msg, error) {
	t.Helper()
	wire, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write(append(append([]byte(nil), header...), wire...))
	_ = c.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	r := new(dns.Msg)
	return r, r.Unpack(buf[:n])
}

func TestListenersOverUDPAnswerTheClientTheHeaderNamesAndReplyToTheSender(t *testing.T) {
	for _, mode := range []string{"optional", "required"} {
		t.Run(mode, func(t *testing.T) {
			h, addr := startListeners(t, mode, withViews(map[string][]string{"internal": {"10.0.0.0/8"}}))
			h.addZone(zoneName,
				authoritative.Record{Name: "app.example.com.", Type: dns.TypeA, TTL: 300, Content: "10.0.0.1", View: "internal"},
				authoritative.Record{Name: "app.example.com.", Type: dns.TypeA, TTL: 300, Content: "192.0.2.1", View: "default"},
			)
			q := func() *dns.Msg { m := new(dns.Msg); m.SetQuestion("app.example.com.", dns.TypeA); return m }
			r, err := udpExchange(t, addr, hdr("10.1.2.3", proxyproto.Dgram), q())
			if err != nil {
				t.Fatal("no reply to the sender's socket:", err)
			}
			wantA(t, r, "10.0.0.1")
			r, err = udpExchange(t, addr, hdr("203.0.113.9", proxyproto.Dgram), q())
			if err != nil {
				t.Fatal(err)
			}
			wantA(t, r, "192.0.2.1")
			// A LOCAL header (dnsdist's health check) is answered as the Dataplane itself.
			r, err = udpExchange(t, addr, proxyproto.Encode(proxyproto.Header{Local: true}), q())
			if err != nil {
				t.Fatal(err)
			}
			wantA(t, r, "192.0.2.1")
		})
	}
}

func TestListenersPlainQueriesFromLoopbackDependOnTheMode(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("www.example.com.", dns.TypeA)

	h, addr := startListeners(t, "optional")
	h.addZone(zoneName, rec("www.example.com.", dns.TypeA, "192.0.2.10"))
	r, err := udpExchange(t, addr, nil, q)
	if err != nil {
		t.Fatal("optional: a node whose dnsdist sends no header must still be answered:", err)
	}
	wantA(t, r, "192.0.2.10")

	h, addr = startListeners(t, "required")
	h.addZone(zoneName, rec("www.example.com.", dns.TypeA, "192.0.2.10"))
	if r, err := udpExchange(t, addr, nil, q); err == nil {
		t.Fatalf("required: a plain datagram must be dropped, got %v", r)
	}
}

func TestListenersOffModeDoesNotLookAtHeaders(t *testing.T) {
	h, addr := startListeners(t, "off")
	h.addZone(zoneName, rec("www.example.com.", dns.TypeA, "192.0.2.10"))
	q := new(dns.Msg)
	q.SetQuestion("www.example.com.", dns.TypeA)
	r, err := udpExchange(t, addr, nil, q)
	if err != nil {
		t.Fatal(err)
	}
	wantA(t, r, "192.0.2.10")
	// A header in front of the message is not a DNS message.
	if r, err := udpExchange(t, addr, hdr("10.1.2.3", proxyproto.Dgram), q); err == nil && r.Rcode == dns.RcodeSuccess && len(r.Answer) > 0 {
		t.Fatalf("off: a header must not be understood, got %v", r)
	}
}

func TestListenersOverTCPUseTheClientTheHeaderNames(t *testing.T) {
	h, addr := startListeners(t, "required", withConfig(func(c *config.Config) {
		allowTransfer(c)
		c.Transfer.AllowFrom = []string{"198.51.100.0/24"}
	}))
	h.addZone(zoneName, rec("www.example.com.", dns.TypeA, "192.0.2.10"))

	axfr := func(client string) (int, int) {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err := c.Write(hdr(client, proxyproto.Stream)); err != nil {
			t.Fatal(err)
		}
		conn := &dns.Conn{Conn: c}
		q := new(dns.Msg)
		q.SetAxfr(zoneName)
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		if err := conn.WriteMsg(q); err != nil {
			t.Fatal(err)
		}
		records, rcode := 0, -1
		for {
			m, err := conn.ReadMsg()
			if err != nil {
				break
			}
			rcode = m.Rcode
			records += len(m.Answer)
			if m.Rcode != dns.RcodeSuccess || (records >= 2 && m.Answer[len(m.Answer)-1].Header().Rrtype == dns.TypeSOA) {
				break
			}
		}
		return records, rcode
	}
	if n, rcode := axfr("203.0.113.50"); rcode != dns.RcodeRefused || n != 0 {
		t.Fatalf("a client outside the allow list: want REFUSED, got rcode=%d records=%d", rcode, n)
	}
	if n, rcode := axfr("198.51.100.7"); rcode != dns.RcodeSuccess || n < 3 {
		t.Fatalf("a client inside the allow list: want the zone, got rcode=%d records=%d", rcode, n)
	}
}

func TestListenersOverTCPRefuseAConnectionWithoutAHeaderInRequiredMode(t *testing.T) {
	h, addr := startListeners(t, "required")
	h.addZone(zoneName, rec("www.example.com.", dns.TypeA, "192.0.2.10"))
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	conn := &dns.Conn{Conn: c}
	q := new(dns.Msg)
	q.SetQuestion("www.example.com.", dns.TypeA)
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	_ = conn.WriteMsg(q)
	if m, err := conn.ReadMsg(); err == nil {
		t.Fatalf("a headerless connection was answered: %v", m)
	}
}
