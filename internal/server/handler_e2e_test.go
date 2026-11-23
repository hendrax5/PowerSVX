package server

// End-to-end tests for the query handler (ServeDNS). Every test sends DNS
// messages in and asserts on the DNS messages that come out; none looks at
// handler internals. They describe the Auth Backend: authoritative answers,
// refusal of everything else, and refusal of non-local sources.

import (
	"context"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/authoritative"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/dnssec"
	"github.com/powersvx/powersvx/internal/geo"
	"github.com/powersvx/powersvx/internal/secondary"
	"github.com/powersvx/powersvx/internal/tsig"
	"github.com/powersvx/powersvx/internal/view"
)

const (
	zoneName    = "example.com."
	soaContent  = "ns1.example.com. hostmaster.example.com. 10 3600 600 86400 300"
	anyClientIP = "203.0.113.9"
)

// ---------------------------------------------------------------- harness

// fakeWriter is a dns.ResponseWriter that keeps every message written to it,
// whether the handler used WriteMsg or Write (wire bytes).
type fakeWriter struct {
	remote  net.Addr
	tsigErr error
	msgs    []*dns.Msg
}

func newWriter(clientIP string) *fakeWriter {
	return &fakeWriter{remote: &net.UDPAddr{IP: net.ParseIP(clientIP), Port: 40000}}
}

func (w *fakeWriter) LocalAddr() net.Addr  { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53} }
func (w *fakeWriter) RemoteAddr() net.Addr { return w.remote }
func (w *fakeWriter) WriteMsg(m *dns.Msg) error {
	w.msgs = append(w.msgs, m.Copy())
	return nil
}
func (w *fakeWriter) Write(b []byte) (int, error) {
	m := new(dns.Msg)
	if err := m.Unpack(b); err != nil {
		return 0, err
	}
	w.msgs = append(w.msgs, m)
	return len(b), nil
}
func (w *fakeWriter) Close() error        { return nil }
func (w *fakeWriter) TsigStatus() error   { return w.tsigErr }
func (w *fakeWriter) TsigTimersOnly(bool) {}
func (w *fakeWriter) Hijack()             {}

type harness struct {
	t      *testing.T
	srv    *Server
	auth   *authoritative.Store
	cfg    *config.Config
	signer *dnssec.Signer
}

type option func(*harness, *Deps)

func withSigner() option {
	return func(h *harness, d *Deps) {
		h.signer = dnssec.NewSigner(h.t.TempDir())
		d.Signer = h.signer
	}
}

func withViews(named map[string][]string) option {
	return func(h *harness, d *Deps) { d.Views = view.FromConfig(true, "default", named) }
}

func withGeo(overrides map[string]string) option {
	return func(h *harness, d *Deps) {
		g, err := geo.New(true, "", "default")
		if err != nil {
			h.t.Fatal(err)
		}
		for ip, country := range overrides {
			g.SetOverride(ip, geo.Info{Country: country})
		}
		d.Geo = g
	}
}

func withTSIG(name, secret string) option {
	return func(h *harness, d *Deps) {
		st := tsig.New()
		if err := st.Set(name, secret); err != nil {
			h.t.Fatal(err)
		}
		d.TSIG = st
	}
}

func withECS() option {
	return func(h *harness, d *Deps) { h.cfg.Resolver.ECSEnabled = true }
}

func withConfig(fn func(*config.Config)) option {
	return func(h *harness, d *Deps) { fn(h.cfg) }
}

func newHarness(t *testing.T, opts ...option) *harness {
	t.Helper()
	cfg := config.Default()
	auth := authoritative.NewStore()
	h := &harness{t: t, auth: auth, cfg: cfg}
	d := Deps{
		Auth:  auth,
	}
	for _, o := range opts {
		o(h, &d)
	}
	h.srv = New(cfg, d, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return h
}

// addZone creates a zone with an SOA and the given records.
func (h *harness) addZone(zone string, recs ...authoritative.Record) {
	h.t.Helper()
	h.auth.UpsertZone(zone)
	h.auth.AddRecord(zone, authoritative.Record{Name: zone, Type: dns.TypeSOA, TTL: 300, Content: strings.Replace(soaContent, "example.com.", strings.TrimSuffix(zone, ".")+".", -1)})
	for _, r := range recs {
		h.auth.AddRecord(zone, r)
	}
	if h.signer != nil {
		if err := h.signer.Ensure(zone); err != nil {
			h.t.Fatal(err)
		}
	}
}

func rec(name string, typ uint16, content string) authoritative.Record {
	return authoritative.Record{Name: name, Type: typ, TTL: 300, Content: content}
}

type queryOpt func(*dns.Msg)

func withDO() queryOpt { return func(m *dns.Msg) { m.SetEdns0(4096, true) } }

func withECSOption(cidr string) queryOpt {
	return func(m *dns.Msg) {
		ip, n, _ := net.ParseCIDR(cidr)
		ones, _ := n.Mask.Size()
		opt := m.IsEdns0()
		if opt == nil {
			m.SetEdns0(1232, false)
			opt = m.IsEdns0()
		}
		opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
			Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: uint8(ones), Address: ip.To4(),
		})
	}
}

// ask sends one query from clientIP and returns the single reply.
func (h *harness) ask(clientIP, name string, qtype uint16, opts ...queryOpt) *dns.Msg {
	h.t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(name, qtype)
	for _, o := range opts {
		o(req)
	}
	w := newWriter(clientIP)
	h.srv.ServeDNS(w, req)
	if len(w.msgs) != 1 {
		h.t.Fatalf("%s %s: want exactly 1 reply, got %d", name, dns.TypeToString[qtype], len(w.msgs))
	}
	return w.msgs[0]
}

func (h *harness) q(name string, qtype uint16, opts ...queryOpt) *dns.Msg {
	h.t.Helper()
	return h.ask(anyClientIP, name, qtype, opts...)
}

// send runs an arbitrary request and returns everything written.
func (h *harness) send(w *fakeWriter, req *dns.Msg) []*dns.Msg {
	h.srv.ServeDNS(w, req)
	return w.msgs
}

func rrsOfType(rrs []dns.RR, typ uint16) []dns.RR {
	var out []dns.RR
	for _, rr := range rrs {
		if rr.Header().Rrtype == typ {
			out = append(out, rr)
		}
	}
	return out
}

func answerA(t *testing.T, m *dns.Msg) []string {
	t.Helper()
	var out []string
	for _, rr := range m.Answer {
		if a, ok := rr.(*dns.A); ok {
			out = append(out, a.A.String())
		}
	}
	return out
}

func wantRcode(t *testing.T, m *dns.Msg, want int) {
	t.Helper()
	if m.Rcode != want {
		t.Fatalf("rcode=%s want %s", dns.RcodeToString[m.Rcode], dns.RcodeToString[want])
	}
}

func wantSOAInAuthority(t *testing.T, m *dns.Msg, zone string) {
	t.Helper()
	soas := rrsOfType(m.Ns, dns.TypeSOA)
	if len(soas) != 1 {
		t.Fatalf("want 1 SOA in authority, got %d (%v)", len(soas), m.Ns)
	}
	if soas[0].Header().Name != zone {
		t.Fatalf("authority SOA owner=%s want %s", soas[0].Header().Name, zone)
	}
}

func wantA(t *testing.T, m *dns.Msg, want ...string) {
	t.Helper()
	got := answerA(t, m)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("A answers=%v want %v", got, want)
	}
}

// ------------------------------------------------- authoritative answers

func TestAnswersAuthoritativelyForExistingNameAndType(t *testing.T) {
	h := newHarness(t)
	h.addZone(zoneName,
		rec("www.example.com.", dns.TypeA, "192.0.2.10"),
		rec("www.example.com.", dns.TypeAAAA, "2001:db8::10"),
		rec("example.com.", dns.TypeMX, "mail.example.com."),
		rec("example.com.", dns.TypeNS, "ns1.example.com."),
		rec("example.com.", dns.TypeTXT, "v=spf1 -all"),
	)

	m := h.q("www.example.com.", dns.TypeA)
	wantRcode(t, m, dns.RcodeSuccess)
	if !m.Authoritative {
		t.Fatal("AA bit not set on an authoritative answer")
	}
	wantA(t, m, "192.0.2.10")

	m = h.q("www.example.com.", dns.TypeAAAA)
	if len(m.Answer) != 1 || m.Answer[0].(*dns.AAAA).AAAA.String() != "2001:db8::10" {
		t.Fatalf("AAAA answer wrong: %v", m.Answer)
	}

	m = h.q("example.com.", dns.TypeMX)
	if mx, ok := m.Answer[0].(*dns.MX); !ok || mx.Mx != "mail.example.com." {
		t.Fatalf("MX answer wrong: %v", m.Answer)
	}

	m = h.q("example.com.", dns.TypeSOA)
	if len(m.Answer) != 1 || m.Answer[0].(*dns.SOA).Ns != "ns1.example.com." {
		t.Fatalf("SOA answer wrong: %v", m.Answer)
	}

	m = h.q("example.com.", dns.TypeTXT)
	if txt, ok := m.Answer[0].(*dns.TXT); !ok || strings.Join(txt.Txt, "") != "v=spf1 -all" {
		t.Fatalf("TXT answer wrong: %v", m.Answer)
	}
}

func TestAnswersWithAllAddressesOfARecordSet(t *testing.T) {
	h := newHarness(t)
	h.addZone(zoneName,
		rec("multi.example.com.", dns.TypeA, "192.0.2.1"),
		rec("multi.example.com.", dns.TypeA, "192.0.2.2"),
	)
	m := h.q("multi.example.com.", dns.TypeA)
	if got := answerA(t, m); len(got) != 2 {
		t.Fatalf("want both addresses, got %v", got)
	}
}

func TestMatchesQueryNamesCaseInsensitively(t *testing.T) {
	h := newHarness(t)
	h.addZone(zoneName, rec("www.example.com.", dns.TypeA, "192.0.2.10"))
	wantA(t, h.q("WWW.Example.COM.", dns.TypeA), "192.0.2.10")
}

func TestAnswersCNAMEWhenCNAMEIsAsked(t *testing.T) {
	h := newHarness(t)
	h.addZone(zoneName,
		rec("alias.example.com.", dns.TypeCNAME, "www.example.com."),
		rec("www.example.com.", dns.TypeA, "192.0.2.10"),
	)
	m := h.q("alias.example.com.", dns.TypeCNAME)
	wantRcode(t, m, dns.RcodeSuccess)
	if len(m.Answer) != 1 {
		t.Fatalf("answer=%v", m.Answer)
	}
	if c, ok := m.Answer[0].(*dns.CNAME); !ok || c.Target != "www.example.com." {
		t.Fatalf("CNAME answer wrong: %v", m.Answer)
	}
}

func TestAnswersWildcardRecordForNameWithoutOwnRecord(t *testing.T) {
	h := newHarness(t)
	h.addZone(zoneName,
		rec("*.example.com.", dns.TypeA, "192.0.2.99"),
		rec("www.example.com.", dns.TypeA, "192.0.2.10"),
	)
	m := h.q("anything.example.com.", dns.TypeA)
	wantRcode(t, m, dns.RcodeSuccess)
	wantA(t, m, "192.0.2.99")
	if got := h.q("www.example.com.", dns.TypeA); len(got.Answer) == 0 {
		t.Fatal("explicit record not answered next to a wildcard")
	}
}

func TestAnswersNXDOMAINWithZoneSOAForMissingNameInHostedZone(t *testing.T) {
	h := newHarness(t)
	h.addZone(zoneName, rec("www.example.com.", dns.TypeA, "192.0.2.10"))
	m := h.q("missing.example.com.", dns.TypeA)
	wantRcode(t, m, dns.RcodeNameError)
	if !m.Authoritative {
		t.Fatal("AA bit not set on NXDOMAIN")
	}
	if len(m.Answer) != 0 {
		t.Fatalf("NXDOMAIN carries answers: %v", m.Answer)
	}
	wantSOAInAuthority(t, m, zoneName)
}

func TestAnswersNODATAWithZoneSOAForExistingNameWithoutThatType(t *testing.T) {
	h := newHarness(t)
	h.addZone(zoneName, rec("www.example.com.", dns.TypeA, "192.0.2.10"))
	m := h.q("www.example.com.", dns.TypeAAAA)
	wantRcode(t, m, dns.RcodeSuccess)
	if len(m.Answer) != 0 {
		t.Fatalf("NODATA carries answers: %v", m.Answer)
	}
	wantSOAInAuthority(t, m, zoneName)
}

func TestAnswersFromTheMostSpecificZoneWhenZonesAreNested(t *testing.T) {
	h := newHarness(t)
	h.addZone(zoneName, rec("www.example.com.", dns.TypeA, "192.0.2.10"))
	h.addZone("sub.example.com.", rec("host.sub.example.com.", dns.TypeA, "192.0.2.77"))
	wantA(t, h.q("host.sub.example.com.", dns.TypeA), "192.0.2.77")
	m := h.q("nothere.sub.example.com.", dns.TypeA)
	wantRcode(t, m, dns.RcodeNameError)
	wantSOAInAuthority(t, m, "sub.example.com.")
}

func TestRefusesNamesOutsideEveryZone(t *testing.T) {
	// The Auth Backend does not resolve: a name no hosted zone covers is refused.
	h := newHarness(t)
	h.addZone(zoneName, rec("www.example.com.", dns.TypeA, "192.0.2.10"))
	m := h.q("elsewhere.test.", dns.TypeA)
	wantRcode(t, m, dns.RcodeRefused)
	if m.Authoritative {
		t.Fatal("AA bit set on a name outside every hosted zone")
	}
	if len(m.Answer) != 0 {
		t.Fatalf("answers on a refused query: %v", m.Answer)
	}
}

func TestRefusesNamesThatOnlyShareATextSuffixWithAZone(t *testing.T) {
	// badexample.com. ends with the characters of example.com. but is not below it.
	h := newHarness(t)
	h.addZone(zoneName, rec("www.example.com.", dns.TypeA, "192.0.2.10"))
	for _, name := range []string{"badexample.com.", "www.badexample.com.", "example.com.evil.net."} {
		m := h.q(name, dns.TypeA)
		wantRcode(t, m, dns.RcodeRefused)
		if m.Authoritative {
			t.Fatalf("%s: AA bit set on a name outside every hosted zone", name)
		}
	}
	// A real child of the zone is still answered from it.
	wantRcode(t, h.q("missing.example.com.", dns.TypeA), dns.RcodeNameError)
}

func TestRefusesRecursionDesiredQueriesOutsideEveryZone(t *testing.T) {
	h := newHarness(t)
	h.addZone(zoneName, rec("www.example.com.", dns.TypeA, "192.0.2.10"))
	m := h.q("www.google.com.", dns.TypeAAAA)
	wantRcode(t, m, dns.RcodeRefused)
	if m.RecursionAvailable {
		t.Fatal("RA set: this process does not recurse")
	}
}

func TestQueriesFromANonLocalSourceAreRefusedBeforeAnyProcessing(t *testing.T) {
	h := newHarness(t)
	h.addZone(zoneName, rec("www.example.com.", dns.TypeA, "192.0.2.10"))
	for _, src := range []string{"203.0.113.9", "10.1.2.3", "2001:db8::1", "192.168.1.1"} {
		req := new(dns.Msg)
		req.SetQuestion("www.example.com.", dns.TypeA) // a hosted name, answerable if it were processed
		w := newWriter(src)
		h.srv.serveFromDataplane(w, req)
		if len(w.msgs) != 1 {
			t.Fatalf("%s: want 1 reply, got %d", src, len(w.msgs))
		}
		wantRcode(t, w.msgs[0], dns.RcodeRefused)
		if len(w.msgs[0].Answer) != 0 || w.msgs[0].Authoritative {
			t.Fatalf("%s: a non-local source got an authoritative answer: %v", src, w.msgs[0])
		}
	}
	if q, _ := h.srv.Stats(); q != 0 {
		t.Fatalf("a refused non-local query was counted as processed (%d)", q)
	}
}

func TestQueriesFromLoopbackAreAnswered(t *testing.T) {
	h := newHarness(t)
	h.addZone(zoneName, rec("www.example.com.", dns.TypeA, "192.0.2.10"))
	for _, src := range []string{"127.0.0.1", "127.0.0.53", "::1"} {
		req := new(dns.Msg)
		req.SetQuestion("www.example.com.", dns.TypeA)
		w := newWriter(src)
		h.srv.serveFromDataplane(w, req)
		if len(w.msgs) != 1 {
			t.Fatalf("%s: want 1 reply, got %d", src, len(w.msgs))
		}
		wantRcode(t, w.msgs[0], dns.RcodeSuccess)
		wantA(t, w.msgs[0], "192.0.2.10")
	}
}

func TestAListenerOnLoopbackRefusesNothingFromTheDataplaneAndAnswersOverTheWire(t *testing.T) {
	h := newHarness(t)
	h.addZone(zoneName, rec("www.example.com.", dns.TypeA, "192.0.2.10"))
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(h.srv.serveFromDataplane)}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	defer func() { _ = srv.Shutdown() }()

	req := new(dns.Msg)
	req.SetQuestion("www.example.com.", dns.TypeA)
	in, _, err := (&dns.Client{Timeout: 2 * time.Second}).Exchange(req, pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	wantA(t, in, "192.0.2.10")
	req = new(dns.Msg)
	req.SetQuestion("elsewhere.test.", dns.TypeA)
	in, _, err = (&dns.Client{Timeout: 2 * time.Second}).Exchange(req, pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	wantRcode(t, in, dns.RcodeRefused)
}

func TestAnswersFORMERRForAQueryWithoutQuestion(t *testing.T) {
	h := newHarness(t)
	req := new(dns.Msg)
	req.Id = 7
	w := newWriter(anyClientIP)
	msgs := h.send(w, req)
	if len(msgs) != 1 || msgs[0].Rcode != dns.RcodeFormatError {
		t.Fatalf("want one FORMERR, got %v", msgs)
	}
}

func TestEchoesQueryIDAndQuestion(t *testing.T) {
	h := newHarness(t)
	h.addZone(zoneName, rec("www.example.com.", dns.TypeA, "192.0.2.10"))
	req := new(dns.Msg)
	req.SetQuestion("www.example.com.", dns.TypeA)
	req.Id = 0x4242
	w := newWriter(anyClientIP)
	msgs := h.send(w, req)
	if msgs[0].Id != 0x4242 || len(msgs[0].Question) != 1 || msgs[0].Question[0].Name != "www.example.com." {
		t.Fatalf("id/question not echoed: %v", msgs[0])
	}
	if !msgs[0].Response {
		t.Fatal("QR bit not set")
	}
}

// ---------------------------------------------------------------- DNSSEC

func verifyRRSIG(t *testing.T, rrs []dns.RR, typ uint16, keys []dns.RR) {
	t.Helper()
	var covered []dns.RR
	for _, rr := range rrs {
		if rr.Header().Rrtype == typ {
			covered = append(covered, rr)
		}
	}
	if len(covered) == 0 {
		t.Fatalf("no %s RRset in section", dns.TypeToString[typ])
	}
	for _, rr := range rrs {
		sig, ok := rr.(*dns.RRSIG)
		if !ok || sig.TypeCovered != typ {
			continue
		}
		for _, k := range keys {
			key, ok := k.(*dns.DNSKEY)
			if !ok || key.KeyTag() != sig.KeyTag {
				continue
			}
			if err := sig.Verify(key, covered); err != nil {
				t.Fatalf("RRSIG over %s does not verify: %v", dns.TypeToString[typ], err)
			}
			if !sig.ValidityPeriod(time.Now()) {
				t.Fatalf("RRSIG over %s outside validity period", dns.TypeToString[typ])
			}
			return
		}
	}
	t.Fatalf("no verifiable RRSIG for %s", dns.TypeToString[typ])
}

func TestSignedZoneReturnsVerifiableRRSIGWhenDNSSECOKIsSet(t *testing.T) {
	h := newHarness(t, withSigner())
	h.addZone(zoneName, rec("www.example.com.", dns.TypeA, "192.0.2.10"))
	keys := h.signer.DNSKEYs(zoneName)

	m := h.q("www.example.com.", dns.TypeA, withDO())
	wantRcode(t, m, dns.RcodeSuccess)
	wantA(t, m, "192.0.2.10")
	verifyRRSIG(t, m.Answer, dns.TypeA, keys)
	if opt := m.IsEdns0(); opt == nil || !opt.Do() {
		t.Fatal("reply to a DO query must carry EDNS with DO")
	}
}

func TestSignedZoneOmitsRRSIGWhenDNSSECOKIsNotSet(t *testing.T) {
	h := newHarness(t, withSigner())
	h.addZone(zoneName, rec("www.example.com.", dns.TypeA, "192.0.2.10"))
	m := h.q("www.example.com.", dns.TypeA)
	wantA(t, m, "192.0.2.10")
	if sigs := rrsOfType(m.Answer, dns.TypeRRSIG); len(sigs) != 0 {
		t.Fatalf("RRSIG without DO: %v", sigs)
	}
}

func TestUnsignedZoneReturnsNoRRSIGEvenWithDNSSECOK(t *testing.T) {
	h := newHarness(t, withSigner())
	h.addZone(zoneName, rec("www.example.com.", dns.TypeA, "192.0.2.10"))
	// A second zone the signer was never asked to sign.
	h.signer = nil
	h.auth.UpsertZone("plain.test.")
	h.auth.AddRecord("plain.test.", authoritative.Record{Name: "plain.test.", Type: dns.TypeSOA, TTL: 300, Content: "ns1.plain.test. h.plain.test. 1 3600 600 86400 300"})
	h.auth.AddRecord("plain.test.", rec("www.plain.test.", dns.TypeA, "192.0.2.20"))
	m := h.q("www.plain.test.", dns.TypeA, withDO())
	wantA(t, m, "192.0.2.20")
	if sigs := rrsOfType(m.Answer, dns.TypeRRSIG); len(sigs) != 0 {
		t.Fatalf("RRSIG from an unsigned zone: %v", sigs)
	}
}

func TestSignedZoneAnswersDNSKEYWithSignatureFromTheKeySigningKey(t *testing.T) {
	h := newHarness(t, withSigner())
	h.addZone(zoneName, rec("www.example.com.", dns.TypeA, "192.0.2.10"))
	m := h.q("example.com.", dns.TypeDNSKEY, withDO())
	wantRcode(t, m, dns.RcodeSuccess)
	if got := len(rrsOfType(m.Answer, dns.TypeDNSKEY)); got != 2 {
		t.Fatalf("want ZSK and KSK, got %d DNSKEY", got)
	}
	verifyRRSIG(t, m.Answer, dns.TypeDNSKEY, h.signer.DNSKEYs(zoneName))
}

func TestSignedZoneNXDOMAINHasNoDenialRecordsWithoutDNSSECOK(t *testing.T) {
	h := newHarness(t, withSigner())
	h.addZone(zoneName, rec("www.example.com.", dns.TypeA, "192.0.2.10"))
	m := h.q("missing.example.com.", dns.TypeA)
	wantRcode(t, m, dns.RcodeNameError)
	if len(rrsOfType(m.Ns, dns.TypeNSEC))+len(rrsOfType(m.Ns, dns.TypeRRSIG)) != 0 {
		t.Fatalf("denial records without DO: %v", m.Ns)
	}
}

// ---------------------------------------------------------- zone transfer

// transfer runs an AXFR or IXFR through the handler and returns every RR sent
// across all messages, or the single non-transfer reply.
func (h *harness) transfer(w *fakeWriter, zone string, qtype uint16, clientSerial uint32) ([]dns.RR, []*dns.Msg) {
	req := new(dns.Msg)
	if qtype == dns.TypeIXFR {
		req.SetIxfr(zone, clientSerial, "ns1."+zone, "hostmaster."+zone)
	} else {
		req.SetAxfr(zone)
	}
	msgs := h.send(w, req)
	var rrs []dns.RR
	for _, m := range msgs {
		rrs = append(rrs, m.Answer...)
	}
	return rrs, msgs
}

func allowTransfer(c *config.Config) {
	c.Transfer.AllowAXFR = true
	c.Transfer.RequireTSIG = false
}

func soaSerials(rrs []dns.RR) []uint32 {
	var out []uint32
	for _, rr := range rrs {
		if s, ok := rr.(*dns.SOA); ok {
			out = append(out, s.Serial)
		}
	}
	return out
}

func TestAXFRSendsWholeZoneBetweenTwoCopiesOfTheSOA(t *testing.T) {
	h := newHarness(t, withConfig(allowTransfer))
	h.addZone(zoneName,
		rec("www.example.com.", dns.TypeA, "192.0.2.10"),
		rec("example.com.", dns.TypeNS, "ns1.example.com."),
	)
	rrs, _ := h.transfer(newWriter(anyClientIP), zoneName, dns.TypeAXFR, 0)
	if len(rrs) < 4 {
		t.Fatalf("want SOA, records, SOA; got %v", rrs)
	}
	if _, ok := rrs[0].(*dns.SOA); !ok {
		t.Fatalf("first RR is %T, want SOA", rrs[0])
	}
	if _, ok := rrs[len(rrs)-1].(*dns.SOA); !ok {
		t.Fatalf("last RR is %T, want SOA", rrs[len(rrs)-1])
	}
	if len(rrsOfType(rrs, dns.TypeA)) != 1 || len(rrsOfType(rrs, dns.TypeNS)) != 1 {
		t.Fatalf("zone contents missing from transfer: %v", rrs)
	}
}

func TestAXFRIsRefusedWhenTransfersAreNotEnabled(t *testing.T) {
	h := newHarness(t) // defaults: allow_axfr = false
	h.addZone(zoneName, rec("www.example.com.", dns.TypeA, "192.0.2.10"))
	_, msgs := h.transfer(newWriter(anyClientIP), zoneName, dns.TypeAXFR, 0)
	if len(msgs) != 1 || msgs[0].Rcode != dns.RcodeRefused || len(msgs[0].Answer) != 0 {
		t.Fatalf("want a lone REFUSED, got %v", msgs)
	}
}

func TestAXFRIsRefusedForClientsOutsideTheAllowList(t *testing.T) {
	h := newHarness(t, withConfig(func(c *config.Config) {
		allowTransfer(c)
		c.Transfer.AllowFrom = []string{"198.51.100.0/24"}
	}))
	h.addZone(zoneName, rec("www.example.com.", dns.TypeA, "192.0.2.10"))

	_, msgs := h.transfer(newWriter("203.0.113.50"), zoneName, dns.TypeAXFR, 0)
	if len(msgs) != 1 || msgs[0].Rcode != dns.RcodeRefused {
		t.Fatalf("outside the allow list: want REFUSED, got %v", msgs)
	}
	rrs, _ := h.transfer(newWriter("198.51.100.7"), zoneName, dns.TypeAXFR, 0)
	if len(rrs) < 3 {
		t.Fatalf("inside the allow list: want the zone, got %v", rrs)
	}
}

func TestAXFRIsNotAuthorisedWhenTSIGIsRequiredAndTheSignatureFailed(t *testing.T) {
	h := newHarness(t, withConfig(func(c *config.Config) {
		c.Transfer.AllowAXFR = true
		c.Transfer.RequireTSIG = true
	}))
	h.addZone(zoneName, rec("www.example.com.", dns.TypeA, "192.0.2.10"))
	w := newWriter(anyClientIP)
	w.tsigErr = dns.ErrSig
	_, msgs := h.transfer(w, zoneName, dns.TypeAXFR, 0)
	if len(msgs) != 1 || msgs[0].Rcode != dns.RcodeNotAuth {
		t.Fatalf("want NOTAUTH, got %v", msgs)
	}
}

func TestAXFRForUnknownZoneAnswersNXDOMAIN(t *testing.T) {
	h := newHarness(t, withConfig(allowTransfer))
	h.addZone(zoneName)
	_, msgs := h.transfer(newWriter(anyClientIP), "nozone.test.", dns.TypeAXFR, 0)
	if len(msgs) != 1 || msgs[0].Rcode != dns.RcodeNameError {
		t.Fatalf("want NXDOMAIN, got %v", msgs)
	}
}

func TestIXFRSendsOnlyChangesSinceTheClientSerial(t *testing.T) {
	h := newHarness(t, withConfig(allowTransfer))
	h.addZone(zoneName, rec("www.example.com.", dns.TypeA, "192.0.2.10"))
	start := h.auth.CurrentSOASerial(zoneName)
	h.auth.AddRecord(zoneName, rec("new.example.com.", dns.TypeA, "192.0.2.55"))
	end := h.auth.CurrentSOASerial(zoneName)
	if end <= start {
		t.Fatalf("serial did not advance: %d -> %d", start, end)
	}

	rrs, _ := h.transfer(newWriter(anyClientIP), zoneName, dns.TypeIXFR, start)
	serials := soaSerials(rrs)
	if len(serials) != 4 || serials[0] != end || serials[1] != start || serials[2] != end || serials[3] != end {
		t.Fatalf("IXFR SOA framing = %v, want [%d %d %d %d]", serials, end, start, end, end)
	}
	as := rrsOfType(rrs, dns.TypeA)
	if len(as) != 1 || as[0].(*dns.A).A.String() != "192.0.2.55" {
		t.Fatalf("IXFR should carry only the added A record, got %v", as)
	}
}

func TestIXFRForAnUpToDateClientSendsOnlyTheSOA(t *testing.T) {
	h := newHarness(t, withConfig(allowTransfer))
	h.addZone(zoneName, rec("www.example.com.", dns.TypeA, "192.0.2.10"))
	cur := h.auth.CurrentSOASerial(zoneName)
	rrs, _ := h.transfer(newWriter(anyClientIP), zoneName, dns.TypeIXFR, cur)
	if len(rrs) != 1 {
		t.Fatalf("want a lone SOA, got %v", rrs)
	}
	if s, ok := rrs[0].(*dns.SOA); !ok || s.Serial != cur {
		t.Fatalf("want SOA serial %d, got %v", cur, rrs[0])
	}
}

func TestIXFRFallsBackToFullZoneWhenClientSerialIsNotInTheHistory(t *testing.T) {
	h := newHarness(t, withConfig(allowTransfer))
	h.addZone(zoneName, rec("www.example.com.", dns.TypeA, "192.0.2.10"))
	rrs, _ := h.transfer(newWriter(anyClientIP), zoneName, dns.TypeIXFR, 1)
	if len(rrsOfType(rrs, dns.TypeA)) != 1 || len(soaSerials(rrs)) != 2 {
		t.Fatalf("want a full-zone transfer, got %v", rrs)
	}
}

// startTCP serves the handler on a loopback TCP port with TSIG keys loaded, the
// way ListenAndServe does, and returns the address.
func startTCP(t *testing.T, s *Server, secrets map[string]string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{Listener: ln, Net: "tcp", Handler: dns.HandlerFunc(s.ServeDNS), TsigSecret: secrets}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = srv.Shutdown() })
	return ln.Addr().String()
}

const tsigSecret = "c2VjcmV0LXNlY3JldC1zZWNyZXQ=" // base64("secret-secret-secret")

func pullAXFR(addr, zone, keyName, secret string) ([]dns.RR, error) {
	m := new(dns.Msg)
	m.SetAxfr(zone)
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

func TestAXFRWithRequiredTSIGSucceedsOverTCPWithTheRightKeyAndFailsWithAnUnknownKey(t *testing.T) {
	h := newHarness(t, withTSIG("xfer-key.", tsigSecret), withConfig(func(c *config.Config) {
		c.Transfer.AllowAXFR = true
		c.Transfer.RequireTSIG = true
	}))
	h.addZone(zoneName, rec("www.example.com.", dns.TypeA, "192.0.2.10"))
	addr := startTCP(t, h.srv, h.srv.tsig.Map())

	rrs, err := pullAXFR(addr, zoneName, "xfer-key.", tsigSecret)
	if err != nil {
		t.Fatalf("signed AXFR failed: %v", err)
	}
	if len(rrsOfType(rrs, dns.TypeA)) != 1 || len(soaSerials(rrs)) != 2 {
		t.Fatalf("signed AXFR content wrong: %v", rrs)
	}

	if _, err := pullAXFR(addr, zoneName, "other-key.", tsigSecret); err == nil {
		t.Fatal("AXFR signed with an unknown key must not succeed")
	}
}

// ------------------------------------------------------------------ NOTIFY

func notifyReq(zone string, signed bool) *dns.Msg {
	m := new(dns.Msg)
	m.SetNotify(zone)
	if signed {
		m.SetTsig("notify-key.", dns.HmacSHA256, 300, time.Now().Unix())
	}
	return m
}

// secondaryHarness builds a server whose secondary manager has no authoritative
// store, so an accepted NOTIFY can not start a transfer or touch the network.
func secondaryHarness(t *testing.T, zone string, masters ...string) *harness {
	t.Helper()
	h := newHarness(t)
	mgr := secondary.New(filepath.Join(t.TempDir(), "secondary-zones.json"), nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := mgr.Upsert(secondary.Zone{Name: zone, Masters: masters}); err != nil {
		t.Fatal(err)
	}
	h.srv.SetSecondary(mgr)
	return h
}

func TestNOTIFYIsAcceptedFromTheConfiguredMaster(t *testing.T) {
	h := secondaryHarness(t, "sec.test.", "198.51.100.7")
	msgs := h.send(newWriter("198.51.100.7"), notifyReq("sec.test.", false))
	if len(msgs) != 1 || msgs[0].Rcode != dns.RcodeSuccess || msgs[0].Opcode != dns.OpcodeNotify || !msgs[0].Response {
		t.Fatalf("want a NOTIFY response with NOERROR, got %v", msgs)
	}
}

func TestNOTIFYIsRefusedFromAnUnconfiguredHostWithoutTSIG(t *testing.T) {
	h := secondaryHarness(t, "sec.test.", "198.51.100.7")
	msgs := h.send(newWriter("203.0.113.66"), notifyReq("sec.test.", false))
	if len(msgs) != 1 || msgs[0].Rcode != dns.RcodeRefused {
		t.Fatalf("want REFUSED, got %v", msgs)
	}
}

func TestNOTIFYIsAcceptedFromAnyHostWithAValidTSIG(t *testing.T) {
	h := secondaryHarness(t, "sec.test.", "198.51.100.7")
	msgs := h.send(newWriter("203.0.113.66"), notifyReq("sec.test.", true))
	if len(msgs) != 1 || msgs[0].Rcode != dns.RcodeSuccess {
		t.Fatalf("want NOERROR, got %v", msgs)
	}
}

func TestNOTIFYIsRefusedWhenTheTSIGDoesNotVerifyAndTheHostIsUnknown(t *testing.T) {
	h := secondaryHarness(t, "sec.test.", "198.51.100.7")
	w := newWriter("203.0.113.66")
	w.tsigErr = dns.ErrSig
	msgs := h.send(w, notifyReq("sec.test.", true))
	if len(msgs) != 1 || msgs[0].Rcode != dns.RcodeRefused {
		t.Fatalf("want REFUSED, got %v", msgs)
	}
}

func TestNOTIFYIsRefusedForAZoneThatIsNotASecondaryZone(t *testing.T) {
	h := secondaryHarness(t, "sec.test.", "198.51.100.7")
	msgs := h.send(newWriter("198.51.100.7"), notifyReq("other.test.", false))
	if len(msgs) != 1 || msgs[0].Rcode != dns.RcodeRefused {
		t.Fatalf("want REFUSED, got %v", msgs)
	}
}

func TestNOTIFYIsRefusedWhenNoSecondaryZonesAreConfigured(t *testing.T) {
	h := newHarness(t)
	msgs := h.send(newWriter("198.51.100.7"), notifyReq("sec.test.", false))
	if len(msgs) != 1 || msgs[0].Rcode != dns.RcodeRefused {
		t.Fatalf("want REFUSED, got %v", msgs)
	}
}

// ---------------------------------------------------------- dynamic update

func updateReq(zone string, prereq, updates []dns.RR) *dns.Msg {
	m := new(dns.Msg)
	m.SetUpdate(zone)
	m.Answer = prereq // the prerequisite section shares the Answer slot in miekg/dns
	m.Ns = append(m.Ns, updates...)
	return m
}

func enableUpdate(c *config.Config) {
	c.Update.Enabled = true
	c.Update.RequireTSIG = false
}

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatal(err)
	}
	return rr
}

func TestDynamicUpdateAddsARecordThatIsThenAnswered(t *testing.T) {
	h := newHarness(t, withConfig(enableUpdate))
	h.addZone(zoneName, rec("www.example.com.", dns.TypeA, "192.0.2.10"))
	before := h.auth.CurrentSOASerial(zoneName)

	msgs := h.send(newWriter(anyClientIP), updateReq(zoneName, nil, []dns.RR{mustRR(t, "added.example.com. 120 IN A 192.0.2.77")}))
	if len(msgs) != 1 || msgs[0].Rcode != dns.RcodeSuccess || msgs[0].Opcode != dns.OpcodeUpdate {
		t.Fatalf("want an UPDATE response with NOERROR, got %v", msgs)
	}
	wantA(t, h.q("added.example.com.", dns.TypeA), "192.0.2.77")

	// The SOA serial must have advanced; read it through a transfer (not cached).
	hc := h.cfg
	allowTransfer(hc)
	rrs, _ := h.transfer(newWriter(anyClientIP), zoneName, dns.TypeAXFR, 0)
	if serials := soaSerials(rrs); len(serials) == 0 || serials[0] <= before {
		t.Fatalf("SOA serial did not advance past %d: %v", before, serials)
	}
}

func TestDynamicUpdateDeletesARecordSet(t *testing.T) {
	h := newHarness(t, withConfig(enableUpdate))
	h.addZone(zoneName, rec("gone.example.com.", dns.TypeA, "192.0.2.10"), rec("keep.example.com.", dns.TypeA, "192.0.2.11"))
	del := &dns.ANY{Hdr: dns.RR_Header{Name: "gone.example.com.", Rrtype: dns.TypeA, Class: dns.ClassANY}}
	msgs := h.send(newWriter(anyClientIP), updateReq(zoneName, nil, []dns.RR{del}))
	if msgs[0].Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%s", dns.RcodeToString[msgs[0].Rcode])
	}
	wantRcode(t, h.q("gone.example.com.", dns.TypeA), dns.RcodeNameError)
	wantA(t, h.q("keep.example.com.", dns.TypeA), "192.0.2.11")
}

func TestDynamicUpdateIsRefusedWhenUpdatesAreNotEnabled(t *testing.T) {
	h := newHarness(t) // defaults: update disabled
	h.addZone(zoneName)
	msgs := h.send(newWriter(anyClientIP), updateReq(zoneName, nil, []dns.RR{mustRR(t, "added.example.com. 120 IN A 192.0.2.77")}))
	if len(msgs) != 1 || msgs[0].Rcode != dns.RcodeRefused {
		t.Fatalf("want REFUSED, got %v", msgs)
	}
	wantRcode(t, h.q("added.example.com.", dns.TypeA), dns.RcodeNameError)
}

func TestDynamicUpdateIsRefusedFromClientsOutsideTheAllowList(t *testing.T) {
	h := newHarness(t, withConfig(func(c *config.Config) {
		enableUpdate(c)
		c.Update.AllowFrom = []string{"198.51.100.0/24"}
	}))
	h.addZone(zoneName)
	msgs := h.send(newWriter("203.0.113.9"), updateReq(zoneName, nil, []dns.RR{mustRR(t, "added.example.com. 120 IN A 192.0.2.77")}))
	if len(msgs) != 1 || msgs[0].Rcode != dns.RcodeRefused {
		t.Fatalf("want REFUSED, got %v", msgs)
	}
}

func TestDynamicUpdateIsNotAuthorisedWhenTSIGIsRequiredAndTheSignatureFailed(t *testing.T) {
	h := newHarness(t, withConfig(func(c *config.Config) {
		c.Update.Enabled = true
		c.Update.RequireTSIG = true
	}))
	h.addZone(zoneName)
	w := newWriter(anyClientIP)
	w.tsigErr = dns.ErrSig
	msgs := h.send(w, updateReq(zoneName, nil, []dns.RR{mustRR(t, "added.example.com. 120 IN A 192.0.2.77")}))
	if len(msgs) != 1 || msgs[0].Rcode != dns.RcodeNotAuth {
		t.Fatalf("want NOTAUTH, got %v", msgs)
	}
}

func TestDynamicUpdateForAZoneThatIsNotHostedIsNotAuthoritative(t *testing.T) {
	h := newHarness(t, withConfig(enableUpdate))
	h.addZone(zoneName)
	msgs := h.send(newWriter(anyClientIP), updateReq("nozone.test.", nil, []dns.RR{mustRR(t, "a.nozone.test. 120 IN A 192.0.2.77")}))
	if len(msgs) != 1 || msgs[0].Rcode != dns.RcodeNotAuth {
		t.Fatalf("want NOTAUTH, got %v", msgs)
	}
}

func TestDynamicUpdateFailsWhenAPrerequisiteIsNotMet(t *testing.T) {
	h := newHarness(t, withConfig(enableUpdate))
	h.addZone(zoneName)
	prereq := &dns.ANY{Hdr: dns.RR_Header{Name: "missing.example.com.", Rrtype: dns.TypeA, Class: dns.ClassANY}}
	msgs := h.send(newWriter(anyClientIP), updateReq(zoneName, []dns.RR{prereq}, []dns.RR{mustRR(t, "added.example.com. 120 IN A 192.0.2.77")}))
	if len(msgs) != 1 || msgs[0].Rcode != dns.RcodeNXRrset {
		t.Fatalf("want NXRRSET, got %v", msgs)
	}
	wantRcode(t, h.q("added.example.com.", dns.TypeA), dns.RcodeNameError)
}

// ------------------------------------------------------- Secondary Zones

// primaryWithZone starts a primary on loopback TCP that offers zone transfers.
func primaryWithZone(t *testing.T, zone string, recs ...authoritative.Record) string {
	t.Helper()
	p := newHarness(t, withConfig(allowTransfer))
	p.addZone(zone, recs...)
	return startTCP(t, p.srv, nil)
}

func secondaryOver(t *testing.T, dir string, onChange func(string)) (*harness, *secondary.Manager) {
	t.Helper()
	h := newHarness(t)
	mgr := secondary.New(filepath.Join(dir, "secondary-zones.json"), h.auth, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if onChange != nil {
		mgr.SetOnChange(onChange)
	}
	h.srv.SetSecondary(mgr)
	return h, mgr
}

func TestSecondaryZoneAnswersFromRecordsPulledFromItsMaster(t *testing.T) {
	master := primaryWithZone(t, "sec.test.",
		rec("www.sec.test.", dns.TypeA, "192.0.2.31"),
		rec("sec.test.", dns.TypeNS, "ns1.sec.test."),
	)
	h, mgr := secondaryOver(t, t.TempDir(), nil)
	if err := mgr.Upsert(secondary.Zone{Name: "sec.test.", Masters: []string{master}}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := mgr.Transfer(ctx, "sec.test."); err != nil {
		t.Fatal(err)
	}

	m := h.q("www.sec.test.", dns.TypeA)
	wantRcode(t, m, dns.RcodeSuccess)
	if !m.Authoritative {
		t.Fatal("AA bit not set for a Secondary Zone")
	}
	wantA(t, m, "192.0.2.31")

	m = h.q("nothere.sec.test.", dns.TypeA)
	wantRcode(t, m, dns.RcodeNameError)
	wantSOAInAuthority(t, m, "sec.test.")
	m = h.q("www.sec.test.", dns.TypeAAAA)
	wantRcode(t, m, dns.RcodeSuccess)
	wantSOAInAuthority(t, m, "sec.test.")
}

func TestSecondaryZoneKeepsAnsweringFromStoredRecordsAfterARestart(t *testing.T) {
	master := primaryWithZone(t, "sec.test.", rec("www.sec.test.", dns.TypeA, "192.0.2.31"))
	dir := t.TempDir()
	_, mgr := secondaryOver(t, dir, nil)
	if err := mgr.Upsert(secondary.Zone{Name: "sec.test.", Masters: []string{master}}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := mgr.Transfer(ctx, "sec.test."); err != nil {
		t.Fatal(err)
	}

	// New process: empty store, same data directory, master unreachable.
	h2, mgr2 := secondaryOver(t, dir, nil)
	if err := mgr2.Load(); err != nil {
		t.Fatal(err)
	}
	wantA(t, h2.q("www.sec.test.", dns.TypeA), "192.0.2.31")
}

func TestSecondaryZoneIsPulledWhenAMasterSendsNOTIFY(t *testing.T) {
	master := primaryWithZone(t, "sec.test.", rec("www.sec.test.", dns.TypeA, "192.0.2.31"))
	synced := make(chan string, 4)
	h, mgr := secondaryOver(t, t.TempDir(), func(z string) { synced <- z })
	if err := mgr.Upsert(secondary.Zone{Name: "sec.test.", Masters: []string{master}}); err != nil {
		t.Fatal(err)
	}
	<-synced // Upsert announces the new zone

	// Loopback is always an allowed NOTIFY source for the secondary manager.
	msgs := h.send(newWriter("127.0.0.1"), notifyReq("sec.test.", false))
	if len(msgs) != 1 || msgs[0].Rcode != dns.RcodeSuccess {
		t.Fatalf("want NOERROR, got %v", msgs)
	}
	select {
	case <-synced:
	case <-time.After(10 * time.Second):
		t.Fatal("NOTIFY did not lead to a zone pull")
	}
	wantA(t, h.q("www.sec.test.", dns.TypeA), "192.0.2.31")
}

// -------------------------------------------- split horizon and location

func TestSplitHorizonAnswersEachViewItsOwnRecords(t *testing.T) {
	h := newHarness(t, withViews(map[string][]string{"internal": {"10.0.0.0/8"}}))
	h.addZone(zoneName,
		authoritative.Record{Name: "app.example.com.", Type: dns.TypeA, TTL: 300, Content: "10.0.0.5", View: "internal"},
		authoritative.Record{Name: "app.example.com.", Type: dns.TypeA, TTL: 300, Content: "192.0.2.5", View: "default"},
		rec("shared.example.com.", dns.TypeA, "192.0.2.6"),
	)
	wantA(t, h.ask("10.1.2.3", "app.example.com.", dns.TypeA), "10.0.0.5")
	wantA(t, h.ask("203.0.113.9", "app.example.com.", dns.TypeA), "192.0.2.5")
	// A record without a view is served to every view.
	wantA(t, h.ask("10.1.2.3", "shared.example.com.", dns.TypeA), "192.0.2.6")
	wantA(t, h.ask("203.0.113.9", "shared.example.com.", dns.TypeA), "192.0.2.6")
	// Repeating a query must not leak one view's answer to the other.
	wantA(t, h.ask("10.1.2.3", "app.example.com.", dns.TypeA), "10.0.0.5")
	wantA(t, h.ask("203.0.113.9", "app.example.com.", dns.TypeA), "192.0.2.5")
}

func TestSplitHorizonHidesAnInternalOnlyNameFromOtherViews(t *testing.T) {
	h := newHarness(t, withViews(map[string][]string{"internal": {"10.0.0.0/8"}}))
	h.addZone(zoneName,
		authoritative.Record{Name: "secret.example.com.", Type: dns.TypeA, TTL: 300, Content: "10.0.0.9", View: "internal"},
		rec("www.example.com.", dns.TypeA, "192.0.2.10"),
	)
	wantA(t, h.ask("10.9.9.9", "secret.example.com.", dns.TypeA), "10.0.0.9")
	m := h.ask("203.0.113.9", "secret.example.com.", dns.TypeA)
	if len(m.Answer) != 0 {
		t.Fatalf("internal record leaked to the default view: %v", m.Answer)
	}
}

func TestGeoAnswersTheRecordForTheClientsCountryAndFallsBackToDefault(t *testing.T) {
	h := newHarness(t, withGeo(map[string]string{"198.51.100.20": "ID", "198.51.100.30": "US"}))
	h.addZone(zoneName,
		authoritative.Record{Name: "cdn.example.com.", Type: dns.TypeA, TTL: 300, Content: "192.0.2.100", GeoTag: "ID"},
		authoritative.Record{Name: "cdn.example.com.", Type: dns.TypeA, TTL: 300, Content: "192.0.2.200", GeoTag: "US"},
		authoritative.Record{Name: "cdn.example.com.", Type: dns.TypeA, TTL: 300, Content: "192.0.2.254", GeoTag: "default"},
	)
	wantA(t, h.ask("198.51.100.20", "cdn.example.com.", dns.TypeA), "192.0.2.100")
	wantA(t, h.ask("198.51.100.30", "cdn.example.com.", dns.TypeA), "192.0.2.200")
	// A client without a location gets the default record.
	wantA(t, h.ask("203.0.113.9", "cdn.example.com.", dns.TypeA), "192.0.2.254")
	// Each location keeps getting its own records on repeated queries.
	wantA(t, h.ask("198.51.100.20", "cdn.example.com.", dns.TypeA), "192.0.2.100")
}

func TestGeoAnswersStayWithTheClientAddressWhenTheQueryDidNotComeFromTheDataplane(t *testing.T) {
	// A source that is not the loopback Dataplane is not trusted with a client subnet: the
	// location of the answer is chosen from the address that sent the query. (From the
	// Dataplane the subnet steers GeoDNS: handler_proxy_e2e_test.go.)
	h := newHarness(t, withECS(), withGeo(map[string]string{"198.51.100.20": "ID", "198.51.100.30": "US"}))
	h.addZone(zoneName,
		authoritative.Record{Name: "cdn.example.com.", Type: dns.TypeA, TTL: 300, Content: "192.0.2.100", GeoTag: "ID"},
		authoritative.Record{Name: "cdn.example.com.", Type: dns.TypeA, TTL: 300, Content: "192.0.2.200", GeoTag: "US"},
		authoritative.Record{Name: "cdn.example.com.", Type: dns.TypeA, TTL: 300, Content: "192.0.2.254", GeoTag: "default"},
	)
	// Client at the "US" address, end user's subnet elsewhere.
	m := h.ask("198.51.100.30", "cdn.example.com.", dns.TypeA, withECSOption("198.51.100.0/24"))
	wantRcode(t, m, dns.RcodeSuccess)
	wantA(t, m, "192.0.2.200")
	// Same query name, different client subnet, same client address: same answer.
	wantA(t, h.ask("198.51.100.30", "cdn.example.com.", dns.TypeA, withECSOption("203.0.113.0/24")), "192.0.2.200")
	// And a different client address with the first subnet still gets its own location.
	wantA(t, h.ask("198.51.100.20", "cdn.example.com.", dns.TypeA, withECSOption("198.51.100.0/24")), "192.0.2.100")
}

func TestViewAndGeoSelectionWorkTogether(t *testing.T) {
	h := newHarness(t,
		withViews(map[string][]string{"internal": {"10.0.0.0/8"}}),
		withGeo(map[string]string{"10.1.1.1": "ID", "198.51.100.20": "ID"}),
	)
	h.addZone(zoneName,
		authoritative.Record{Name: "app.example.com.", Type: dns.TypeA, TTL: 300, Content: "10.0.0.1", View: "internal", GeoTag: "ID"},
		authoritative.Record{Name: "app.example.com.", Type: dns.TypeA, TTL: 300, Content: "192.0.2.1", View: "default", GeoTag: "ID"},
		authoritative.Record{Name: "app.example.com.", Type: dns.TypeA, TTL: 300, Content: "192.0.2.2", View: "default", GeoTag: "default"},
	)
	wantA(t, h.ask("10.1.1.1", "app.example.com.", dns.TypeA), "10.0.0.1")
	wantA(t, h.ask("198.51.100.20", "app.example.com.", dns.TypeA), "192.0.2.1")
	wantA(t, h.ask("203.0.113.9", "app.example.com.", dns.TypeA), "192.0.2.2")
}
