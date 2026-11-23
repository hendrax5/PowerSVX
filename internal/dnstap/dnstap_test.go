package dnstap

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// testdata/stream.bin is what dnsdist 1.9.16 sent to a listener: the READY and
// START handshake followed by data frames, captured by test/dataplane (see
// querylog_test.go). testdata/frames.txt holds one data frame per Filter action
// from the same run, as "<action> <hex>".

func realFrames(t *testing.T) map[string][]byte {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "frames.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string][]byte{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		action, h, ok := strings.Cut(sc.Text(), " ")
		if !ok {
			t.Fatalf("bad fixture line %q", sc.Text())
		}
		b, err := hex.DecodeString(h)
		if err != nil {
			t.Fatal(err)
		}
		out[action] = b
	}
	return out
}

func TestDecodeRealDnsdistFrames(t *testing.T) {
	want := map[string]struct{ qname, qtype, rcode string }{
		ActionAllowed:       {"bank.allowed.powersvx.test", "A", "NXDOMAIN"},
		ActionBlockedFilter: {"blocked.filter.powersvx.test", "A", "NOERROR"},
		ActionBlockedCustom: {"blocked.custom.powersvx.test", "A", "NOERROR"},
		ActionAuth:          {"www.hosted.powersvx.test", "A", "NOERROR"},
		ActionRecursed:      {"exists.powersvx.test", "A", "NOERROR"},
		ActionRefused:       {"9.2.0.192.in-addr.arpa", "PTR", "REFUSED"},
	}
	frames := realFrames(t)
	for action, w := range want {
		frame, ok := frames[action]
		if !ok {
			t.Fatalf("fixture has no %s frame", action)
		}
		e, ok, err := Decode(frame)
		if err != nil || !ok {
			t.Fatalf("%s: ok=%v err=%v", action, ok, err)
		}
		if e.Action != action || e.QName != w.qname || e.QType != w.qtype || e.RCode != w.rcode {
			t.Errorf("%s: got %+v", action, e)
		}
		if e.Protocol != "udp" {
			t.Errorf("%s: protocol %q", action, e.Protocol)
		}
		if _, err := netipParse(e.ClientIP); err != nil {
			t.Errorf("%s: client %q: %v", action, e.ClientIP, err)
		}
		if e.Time.Year() < 2026 || e.Time.After(time.Now().Add(time.Hour)) {
			t.Errorf("%s: implausible time %v", action, e.Time)
		}
		if e.Blocked() != (action == ActionBlockedFilter || action == ActionBlockedCustom) {
			t.Errorf("%s: Blocked() = %v", action, e.Blocked())
		}
	}
}

func netipParse(s string) (net.IP, error) {
	if ip := net.ParseIP(s); ip != nil {
		return ip, nil
	}
	return nil, &net.ParseError{Type: "IP address", Text: s}
}

// readWriter feeds a captured stream to the reader and records what it answers.
type readWriter struct {
	*bytes.Reader
	wrote bytes.Buffer
}

func (rw *readWriter) Write(p []byte) (int, error) { return rw.wrote.Write(p) }

func TestReadStreamRealDnsdistCapture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "stream.bin"))
	if err != nil {
		t.Fatal(err)
	}
	rw := &readWriter{Reader: bytes.NewReader(raw)}
	var frames [][]byte
	// The capture ends where the live connection was still open: that is a clean end.
	if err := ReadStream(rw, func(f []byte) { frames = append(frames, f) }); err != nil {
		t.Fatalf("ReadStream: %v", err)
	}
	// dnsdist opened with READY, so the reader must have answered ACCEPT with the dnstap type.
	acc, ctl, err := readFrame(&rw.wrote)
	if err != nil || acc != nil || ctl.kind != ctlAccept || !hasContentType(ctl.contentTypes) || len(ctl.contentTypes) != 1 {
		t.Fatalf("expected one ACCEPT with the dnstap content type, got %+v err=%v", ctl, err)
	}
	if len(frames) < 6 {
		t.Fatalf("expected the captured data frames, got %d", len(frames))
	}
	seen := map[string]bool{}
	for _, f := range frames {
		e, ok, err := Decode(f)
		if err != nil || !ok {
			t.Fatalf("captured frame did not decode: ok=%v err=%v", ok, err)
		}
		seen[e.Action] = true
	}
	for _, a := range []string{ActionAllowed, ActionBlockedFilter, ActionBlockedCustom, ActionAuth, ActionRecursed, ActionRefused} {
		if !seen[a] {
			t.Errorf("no captured frame carries action %s", a)
		}
	}
}

func control(kind uint32, contentType string) []byte {
	var b bytes.Buffer
	_ = writeControl(&b, kind, contentType)
	return b.Bytes()
}

func data(payload []byte) []byte {
	out := make([]byte, 4, 4+len(payload))
	binary.BigEndian.PutUint32(out, uint32(len(payload)))
	return append(out, payload...)
}

func TestReadStreamUnidirectional(t *testing.T) {
	var in bytes.Buffer
	in.Write(control(ctlStart, ContentType))
	in.Write(data([]byte("one")))
	in.Write(data([]byte("two")))
	in.Write(control(ctlStop, ""))
	rw := &readWriter{Reader: bytes.NewReader(in.Bytes())}
	var got []string
	if err := ReadStream(rw, func(f []byte) { got = append(got, string(f)) }); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "one,two" {
		t.Fatalf("frames %v", got)
	}
	if rw.wrote.Len() != 0 {
		t.Fatal("a unidirectional stream must not be answered")
	}
}

func TestReadStreamBidirectionalFinish(t *testing.T) {
	var in bytes.Buffer
	in.Write(control(ctlReady, ContentType))
	in.Write(control(ctlStart, ContentType))
	in.Write(data([]byte("x")))
	in.Write(control(ctlStop, ""))
	rw := &readWriter{Reader: bytes.NewReader(in.Bytes())}
	if err := ReadStream(rw, func([]byte) {}); err != nil {
		t.Fatal(err)
	}
	_, a, _ := readFrame(&rw.wrote)
	_, f, _ := readFrame(&rw.wrote)
	if a == nil || a.kind != ctlAccept || f == nil || f.kind != ctlFinish {
		t.Fatalf("expected ACCEPT then FINISH, got %+v %+v", a, f)
	}
}

func TestReadStreamRejects(t *testing.T) {
	huge := make([]byte, 4)
	binary.BigEndian.PutUint32(huge, MaxFrame+1)
	cases := map[string][]byte{
		"data before start": data([]byte("x")),
		"wrong content":     control(ctlStart, "protobuf:other.Thing"),
		"oversized frame":   append(control(ctlStart, ContentType), huge...),
		"bad control":       append([]byte{0, 0, 0, 0, 0, 0, 0, 2}, 0, 1),
		"unknown control":   control(99, ""),
	}
	for name, in := range cases {
		rw := &readWriter{Reader: bytes.NewReader(in)}
		if err := ReadStream(rw, func([]byte) { t.Errorf("%s: a frame was delivered", name) }); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

// pb builds protobuf fields for the synthetic frames.
func pbVarint(num, v uint64) []byte {
	return binary.AppendUvarint(binary.AppendUvarint(nil, num<<3), v)
}

func pbBytes(num uint64, b []byte) []byte {
	out := binary.AppendUvarint(binary.AppendUvarint(nil, num<<3|2), uint64(len(b)))
	return append(out, b...)
}

func syntheticFrame(t *testing.T, kind uint64, qname string, extra string) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), dns.TypeAAAA)
	m.Response = true
	m.Rcode = dns.RcodeNameError
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	var msg []byte
	msg = append(msg, pbVarint(msgType, kind)...)
	msg = append(msg, pbVarint(msgSocketProto, 3)...) // DoT
	msg = append(msg, pbBytes(msgQueryAddr, net.ParseIP("2001:db8::7").To16())...)
	msg = append(msg, pbVarint(msgQuerySec, 1700000000)...)
	msg = append(msg, pbVarint(msgRespSec, 1700000000)...)
	msg = append(msg, 0x6d, 0x40, 0x42, 0x0f, 0x00) // response_time_nsec fixed32 = 1_000_000 (field 13)
	msg = append(msg, pbBytes(msgRespMessage, wire)...)
	var frame []byte
	if extra != "" {
		frame = append(frame, pbBytes(tapExtra, []byte(extra))...)
	}
	frame = append(frame, pbBytes(tapMessage, msg)...)
	return frame
}

func TestDecodeSynthetic(t *testing.T) {
	e, ok, err := Decode(syntheticFrame(t, typeClientResponse, "Mixed.Example.ORG", "action=blocked-filter"))
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if e.QName != "mixed.example.org" || e.QType != "AAAA" || e.RCode != "NXDOMAIN" || e.Protocol != "dot" ||
		e.ClientIP != "2001:db8::7" || e.Action != ActionBlockedFilter || !e.Blocked() {
		t.Fatalf("got %+v", e)
	}
	if e.Time.Unix() != 1700000000 || e.Time.Nanosecond() != 1_000_000 {
		t.Fatalf("time %v", e.Time)
	}
}

func TestDecodeActionIsWhitelisted(t *testing.T) {
	for _, extra := range []string{"", "action=", "action=drop table", "action=allowed\nx", "other=allowed", strings.Repeat("a", 200)} {
		e, ok, err := Decode(syntheticFrame(t, typeClientResponse, "a.example", extra))
		if err != nil || !ok {
			t.Fatalf("extra %q: ok=%v err=%v", extra, ok, err)
		}
		if e.Action != "" {
			t.Errorf("extra %q produced action %q", extra, e.Action)
		}
	}
}

func TestDecodeIgnoresOtherMessages(t *testing.T) {
	// A CLIENT_QUERY (type 5) is not a logged answer.
	if _, ok, err := Decode(syntheticFrame(t, 5, "a.example", "action=allowed")); ok || err != nil {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	// A dnstap frame without a Message.
	if _, ok, err := Decode(pbBytes(tapExtra, []byte("action=allowed"))); ok || err != nil {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestDecodeMalformed(t *testing.T) {
	good := syntheticFrame(t, typeClientResponse, "a.example", "action=allowed")
	for i := 1; i < len(good); i += 7 {
		// Must never panic, whatever the cut.
		_, _, _ = Decode(good[:i])
	}
	for _, bad := range [][]byte{{0xff}, {0x72, 0xff, 0xff, 0xff}, {0x0b}, pbBytes(tapMessage, []byte{0x30})} {
		if _, ok, err := Decode(bad); ok && err == nil {
			t.Errorf("%x decoded as a valid entry", bad)
		}
	}
	// A message whose DNS payload is not a DNS message.
	msg := append(pbVarint(msgType, typeClientResponse), pbBytes(msgRespMessage, []byte{1, 2, 3})...)
	if _, ok, err := Decode(pbBytes(tapMessage, msg)); ok || err == nil {
		t.Errorf("garbage DNS payload: ok=%v err=%v", ok, err)
	}
}

func TestListenerReceivesCapturedStream(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets in a temp dir are exercised on Linux")
	}
	raw, err := os.ReadFile(filepath.Join("testdata", "stream.bin"))
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "dnstap")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, SocketName)

	var mu sync.Mutex
	var got []Entry
	l, err := Listen(path, func(e Entry) { mu.Lock(); got = append(got, e); mu.Unlock() }, nil)
	if err != nil {
		t.Fatal(err)
	}
	go l.Serve()

	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode: %v %v", fi, err)
	}
	if l.Connected() {
		t.Fatal("connected before any peer")
	}
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	// Play the captured stream the way dnsdist does: write, but read our ACCEPT first.
	if _, err := c.Write(raw[:42]); err != nil { // READY
		t.Fatal(err)
	}
	if _, ctl, err := readFrame(c); err != nil || ctl == nil || ctl.kind != ctlAccept {
		t.Fatalf("no ACCEPT: %+v %v", ctl, err)
	}
	if _, err := c.Write(raw[42:]); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n >= 6 && l.Connected() {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	n := len(got)
	mu.Unlock()
	if n < 6 || !l.Connected() {
		t.Fatalf("entries=%d connected=%v", n, l.Connected())
	}

	l.Close() // must return although the peer is still connected
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("socket file left behind: %v", err)
	}
	_ = c.Close()
}

func TestListenReplacesStaleSocketAndRefusesFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets in a temp dir are exercised on Linux")
	}
	dir, err := os.MkdirTemp("", "dnstap")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, SocketName)
	first, err := Listen(path, func(Entry) {}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Leave the socket file in place, as a crashed process would.
	_ = first.ln.Close()
	second, err := Listen(path, func(Entry) {}, nil)
	if err != nil {
		t.Fatalf("stale socket not replaced: %v", err)
	}
	second.Close()

	if err := os.WriteFile(path, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(path, func(Entry) {}, nil); err == nil {
		t.Fatal("a regular file must not be replaced by a socket")
	}
	if b, _ := os.ReadFile(path); string(b) != "keep" {
		t.Fatal("the regular file was touched")
	}
}
