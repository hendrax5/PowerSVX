package proxyproto

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

// ---- fakes: a peer address the test chooses, which a real socket on this host cannot have

type fakeConn struct {
	net.Conn
	remote net.Addr
}

func (c fakeConn) RemoteAddr() net.Addr { return c.remote }

type fakeListener struct{ conns chan net.Conn }

func (l fakeListener) Accept() (net.Conn, error) {
	c, ok := <-l.conns
	if !ok {
		return nil, net.ErrClosed
	}
	return c, nil
}
func (l fakeListener) Close() error   { close(l.conns); return nil }
func (l fakeListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5354} }

func tcpFrom(peer string) (server net.Conn, client net.Conn, l fakeListener) {
	s, c := net.Pipe()
	l = fakeListener{conns: make(chan net.Conn, 1)}
	l.conns <- fakeConn{Conn: s, remote: net.TCPAddrFromAddrPort(netip.MustParseAddrPort(peer))}
	return s, c, l
}

func readAll(t *testing.T, c net.Conn, n int) (string, error) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, n)
	got, err := io.ReadFull(c, buf)
	return string(buf[:got]), err
}

func TestTCPListenerReportsTheClientTheHeaderNamesFromALoopbackPeer(t *testing.T) {
	_, client, fl := tcpFrom("127.0.0.1:41000")
	l := &Listener{Listener: fl, Mode: Required}
	go func() {
		_, _ = client.Write(Encode(Header{Transport: Stream, Src: ap("203.0.113.9:40000"), Dst: ap("192.0.2.1:53")}))
		_, _ = client.Write([]byte("hello"))
	}()
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if got := c.RemoteAddr().String(); got != "127.0.0.1:41000" {
		t.Fatalf("before the header is read RemoteAddr must be the peer, got %s", got)
	}
	got, err := readAll(t, c, 5)
	if err != nil || got != "hello" {
		t.Fatalf("payload after the header: %q %v", got, err)
	}
	if got := c.RemoteAddr().String(); got != "203.0.113.9:40000" {
		t.Fatalf("RemoteAddr = %s, want the client from the header", got)
	}
	if p := TransportPeer(c.RemoteAddr()); p.String() != "127.0.0.1:41000" {
		t.Fatalf("TransportPeer = %s, want the loopback peer", p)
	}
}

func TestTCPListenerReportsIPv6ClientsAndUnmapsIPv4InIPv6(t *testing.T) {
	for _, tc := range []struct{ src, want string }{
		{"[2001:db8::9]:40000", "[2001:db8::9]:40000"},
		{"[::ffff:203.0.113.9]:40000", "203.0.113.9:40000"},
	} {
		_, client, fl := tcpFrom("[::1]:41000")
		l := &Listener{Listener: fl, Mode: Required}
		go func() {
			_, _ = client.Write(Encode(Header{Transport: Stream, Src: ap(tc.src), Dst: ap("[2001:db8::1]:53")}))
			_, _ = client.Write([]byte("x"))
		}()
		c, _ := l.Accept()
		if _, err := readAll(t, c, 1); err != nil {
			t.Fatal(err)
		}
		if c.RemoteAddr().String() != tc.want {
			t.Fatalf("%s: RemoteAddr = %s, want %s", tc.src, c.RemoteAddr(), tc.want)
		}
	}
}

func TestTCPListenerLocalCommandKeepsThePeerAddress(t *testing.T) {
	_, client, fl := tcpFrom("127.0.0.1:41000")
	l := &Listener{Listener: fl, Mode: Required}
	go func() {
		_, _ = client.Write(Encode(Header{Local: true}))
		_, _ = client.Write([]byte("x"))
	}()
	c, _ := l.Accept()
	if _, err := readAll(t, c, 1); err != nil {
		t.Fatal(err)
	}
	if c.RemoteAddr().String() != "127.0.0.1:41000" {
		t.Fatalf("a LOCAL header names no client, RemoteAddr = %s", c.RemoteAddr())
	}
}

func TestTCPListenerModes(t *testing.T) {
	plain := []byte("\x00\x1d\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01")
	t.Run("optional passes a plain connection through byte for byte", func(t *testing.T) {
		_, client, fl := tcpFrom("127.0.0.1:41000")
		l := &Listener{Listener: fl, Mode: Optional}
		go func() { _, _ = client.Write(plain) }()
		c, _ := l.Accept()
		got, err := readAll(t, c, len(plain))
		if err != nil || got != string(plain) {
			t.Fatalf("plain bytes changed: %q %v", got, err)
		}
		if c.RemoteAddr().String() != "127.0.0.1:41000" {
			t.Fatalf("RemoteAddr = %s", c.RemoteAddr())
		}
	})
	t.Run("a one-byte plain message is not held up waiting for a whole signature", func(t *testing.T) {
		_, client, fl := tcpFrom("127.0.0.1:41000")
		l := &Listener{Listener: fl, Mode: Optional}
		go func() { _, _ = client.Write([]byte{0x00}) }()
		c, _ := l.Accept()
		if got, err := readAll(t, c, 1); err != nil || got != "\x00" {
			t.Fatalf("got %q %v", got, err)
		}
	})
	t.Run("required refuses a plain connection", func(t *testing.T) {
		before := Refused.Load()
		_, client, fl := tcpFrom("127.0.0.1:41000")
		l := &Listener{Listener: fl, Mode: Required}
		go func() { _, _ = client.Write(plain) }()
		c, _ := l.Accept()
		if _, err := readAll(t, c, 4); !errors.Is(err, ErrNoHeader) {
			t.Fatalf("want ErrNoHeader, got %v", err)
		}
		if Refused.Load() != before+1 {
			t.Fatal("the refusal is not counted")
		}
	})
	t.Run("a malformed or truncated header ends the connection", func(t *testing.T) {
		for name, hdr := range map[string][]byte{
			"truncated": Encode(Header{Transport: Stream, Src: ap("203.0.113.9:1"), Dst: ap("192.0.2.1:53")})[:20],
			"bad cmd":   append(append([]byte(nil), Signature...), 0x2f, 0x11, 0, 12),
		} {
			s, client, fl := tcpFrom("127.0.0.1:41000")
			l := &Listener{Listener: fl, Mode: Optional}
			go func() { _, _ = client.Write(hdr); _ = client.Close() }()
			c, _ := l.Accept()
			if _, err := readAll(t, c, 1); err == nil {
				t.Fatalf("%s: a bad header must fail the read", name)
			}
			_ = s
		}
	})
}

func TestTCPListenerNeverTrustsAHeaderFromANonLoopbackPeer(t *testing.T) {
	for _, peer := range []string{"203.0.113.50:41000", "10.0.0.7:41000", "192.168.1.9:41000", "[2001:db8::50]:41000", "[fe80::1]:41000"} {
		_, client, fl := tcpFrom(peer)
		l := &Listener{Listener: fl, Mode: Required}
		hdr := Encode(Header{Transport: Stream, Src: ap("127.0.0.1:53"), Dst: ap("192.0.2.1:53")})
		go func() { _, _ = client.Write(hdr) }()
		c, _ := l.Accept()
		if got := c.RemoteAddr().String(); got != peer {
			t.Fatalf("%s: RemoteAddr = %s", peer, got)
		}
		// The bytes are passed on as they are: the header is not parsed, so it is not believed.
		got, err := readAll(t, c, len(hdr))
		if err != nil || got != string(hdr) {
			t.Fatalf("%s: bytes were altered or the read failed: %v", peer, err)
		}
		if got := c.RemoteAddr().String(); got != peer {
			t.Fatalf("%s: the client address changed after reading: %s", peer, got)
		}
	}
}

// ---- UDP

type datagram struct {
	b    []byte
	from net.Addr
}

type fakePacketConn struct {
	in    chan datagram
	wrote chan datagram
}

func newFakePC() *fakePacketConn {
	return &fakePacketConn{in: make(chan datagram, 8), wrote: make(chan datagram, 8)}
}
func (f *fakePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	d, ok := <-f.in
	if !ok {
		return 0, nil, net.ErrClosed
	}
	return copy(b, d.b), d.from, nil
}
func (f *fakePacketConn) WriteTo(b []byte, to net.Addr) (int, error) {
	f.wrote <- datagram{append([]byte(nil), b...), to}
	return len(b), nil
}
func (f *fakePacketConn) Close() error { return nil }
func (f *fakePacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5354}
}
func (f *fakePacketConn) SetDeadline(time.Time) error      { return nil }
func (f *fakePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakePacketConn) SetWriteDeadline(time.Time) error { return nil }
func udpAddr(s string) net.Addr                            { return net.UDPAddrFromAddrPort(netip.MustParseAddrPort(s)) }

func TestUDPHeaderIsRemovedAndRepliesGoToTheDataplaneNotTheClient(t *testing.T) {
	f := newFakePC()
	pc := &PacketConn{PacketConn: f, Mode: Required}
	peer := udpAddr("127.0.0.1:49200")
	hdr := Encode(Header{Transport: Dgram, Src: ap("203.0.113.9:40000"), Dst: ap("192.0.2.1:53")})
	f.in <- datagram{append(hdr, []byte("dns query bytes")...), peer}

	buf := make([]byte, 512)
	n, from, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "dns query bytes" {
		t.Fatalf("payload = %q, the header was not removed", buf[:n])
	}
	if from.String() != "203.0.113.9:40000" {
		t.Fatalf("source = %s, want the client from the header", from)
	}
	if _, err := pc.WriteTo([]byte("dns reply"), from); err != nil {
		t.Fatal(err)
	}
	w := <-f.wrote
	if w.from.String() != "127.0.0.1:49200" {
		t.Fatalf("the reply was sent to %s; it must go to the datagram's real source (the Dataplane), never to the client", w.from)
	}
	if string(w.b) != "dns reply" {
		t.Fatalf("reply bytes = %q", w.b)
	}
}

func TestUDPWriteToAPlainAddressIsUntouched(t *testing.T) {
	f := newFakePC()
	pc := &PacketConn{PacketConn: f, Mode: Optional}
	to := udpAddr("127.0.0.1:49200")
	_, _ = pc.WriteTo([]byte("x"), to)
	if w := <-f.wrote; w.from.String() != to.String() {
		t.Fatalf("sent to %s", w.from)
	}
}

func TestUDPLocalHeaderKeepsThePeerAddress(t *testing.T) {
	f := newFakePC()
	pc := &PacketConn{PacketConn: f, Mode: Required}
	peer := udpAddr("127.0.0.1:49200")
	f.in <- datagram{append(Encode(Header{Local: true}), []byte("health check")...), peer}
	buf := make([]byte, 512)
	n, from, err := pc.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "health check" || from.String() != "127.0.0.1:49200" {
		t.Fatalf("n=%d from=%v err=%v", n, from, err)
	}
}

func TestUDPDropsWhatBreaksTheRules(t *testing.T) {
	good := Encode(Header{Transport: Dgram, Src: ap("203.0.113.9:40000"), Dst: ap("192.0.2.1:53")})
	loop := udpAddr("127.0.0.1:49200")
	plain := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 3, 'w', 'w', 'w', 0, 0, 1, 0, 1}
	last := append(append([]byte(nil), good...), []byte("last")...)

	t.Run("required drops a plain datagram, a truncated header and an oversize header", func(t *testing.T) {
		before := Refused.Load()
		f := newFakePC()
		pc := &PacketConn{PacketConn: f, Mode: Required}
		f.in <- datagram{plain, loop}
		f.in <- datagram{good[:20], loop}
		f.in <- datagram{v2(0x21, 0x12, make([]byte, MaxHeaderLen)), loop}
		f.in <- datagram{last, loop}
		buf := make([]byte, 2048)
		n, from, err := pc.ReadFrom(buf)
		if err != nil || string(buf[:n]) != "last" || from.String() != "203.0.113.9:40000" {
			t.Fatalf("the first accepted datagram should be the last one: %q %v %v", buf[:n], from, err)
		}
		if got := Refused.Load() - before; got != 3 {
			t.Fatalf("refused counter moved by %d, want 3", got)
		}
	})
	t.Run("optional passes a plain datagram from loopback and drops a bad header", func(t *testing.T) {
		f := newFakePC()
		pc := &PacketConn{PacketConn: f, Mode: Optional}
		f.in <- datagram{good[:20], loop}
		f.in <- datagram{plain, loop}
		buf := make([]byte, 2048)
		n, from, err := pc.ReadFrom(buf)
		if err != nil || n != len(plain) || from.String() != "127.0.0.1:49200" {
			t.Fatalf("n=%d from=%v err=%v", n, from, err)
		}
	})
	t.Run("a header from a non-loopback source is dropped and never believed", func(t *testing.T) {
		before := Refused.Load()
		f := newFakePC()
		pc := &PacketConn{PacketConn: f, Mode: Optional}
		for _, src := range []string{"203.0.113.50:5000", "10.0.0.7:5000", "[2001:db8::50]:5000"} {
			f.in <- datagram{append(append([]byte(nil), good...), []byte("spoof")...), udpAddr(src)}
		}
		// a plain datagram from a stranger is passed on with its own source; the handler refuses it
		f.in <- datagram{plain, udpAddr("203.0.113.50:5001")}
		buf := make([]byte, 2048)
		n, from, err := pc.ReadFrom(buf)
		if err != nil || n != len(plain) || from.String() != "203.0.113.50:5001" {
			t.Fatalf("n=%d from=%v err=%v", n, from, err)
		}
		if _, ok := from.(*Addr); ok {
			t.Fatal("a stranger's datagram came back as a proxied address")
		}
		if got := Refused.Load() - before; got != 3 {
			t.Fatalf("refused counter moved by %d, want 3", got)
		}
	})
}

func TestTrusted(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:1": true, "127.53.0.1:1": true, "[::1]:1": true,
		"203.0.113.1:1": false, "10.0.0.1:1": false, "[2001:db8::1]:1": false, "0.0.0.0:1": false,
	} {
		if got := Trusted(udpAddr(addr)); got != want {
			t.Errorf("Trusted(%s) = %v, want %v", addr, got, want)
		}
	}
	if Trusted(nil) {
		t.Error("a nil address must not be trusted")
	}
	// A client address that a header named is not the peer: it never makes a connection trusted.
	named := &Addr{AddrPort: ap("127.0.0.1:53"), Net: "udp", Peer: udpAddr("203.0.113.50:5000")}
	if Trusted(TransportPeer(named)) {
		t.Error("a header naming a loopback client must not make a stranger trusted")
	}
}

// One round trip on real loopback sockets.
func TestUDPOnRealSockets(t *testing.T) {
	inner, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback UDP:", err)
	}
	defer inner.Close()
	pc := &PacketConn{PacketConn: inner, Mode: Required}
	cl, err := net.Dial("udp", inner.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	_, _ = cl.Write(append(Encode(Header{Transport: Dgram, Src: ap("203.0.113.9:40000"), Dst: ap("192.0.2.1:53")}), "q"...))
	_ = inner.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, from, err := pc.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "q" || from.String() != "203.0.113.9:40000" {
		t.Fatalf("n=%d from=%v err=%v", n, from, err)
	}
	if _, err := pc.WriteTo([]byte("r"), from); err != nil {
		t.Fatal(err)
	}
	_ = cl.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err = cl.Read(buf)
	if err != nil || string(buf[:n]) != "r" {
		t.Fatalf("the Dataplane socket did not get the reply: n=%d err=%v", n, err)
	}
}
