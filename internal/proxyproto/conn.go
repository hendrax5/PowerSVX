package proxyproto

import (
	"bufio"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
)

// Mode says what the wrapped sockets expect from the peer.
type Mode int

const (
	// Optional accepts a PROXY header and also a connection or datagram without one, both
	// only from a trusted peer. It is how a node keeps working while the Dataplane and the
	// Control Plane are updated one after the other.
	Optional Mode = iota
	// Required accepts only connections and datagrams that start with a PROXY header
	// from a trusted peer; anything else from a trusted peer is dropped.
	Required
)

// Trusted reports whether a peer may send PROXY headers: only the loopback addresses the
// local Dataplane connects from.
func Trusted(a net.Addr) bool {
	ap, ok := addrPort(a)
	return ok && ap.Addr().IsLoopback()
}

func addrPort(a net.Addr) (netip.AddrPort, bool) {
	switch v := a.(type) {
	case *net.TCPAddr:
		return v.AddrPort(), v.AddrPort().IsValid()
	case *net.UDPAddr:
		return v.AddrPort(), v.AddrPort().IsValid()
	case *Addr:
		return v.AddrPort, true
	}
	if a == nil {
		return netip.AddrPort{}, false
	}
	ap, err := netip.ParseAddrPort(a.String())
	return ap, err == nil
}

// Addr is the address of a client that a PROXY header named. The connection or datagram
// itself came from Peer.
type Addr struct {
	netip.AddrPort
	Net  string
	Peer net.Addr
}

func (a *Addr) Network() string { return a.Net }
func (a *Addr) String() string  { return a.AddrPort.String() }

// TransportPeer returns the address the bytes really came from: the client address of a
// wrapped connection is not the peer, anything else is its own peer.
func TransportPeer(a net.Addr) net.Addr {
	if p, ok := a.(*Addr); ok && p.Peer != nil {
		return p.Peer
	}
	return a
}

func clientAddr(h Header, network string, peer net.Addr) net.Addr {
	if h.Local || !h.Src.IsValid() {
		return peer
	}
	src := netip.AddrPortFrom(h.Src.Addr().Unmap(), h.Src.Port())
	return &Addr{AddrPort: src, Net: network, Peer: peer}
}

// Counters count what the wrappers refused. They are plain atomics so the package has no
// dependency on a metrics library; the Control Plane exposes them.
var (
	Accepted atomic.Uint64 // headers accepted from a trusted peer
	Refused  atomic.Uint64 // headers or header-less input dropped
)

// Listener wraps a TCP listener. Connections from a trusted peer are expected to start with
// a header (Required) or may (Optional); connections from any other peer are passed through
// untouched and never have a header looked at, so the handler's own check refuses them.
type Listener struct {
	net.Listener
	Mode Mode
}

func (l *Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if !Trusted(c.RemoteAddr()) {
		return c, nil
	}
	return &conn{Conn: c, br: bufio.NewReaderSize(c, 2048), mode: l.Mode, peer: c.RemoteAddr()}, nil
}

type conn struct {
	net.Conn
	br   *bufio.Reader
	mode Mode
	peer net.Addr

	once   sync.Once
	mu     sync.Mutex
	client net.Addr
	err    error
}

func (c *conn) first() {
	c.once.Do(func() {
		// Look at the first bytes one at a time: a plain DNS message differs from the
		// signature at once and is not held up waiting for 12 bytes.
		matched := 0
		for matched < len(Signature) {
			b, err := c.br.Peek(matched + 1)
			if err != nil {
				c.err = err
				return
			}
			if b[matched] != Signature[matched] {
				break
			}
			matched++
		}
		if matched < len(Signature) {
			if c.mode == Required {
				Refused.Add(1)
				c.err = ErrNoHeader
			}
			return
		}
		h, err := ReadHeader(c.br)
		if err != nil {
			Refused.Add(1)
			c.err = err
			return
		}
		Accepted.Add(1)
		c.mu.Lock()
		c.client = clientAddr(h, c.peer.Network(), c.peer)
		c.mu.Unlock()
	})
}

func (c *conn) Read(p []byte) (int, error) {
	c.first()
	if c.err != nil {
		return 0, c.err
	}
	return c.br.Read(p)
}

// RemoteAddr is the client the header named once it was read, the peer before that.
func (c *conn) RemoteAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client != nil {
		return c.client
	}
	return c.peer
}

// PacketConn wraps a UDP socket. A datagram from a trusted peer starts with a header
// (Required) or may (Optional); the header is removed and the datagram is reported as coming
// from the client it names. Replies written to such an address go to the peer, which is the
// Dataplane, not to the client. A datagram that fails the rules is dropped.
type PacketConn struct {
	net.PacketConn
	Mode Mode
}

func (p *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, from, err := p.PacketConn.ReadFrom(b)
		if err != nil {
			return n, from, err
		}
		if !Trusted(from) {
			if hasSignature(b[:n]) {
				Refused.Add(1) // a header from a stranger is not looked at, and not answered
				continue
			}
			return n, from, nil
		}
		if !hasSignature(b[:n]) {
			if p.Mode == Required {
				Refused.Add(1)
				continue
			}
			return n, from, nil
		}
		h, hl, err := Parse(b[:n])
		if err != nil {
			Refused.Add(1)
			continue
		}
		Accepted.Add(1)
		n = copy(b, b[hl:n])
		return n, clientAddr(h, "udp", from), nil
	}
}

func (p *PacketConn) WriteTo(b []byte, to net.Addr) (int, error) {
	if a, ok := to.(*Addr); ok && a.Peer != nil {
		to = a.Peer
	}
	return p.PacketConn.WriteTo(b, to)
}

func hasSignature(b []byte) bool {
	return len(b) >= len(Signature) && string(b[:len(Signature)]) == string(Signature)
}
