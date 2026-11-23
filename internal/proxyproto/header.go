// Package proxyproto reads PROXY protocol version 2 headers, the way dnsdist sends them to
// a backend that has useProxyProtocol=true, and wraps a TCP listener and a UDP socket so
// that the Auth Backend sees the real client's address.
//
// The specification is the HAProxy "PROXY protocol" document, section 2.2. Only what
// dnsdist produces is accepted: version 2, the LOCAL and PROXY commands, and the IPv4 and
// IPv6 families. A header is believed only when the connection or datagram came from a
// loopback address (see Trusted).
package proxyproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
)

// Signature is the 12 bytes that start every version 2 header.
var Signature = []byte("\r\n\r\n\x00\r\nQUIT\n")

const (
	fixedLen = 16 // signature, version and command, family and protocol, length
	// MaxHeaderLen bounds the whole header, TLVs included. dnsdist sends no TLVs unless it is
	// told to; a header larger than this is refused instead of buffered.
	MaxHeaderLen = 1024

	cmdLocal = 0x0
	cmdProxy = 0x1

	famUnspec = 0x0
	famInet   = 0x1
	famInet6  = 0x2

	lenInet  = 12
	lenInet6 = 36
)

// Transport is the protocol nibble of the header.
type Transport byte

const (
	Unspec Transport = 0
	Stream Transport = 1
	Dgram  Transport = 2
)

// Errors returned for a header that is not acceptable. ErrNoHeader means the bytes do not
// start with the signature at all.
var (
	ErrNoHeader  = errors.New("proxyproto: no PROXY protocol header")
	ErrShort     = errors.New("proxyproto: header is truncated")
	ErrMalformed = errors.New("proxyproto: malformed header")
	ErrTooLarge  = errors.New("proxyproto: header is too large")
)

// Header is a parsed version 2 header.
type Header struct {
	// Local is true for the LOCAL command (dnsdist's own checks) and for a PROXY header
	// with an unspecified family: there is no client address, the connection's own source
	// is the peer.
	Local     bool
	Transport Transport
	// Src and Dst are the original client and the address it asked. Zero when Local.
	Src, Dst netip.AddrPort
}

// HasPrefix reports whether b starts like a header. It is true as soon as b agrees with
// the signature for as many bytes as b has.
func HasPrefix(b []byte) bool {
	n := len(b)
	if n > len(Signature) {
		n = len(Signature)
	}
	return bytes.Equal(b[:n], Signature[:n])
}

// Parse reads one header from the start of b and returns it with its length. It returns
// ErrNoHeader when b does not start with the signature, and ErrShort when b is a prefix of
// a header that is not complete yet.
func Parse(b []byte) (Header, int, error) {
	var h Header
	if !HasPrefix(b) {
		return h, 0, ErrNoHeader
	}
	if len(b) < fixedLen {
		return h, 0, ErrShort
	}
	if b[12]>>4 != 2 {
		return h, 0, fmt.Errorf("%w: version %d", ErrMalformed, b[12]>>4)
	}
	cmd := b[12] & 0x0f
	if cmd != cmdLocal && cmd != cmdProxy {
		return h, 0, fmt.Errorf("%w: command %d", ErrMalformed, cmd)
	}
	fam, proto := b[13]>>4, Transport(b[13]&0x0f)
	if proto > Dgram {
		return h, 0, fmt.Errorf("%w: transport %d", ErrMalformed, proto)
	}
	ln := int(binary.BigEndian.Uint16(b[14:16]))
	if fixedLen+ln > MaxHeaderLen {
		return h, 0, ErrTooLarge
	}
	total := fixedLen + ln
	if len(b) < total {
		return h, 0, ErrShort
	}
	h.Transport = proto
	body := b[fixedLen:total]

	if cmd == cmdLocal {
		h.Local = true // the address block, if any, is ignored as the specification says
		return h, total, nil
	}
	switch fam {
	case famUnspec:
		h.Local = true
	case famInet:
		if ln < lenInet {
			return Header{}, 0, fmt.Errorf("%w: IPv4 block is %d bytes", ErrMalformed, ln)
		}
		h.Src = netip.AddrPortFrom(netip.AddrFrom4([4]byte(body[0:4])), binary.BigEndian.Uint16(body[8:10]))
		h.Dst = netip.AddrPortFrom(netip.AddrFrom4([4]byte(body[4:8])), binary.BigEndian.Uint16(body[10:12]))
	case famInet6:
		if ln < lenInet6 {
			return Header{}, 0, fmt.Errorf("%w: IPv6 block is %d bytes", ErrMalformed, ln)
		}
		h.Src = netip.AddrPortFrom(netip.AddrFrom16([16]byte(body[0:16])), binary.BigEndian.Uint16(body[32:34]))
		h.Dst = netip.AddrPortFrom(netip.AddrFrom16([16]byte(body[16:32])), binary.BigEndian.Uint16(body[34:36]))
	default:
		return Header{}, 0, fmt.Errorf("%w: address family %d", ErrMalformed, fam)
	}
	return h, total, nil
}

// ReadHeader reads exactly one header from r, which must be positioned at its first byte.
// It reads no byte beyond the header.
func ReadHeader(r io.Reader) (Header, error) {
	buf := make([]byte, fixedLen, 64)
	if _, err := io.ReadFull(r, buf); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return Header{}, ErrShort
		}
		return Header{}, err
	}
	if !bytes.Equal(buf[:12], Signature) {
		return Header{}, ErrNoHeader
	}
	ln := int(binary.BigEndian.Uint16(buf[14:16]))
	if fixedLen+ln > MaxHeaderLen {
		return Header{}, ErrTooLarge
	}
	buf = append(buf, make([]byte, ln)...)
	if _, err := io.ReadFull(r, buf[fixedLen:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return Header{}, ErrShort
		}
		return Header{}, err
	}
	h, _, err := Parse(buf)
	return h, err
}

// Encode builds a version 2 header, for tests and probes. A zero Src makes a LOCAL header.
func Encode(h Header) []byte {
	out := append([]byte(nil), Signature...)
	if h.Local || !h.Src.IsValid() {
		return append(out, 0x20, 0x00, 0, 0)
	}
	proto := byte(h.Transport)
	if h.Src.Addr().Is4() && h.Dst.Addr().Is4() {
		out = append(out, 0x21, famInet<<4|proto, 0, lenInet)
		s, d := h.Src.Addr().As4(), h.Dst.Addr().As4()
		out = append(out, s[:]...)
		out = append(out, d[:]...)
	} else {
		out = append(out, 0x21, famInet6<<4|proto, 0, lenInet6)
		s, d := h.Src.Addr().As16(), h.Dst.Addr().As16()
		out = append(out, s[:]...)
		out = append(out, d[:]...)
	}
	return binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(out, h.Src.Port()), h.Dst.Port())
}
