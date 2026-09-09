package server

import (
	"net"
	"time"

	"github.com/miekg/dns"
)

// Some stub resolvers encode the OPT owner as a 1-byte NUL label (\x01\x00)
// instead of root (\x00). miekg then overruns the packet →
// "dns: buffer size too small" and the client retries google.com forever.
func repairEDNSRootName(msg []byte) []byte {
	if len(msg) < 12 {
		return msg
	}
	off := 12
	qd := int(msg[4])<<8 | int(msg[5])
	for i := 0; i < qd; i++ {
		for {
			if off >= len(msg) {
				return msg
			}
			lab := int(msg[off])
			if lab == 0 {
				off++
				break
			}
			if lab >= 0xC0 {
				off += 2
				break
			}
			off += 1 + lab
		}
		off += 4 // type + class
		if off > len(msg) {
			return msg
		}
	}
	if off+3 <= len(msg) && msg[off] == 0x01 && msg[off+1] == 0x00 && msg[off+2] == 0x29 {
		out := append([]byte(nil), msg...)
		out[off] = 0x00
		return out
	}
	return msg
}

type ednsRepairReader struct {
	inner dns.Reader
}

func decorateEDNSRepair(r dns.Reader) dns.Reader {
	if r == nil {
		return r
	}
	return ednsRepairReader{inner: r}
}

func (r ednsRepairReader) ReadTCP(conn net.Conn, timeout time.Duration) ([]byte, error) {
	b, err := r.inner.ReadTCP(conn, timeout)
	return repairEDNSRootName(b), err
}

func (r ednsRepairReader) ReadUDP(conn *net.UDPConn, timeout time.Duration) ([]byte, *dns.SessionUDP, error) {
	b, s, err := r.inner.ReadUDP(conn, timeout)
	return repairEDNSRootName(b), s, err
}

func (r ednsRepairReader) ReadPacketConn(conn net.PacketConn, timeout time.Duration) ([]byte, net.Addr, error) {
	pc, ok := r.inner.(dns.PacketConnReader)
	if !ok {
		return nil, nil, net.ErrClosed
	}
	b, addr, err := pc.ReadPacketConn(conn, timeout)
	return repairEDNSRootName(b), addr, err
}
