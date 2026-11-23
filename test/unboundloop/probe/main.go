// Command probe is a fake Auth Backend for the PROXY protocol facts test. It listens on
// loopback (UDP and TCP), writes one line per DNS message to stdout describing exactly
// what arrived (the PROXY header if there is one, the opcode, the question and every EDNS
// option), and answers NOERROR so dnsdist is satisfied. It never trusts or strips
// anything: it shows the raw bytes.
package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/proxyproto"
)

var connSeq atomic.Int64

func describe(proto, id string, peer net.Addr, hdr string, raw []byte) (*dns.Msg, string) {
	m := new(dns.Msg)
	if err := m.Unpack(raw); err != nil {
		return nil, fmt.Sprintf("FACT proto=%s conn=%s peer=%s proxy=[%s] undecodable=%v", proto, id, peer, hdr, err)
	}
	q := ""
	if len(m.Question) > 0 {
		q = fmt.Sprintf("%s/%s", m.Question[0].Name, dns.TypeToString[m.Question[0].Qtype])
	}
	opts := []string{}
	if o := m.IsEdns0(); o != nil {
		for _, op := range o.Option {
			switch v := op.(type) {
			case *dns.EDNS0_SUBNET:
				opts = append(opts, fmt.Sprintf("ECS(family=%d source=/%d scope=/%d addr=%s)", v.Family, v.SourceNetmask, v.SourceScope, v.Address))
			default:
				opts = append(opts, fmt.Sprintf("option%d", op.Option()))
			}
		}
		opts = append(opts, fmt.Sprintf("udpsize=%d do=%v", o.UDPSize(), o.Do()))
	} else {
		opts = append(opts, "no-EDNS")
	}
	return m, fmt.Sprintf("FACT proto=%s conn=%s peer=%s proxy=[%s] opcode=%s question=%s tsig=%v additional=%s opts=%s",
		proto, id, peer, hdr, dns.OpcodeToString[m.Opcode], q, m.IsTsig() != nil, addTypes(m), strings.Join(opts, ","))
}

func hdrText(h proxyproto.Header) string {
	if h.Local {
		return "LOCAL"
	}
	return fmt.Sprintf("PROXY transport=%d src=%s dst=%s", h.Transport, h.Src, h.Dst)
}

func reply(m *dns.Msg) []byte {
	r := new(dns.Msg)
	r.SetReply(m)
	r.Authoritative = true
	if m.Opcode == dns.OpcodeQuery && len(m.Question) > 0 && m.Question[0].Qtype == dns.TypeA {
		a, _ := dns.NewRR(m.Question[0].Name + " 60 IN A 192.0.2.1")
		r.Answer = append(r.Answer, a)
	}
	if m.Opcode == dns.OpcodeQuery && len(m.Question) > 0 && m.Question[0].Qtype == dns.TypeSOA {
		soa, _ := dns.NewRR(m.Question[0].Name + " 60 IN SOA ns. host. 1 3600 600 86400 60")
		r.Answer = append(r.Answer, soa)
	}
	b, _ := r.Pack()
	return b
}

func serveUDP(addr string) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		panic(err)
	}
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		raw := append([]byte(nil), buf[:n]...)
		hdr := "none"
		first := fmt.Sprintf("%x", raw[:min(len(raw), 16)])
		if h, hl, err := proxyproto.Parse(raw); err == nil {
			hdr, raw = hdrText(h), raw[hl:]
		}
		m, line := describe("udp", "-", from, hdr, raw)
		fmt.Println(line, "first16="+first)
		if m != nil {
			pc.WriteTo(reply(m), from)
		}
	}
}

func serveTCP(addr string) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		panic(err)
	}
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		id := fmt.Sprint(connSeq.Add(1))
		go func() {
			defer c.Close()
			br := bufio.NewReader(c)
			hdr := "none"
			if p, err := br.Peek(len(proxyproto.Signature)); err == nil && proxyproto.HasPrefix(p) {
				h, err := proxyproto.ReadHeader(br)
				if err != nil {
					fmt.Println("FACT proto=tcp conn="+id, "bad header:", err)
					return
				}
				hdr = hdrText(h)
			}
			fmt.Printf("FACT proto=tcp conn=%s opened peer=%s proxy=[%s]\n", id, c.RemoteAddr(), hdr)
			for {
				var l [2]byte
				if _, err := io.ReadFull(br, l[:]); err != nil {
					fmt.Printf("FACT proto=tcp conn=%s closed\n", id)
					return
				}
				raw := make([]byte, binary.BigEndian.Uint16(l[:]))
				if _, err := io.ReadFull(br, raw); err != nil {
					return
				}
				m, line := describe("tcp", id, c.RemoteAddr(), hdr, raw)
				fmt.Println(line)
				if m != nil {
					out := reply(m)
					c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(out))), out...))
				}
			}
		}()
	}
}

func main() {
	addr := "127.0.0.1:5354"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}
	go serveUDP(addr)
	serveTCP(addr)
}

func addTypes(m *dns.Msg) string {
	var t []string
	for _, rr := range m.Extra {
		t = append(t, dns.TypeToString[rr.Header().Rrtype])
	}
	return "[" + strings.Join(t, ",") + "]"
}
