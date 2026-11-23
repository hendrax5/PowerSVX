// Command dnsq sends one DNS request from the container it runs in and prints the result on
// one line, so a test can ask dnsdist from a source address of its own:
//
//	dnsq -s 172.17.0.2:53 -n www.example.com. -t A [-net tcp] [-ecs 203.0.113.0/24] [-op query|notify|update]
//
// Output: "rcode=NOERROR aa=true answers=A 192.0.2.10;A 192.0.2.11 records=2". For AXFR and
// IXFR, records counts the records of the whole transfer. A transport failure prints
// "error=<text>".
package main

import (
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/proxyproto"
)

func main() {
	server := flag.String("s", "", "server host:port")
	name := flag.String("n", "", "query name")
	typ := flag.String("t", "A", "query type")
	netw := flag.String("net", "udp", "udp or tcp")
	ecs := flag.String("ecs", "", "send an EDNS client subnet option (CIDR)")
	op := flag.String("op", "query", "query, notify or update")
	proxy := flag.String("proxy", "", "put a PROXY protocol v2 header naming this client address in front of the request (talk to an Auth Backend directly)")
	flag.Parse()

	qt, ok := dns.StringToType[strings.ToUpper(*typ)]
	if !ok {
		fmt.Println("error=unknown type", *typ)
		os.Exit(2)
	}
	m := new(dns.Msg)
	switch *op {
	case "notify":
		m.SetNotify(dns.Fqdn(*name))
	case "update":
		m.SetUpdate(dns.Fqdn(*name))
	default:
		m.SetQuestion(dns.Fqdn(*name), qt)
	}
	if *ecs != "" {
		ip, n, err := net.ParseCIDR(*ecs)
		if err != nil {
			fmt.Println("error=", err)
			os.Exit(2)
		}
		ones, _ := n.Mask.Size()
		fam, a := uint16(1), ip.To4()
		if a == nil {
			fam, a = 2, ip.To16()
		}
		m.SetEdns0(1232, false)
		m.IsEdns0().Option = append(m.IsEdns0().Option, &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: fam, SourceNetmask: uint8(ones), Address: a})
	}

	if *proxy != "" {
		rawProxy(*server, *netw, *proxy, m)
		return
	}

	if qt == dns.TypeAXFR || qt == dns.TypeIXFR {
		conn, err := dns.DialTimeout("tcp", *server, 5*time.Second)
		if err != nil {
			fmt.Println("error=" + err.Error())
			return
		}
		defer conn.Close()
		tr := &dns.Transfer{Conn: conn, ReadTimeout: 8 * time.Second}
		ch, err := tr.In(m, *server)
		if err != nil {
			fmt.Println("error=" + err.Error())
			return
		}
		n := 0
		for env := range ch {
			if env.Error != nil {
				// A refused transfer is reported by the library as an error, not a message.
				fmt.Println("error=" + env.Error.Error())
				return
			}
			n += len(env.RR)
		}
		fmt.Printf("rcode=NOERROR records=%d\n", n)
		return
	}

	c := &dns.Client{Net: *netw, Timeout: 6 * time.Second}
	r, _, err := c.Exchange(m, *server)
	if err != nil {
		fmt.Println("error=" + err.Error())
		return
	}
	var ans []string
	for _, rr := range r.Answer {
		ans = append(ans, strings.Join(strings.Fields(rr.String())[3:], " "))
	}
	fmt.Printf("rcode=%s aa=%v answers=%s records=%d\n", dns.RcodeToString[r.Rcode], r.Authoritative, strings.Join(ans, ";"), len(r.Answer))
}

// rawProxy sends the request with a PROXY protocol header in front, on a socket of its own, and
// prints the reply's rcode, or "noreply" when nothing came back within the timeout.
func rawProxy(server, netw, client string, m *dns.Msg) {
	wire, err := m.Pack()
	if err != nil {
		fmt.Println("error=" + err.Error())
		return
	}
	src, err := netip.ParseAddr(client)
	if err != nil {
		fmt.Println("error=" + err.Error())
		return
	}
	tr := proxyproto.Dgram
	if netw == "tcp" {
		tr = proxyproto.Stream
	}
	hdr := proxyproto.Encode(proxyproto.Header{Transport: tr, Src: netip.AddrPortFrom(src, 40000), Dst: netip.MustParseAddrPort("192.0.2.1:53")})
	c, err := net.DialTimeout(netw, server, 3*time.Second)
	if err != nil {
		fmt.Println("error=" + err.Error())
		return
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if netw == "tcp" {
		_, err = c.Write(append(append(hdr, byte(len(wire)>>8), byte(len(wire))), wire...))
	} else {
		_, err = c.Write(append(hdr, wire...))
	}
	if err != nil {
		fmt.Println("error=" + err.Error())
		return
	}
	buf := make([]byte, 65535)
	n, err := c.Read(buf)
	if err != nil {
		fmt.Println("noreply")
		return
	}
	body := buf[:n]
	if netw == "tcp" && n > 2 {
		body = body[2:]
	}
	r := new(dns.Msg)
	if err := r.Unpack(body); err != nil {
		fmt.Println("error=" + err.Error())
		return
	}
	var ans []string
	for _, rr := range r.Answer {
		ans = append(ans, strings.Join(strings.Fields(rr.String())[3:], " "))
	}
	fmt.Printf("rcode=%s aa=%v answers=%s records=%d\n", dns.RcodeToString[r.Rcode], r.Authoritative, strings.Join(ans, ";"), len(r.Answer))
}
