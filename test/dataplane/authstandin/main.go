// Command authstandin stands in for the Auth Backend behind dnsdist in the Dataplane tests.
// It answers UDP queries on the given address like the Auth Backend does: with a PROXY
// protocol v2 header in front of the query when dnsdist sends one (the default mode), or
// plain. It uses the production parser, so the test exercises the same header handling.
// It prints one line per query, "query <name> proxy=<client address|none>", and answers
// www.hosted.powersvx.test with 192.0.2.9, anything else with NXDOMAIN.
//
//	authstandin <listen address>
package main

import (
	"fmt"
	"net"
	"os"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/proxyproto"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: authstandin <listen address>")
		os.Exit(2)
	}
	pc, err := net.ListenPacket("udp", os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
	fmt.Println("ready")
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		msg, client := buf[:n], "none"
		if proxyproto.HasPrefix(msg) {
			h, hl, err := proxyproto.Parse(msg)
			if err != nil {
				continue
			}
			msg = msg[hl:]
			client = "local"
			if !h.Local {
				client = h.Src.Addr().String()
			}
		}
		var q dns.Msg
		if q.Unpack(msg) != nil || len(q.Question) == 0 {
			continue
		}
		fmt.Printf("query %s proxy=%s\n", q.Question[0].Name, client)
		r := new(dns.Msg)
		r.SetReply(&q)
		r.Authoritative = true
		if q.Question[0].Name == "www.hosted.powersvx.test." {
			if q.Question[0].Qtype == dns.TypeA {
				r.Answer = append(r.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.9")})
			}
		} else {
			r.Rcode = dns.RcodeNameError
		}
		if out, err := r.Pack(); err == nil {
			_, _ = pc.WriteTo(out, from)
		}
	}
}
