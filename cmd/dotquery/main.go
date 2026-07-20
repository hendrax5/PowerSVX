package main

import (
	"crypto/tls"
	"fmt"
	"os"
	"time"

	"github.com/miekg/dns"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <host:port> <name> [type]\n", os.Args[0])
		os.Exit(2)
	}
	server := os.Args[1]
	name := os.Args[2]
	qtype := dns.TypeA
	if len(os.Args) > 3 {
		if t, ok := dns.StringToType[os.Args[3]]; ok {
			qtype = t
		}
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	c := &dns.Client{
		Net:     "tcp-tls",
		Timeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "localhost",
		},
	}
	start := time.Now()
	resp, _, err := c.Exchange(m, server)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("rcode=%s answers=%d ad=%v ms=%d\n", dns.RcodeToString[resp.Rcode], len(resp.Answer), resp.AuthenticatedData, time.Since(start).Milliseconds())
	for _, rr := range resp.Answer {
		fmt.Println(rr.String())
	}
}
