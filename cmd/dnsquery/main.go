package main

import (
	"fmt"
	"os"
	"time"

	"github.com/miekg/dns"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <server:port> <name> [type]\n", os.Args[0])
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
	c := &dns.Client{Timeout: 5 * time.Second}
	start := time.Now()
	resp, _, err := c.Exchange(m, server)
	elapsed := time.Since(start)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("rcode=%s answers=%d ms=%d\n", dns.RcodeToString[resp.Rcode], len(resp.Answer), elapsed.Milliseconds())
	for _, rr := range resp.Answer {
		fmt.Println(rr.String())
	}
}
