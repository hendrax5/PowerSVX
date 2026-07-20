package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/miekg/dns"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <https://host:port/dns-query> <name> [type]\n", os.Args[0])
		os.Exit(2)
	}
	url := os.Args[1]
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
	wire, err := m.Pack()
	if err != nil {
		fatal(err)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // self-signed ok for smoke test
		},
	}

	// POST
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(wire))
	if err != nil {
		fatal(err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	elapsed := time.Since(start)
	if resp.StatusCode != 200 {
		fatal(fmt.Errorf("POST status %d: %s", resp.StatusCode, body))
	}
	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		fatal(err)
	}
	fmt.Printf("POST rcode=%s answers=%d ad=%v ms=%d\n", dns.RcodeToString[out.Rcode], len(out.Answer), out.AuthenticatedData, elapsed.Milliseconds())
	for _, rr := range out.Answer {
		fmt.Println(rr.String())
	}

	// GET
	q := base64.RawURLEncoding.EncodeToString(wire)
	getURL := url
	if bytes.Contains([]byte(url), []byte("?")) {
		getURL += "&dns=" + q
	} else {
		getURL += "?dns=" + q
	}
	gresp, err := client.Get(getURL)
	if err != nil {
		fatal(err)
	}
	gbody, _ := io.ReadAll(gresp.Body)
	_ = gresp.Body.Close()
	if gresp.StatusCode != 200 {
		fatal(fmt.Errorf("GET status %d", gresp.StatusCode))
	}
	gout := new(dns.Msg)
	if err := gout.Unpack(gbody); err != nil {
		fatal(err)
	}
	fmt.Printf("GET  rcode=%s answers=%d ad=%v\n", dns.RcodeToString[gout.Rcode], len(gout.Answer), gout.AuthenticatedData)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
