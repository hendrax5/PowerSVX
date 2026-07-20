package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <host:port> <name> [type]\n", os.Args[0])
		os.Exit(2)
	}
	addr := os.Args[1]
	name := os.Args[2]
	qtype := dns.TypeA
	if len(os.Args) > 3 {
		if t, ok := dns.StringToType[os.Args[3]]; ok {
			qtype = t
		}
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.Id = 0
	m.RecursionDesired = true
	wire, err := m.Pack()
	if err != nil {
		fatal(err)
	}

	tlsConf := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"doq"}, ServerName: "localhost"}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, addr, tlsConf, nil)
	if err != nil {
		fatal(err)
	}
	defer func() { _ = conn.CloseWithError(0, "") }()

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		fatal(err)
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(wire)))
	if _, err := stream.Write(hdr[:]); err != nil {
		fatal(err)
	}
	if _, err := stream.Write(wire); err != nil {
		fatal(err)
	}
	_ = stream.Close()

	var n uint16
	if err := binary.Read(stream, binary.BigEndian, &n); err != nil {
		fatal(err)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(stream, buf); err != nil {
		fatal(err)
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(buf); err != nil {
		fatal(err)
	}
	fmt.Printf("rcode=%s answers=%d\n", dns.RcodeToString[resp.Rcode], len(resp.Answer))
	for _, rr := range resp.Answer {
		fmt.Println(rr.String())
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
