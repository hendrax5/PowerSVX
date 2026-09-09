package server

import (
	"testing"

	"github.com/miekg/dns"
)

func TestRepairEDNSRootNameGoogleCookie(t *testing.T) {
	bad := mustHex("0b350100000100000000000106676f6f676c6503636f6d0000010001010029100000000000000c000a0008121badeb9ce77e55")
	msg := new(dns.Msg)
	if err := msg.Unpack(bad); err == nil {
		t.Fatal("expected unpack fail on broken OPT name")
	}
	fixed := repairEDNSRootName(bad)
	if err := msg.Unpack(fixed); err != nil {
		t.Fatalf("repaired unpack: %v", err)
	}
	if got := msg.Question[0].Name; got != "google.com." {
		t.Fatalf("qname=%q", got)
	}
	if msg.IsEdns0() == nil {
		t.Fatal("expected OPT after repair")
	}
}

func mustHex(s string) []byte {
	b := make([]byte, len(s)/2)
	for i := 0; i < len(b); i++ {
		b[i] = unhex(s[i*2])<<4 | unhex(s[i*2+1])
	}
	return b
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}
