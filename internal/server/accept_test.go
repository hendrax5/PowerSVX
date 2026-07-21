package server

import (
	"testing"

	"github.com/miekg/dns"
)

func TestMsgAcceptAllowsDigEDNSExtras(t *testing.T) {
	dh := dns.Header{Qdcount: 1, Ancount: 0, Nscount: 0, Arcount: 5}
	if msgAcceptFunc(dh) != dns.MsgAccept {
		t.Fatal("expected accept for dig-style additional section")
	}
	dh.Arcount = 33
	if msgAcceptFunc(dh) != dns.MsgAccept {
		t.Fatal("expected accept even with large arcount")
	}
	dh.Arcount = 0
	dh.Qdcount = 0
	if msgAcceptFunc(dh) != dns.MsgReject {
		t.Fatal("expected reject for empty question")
	}
	dh.Qdcount = 1
	dh.Bits = 0x8000 // QR
	if msgAcceptFunc(dh) != dns.MsgIgnore {
		t.Fatal("expected ignore for response bit")
	}
}
