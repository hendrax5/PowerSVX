package server

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/miekg/dns"
)

func TestDecodeDoHGET_RFC8484(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	wire, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	q := base64.RawURLEncoding.EncodeToString(wire)
	req := httptest.NewRequest(http.MethodGet, "/dns-query?dns="+q, nil)
	got, err := decodeDoHGET(req)
	if err != nil {
		t.Fatal(err)
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(got); err != nil {
		t.Fatal(err)
	}
	if msg.Question[0].Name != "example.com." {
		t.Fatalf("got %s", msg.Question[0].Name)
	}
}

func TestDecodeDoHGET_ConvenienceName(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/dns-query?name=example.com&type=AAAA", nil)
	got, err := decodeDoHGET(req)
	if err != nil {
		t.Fatal(err)
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(got); err != nil {
		t.Fatal(err)
	}
	if msg.Question[0].Qtype != dns.TypeAAAA {
		t.Fatalf("type=%d", msg.Question[0].Qtype)
	}
}

func TestDecodeDoHGET_MissingParams(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/dns-query", nil)
	_, err := decodeDoHGET(req)
	if err != errDoHUsage {
		t.Fatalf("expected usage err, got %v", err)
	}
}
