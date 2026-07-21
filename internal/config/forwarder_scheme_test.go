package config

import "testing"

func TestNormalizeForwarderSchemes(t *testing.T) {
	got, err := NormalizeForwarder("tls://one.one.one.one")
	if err != nil {
		t.Fatal(err)
	}
	if got != "tls://one.one.one.one:853" {
		t.Fatalf("got %q", got)
	}
	got, err = NormalizeForwarder("tls://1.1.1.1:853#cloudflare-dns.com")
	if err != nil || got != "tls://1.1.1.1:853#cloudflare-dns.com" {
		t.Fatalf("got %q err=%v", got, err)
	}
	got, err = NormalizeForwarder("https://cloudflare-dns.com/dns-query")
	if err != nil || got != "https://cloudflare-dns.com/dns-query" {
		t.Fatalf("got %q err=%v", got, err)
	}
	got, err = NormalizeForwarder("8.8.8.8")
	if err != nil || got != "8.8.8.8:53" {
		t.Fatalf("got %q err=%v", got, err)
	}
	if _, err := NormalizeForwarder("http://bad.example/dns-query"); err == nil {
		t.Fatal("http should fail")
	}
}

func TestParseForwardTarget(t *testing.T) {
	tg, err := ParseForwardTarget("tls://dns.google:853")
	if err != nil || tg.Network != "tcp-tls" || tg.ServerName != "dns.google" || tg.Addr != "dns.google:853" {
		t.Fatalf("%+v err=%v", tg, err)
	}
	tg, err = ParseForwardTarget("https://dns.google/dns-query")
	if err != nil || tg.Network != "https" || tg.URL == "" {
		t.Fatalf("%+v err=%v", tg, err)
	}
}
