package tsig

import (
	"testing"

	"github.com/miekg/dns"
)

func TestStoreGetNamesAndApply(t *testing.T) {
	s := New()
	if err := s.Set("axfr-key", "c2VjcmV0LWtleS1mb3ItdGVzdGluZw=="); err != nil {
		t.Fatal(err)
	}
	fqdn, sec, ok := s.Get("axfr-key")
	if !ok || fqdn != "axfr-key." || sec == "" {
		t.Fatalf("unexpected Get: fqdn=%q sec=%q ok=%v", fqdn, sec, ok)
	}
	names := s.Names()
	if len(names) != 1 || names[0] != "axfr-key." {
		t.Fatalf("names=%v", names)
	}

	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeSOA)
	secrets := Apply(m, Auth{Name: "axfr-key", Secret: sec})
	if len(secrets) != 1 || secrets["axfr-key."] != sec || m.IsTsig() == nil {
		t.Fatalf("expected signed msg with secret map, got %+v", secrets)
	}
}

func TestSerialGreaterRFC1982(t *testing.T) {
	cases := []struct {
		a, b uint32
		want bool
	}{
		{2, 1, true},
		{1, 1, false},
		{1, 2, false},
		{1, 0xffffffff, true},  // wraparound forward by 2
		{5, 0xfffffff0, true},  // wraparound forward across 0
		{0xfffffff0, 5, false}, // reverse of wraparound
		{0x80000001, 1, false}, // ambiguous boundary (2^31) -> false in RFC 1982
		{0x80000000, 1, true},  // 2^31 - 1 forward -> true
	}
	for _, tc := range cases {
		if got := SerialGreater(tc.a, tc.b); got != tc.want {
			t.Errorf("SerialGreater(%d, %d) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}
