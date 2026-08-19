package rpz

import (
	"fmt"
	"math/rand"
	"testing"
)

func TestSuffixAndExactMatch(t *testing.T) {
	z := BuildZone([]string{"evil.com", "ads.example.net", "doubleclick.net"}, ActionNXDOMAIN)
	m := NewMatcher()
	m.Swap(z)

	cases := []struct {
		name string
		want Action
	}{
		{"evil.com.", ActionNXDOMAIN},          // exact
		{"www.evil.com.", ActionNXDOMAIN},      // subdomain
		{"deep.sub.evil.com.", ActionNXDOMAIN}, // deep subdomain
		{"eviltwin.com.", ActionNone},          // must NOT match evil.com
		{"notevil.com.", ActionNone},           // must NOT match
		{"ads.example.net.", ActionNXDOMAIN},   // exact
		{"x.ads.example.net.", ActionNXDOMAIN}, // subdomain
		{"example.net.", ActionNone},           // parent NOT blocked
		{"doubleclick.net.", ActionNXDOMAIN},
		{"clean.org.", ActionNone},
	}
	for _, c := range cases {
		if got := m.Lookup(c.name); got != c.want {
			t.Errorf("Lookup(%q)=%d want %d", c.name, got, c.want)
		}
	}
}

func TestAtomicSwap(t *testing.T) {
	m := NewMatcher()
	m.Swap(BuildZone([]string{"a.com"}, ActionNXDOMAIN))
	if m.Lookup("a.com.") != ActionNXDOMAIN {
		t.Fatal("expected block before swap")
	}
	m.Swap(BuildZone([]string{"b.com"}, ActionNXDOMAIN))
	if m.Lookup("a.com.") != ActionNone {
		t.Error("old rule should be gone after swap")
	}
	if m.Lookup("b.com.") != ActionNXDOMAIN {
		t.Error("new rule should be active after swap")
	}
}

func genDomains(n int) []string {
	r := rand.New(rand.NewSource(1))
	tlds := []string{"com", "net", "org", "io", "co"}
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("d%d-%d.%s", i, r.Int31(), tlds[r.Intn(len(tlds))])
	}
	return out
}

func BenchmarkLookupHitMillion(b *testing.B) {
	domains := genDomains(1_000_000)
	z := BuildZone(domains, ActionNXDOMAIN)
	m := NewMatcher()
	m.Swap(z)
	// Query a domain guaranteed to be present as a subdomain.
	target := "sub." + domains[500000] + "."
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if m.Lookup(target) != ActionNXDOMAIN {
			b.Fatal("expected hit")
		}
	}
}

func BenchmarkLookupMissMillion(b *testing.B) {
	domains := genDomains(1_000_000)
	z := BuildZone(domains, ActionNXDOMAIN)
	m := NewMatcher()
	m.Swap(z)
	target := "random-nonexistent-qname.example.zzz."
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.Lookup(target)
	}
}

func BenchmarkBuildMillion(b *testing.B) {
	domains := genDomains(1_000_000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = BuildZone(domains, ActionNXDOMAIN)
	}
}
