package recursive

import "testing"

func TestDelegCacheAncestorMatch(t *testing.T) {
	d := newDelegCache()
	d.put("com.", []string{"192.0.2.1:53", "192.0.2.2:53"}, 300)

	// A qname under .com should find the cached com. delegation.
	if got := d.get("example.com."); len(got) != 2 {
		t.Fatalf("expected ancestor (com.) delegation, got %v", got)
	}
	if got := d.get("a.b.example.com."); len(got) != 2 {
		t.Fatalf("expected deep ancestor match, got %v", got)
	}
	// Unrelated TLD => miss.
	if got := d.get("example.net."); got != nil {
		t.Fatalf("expected miss for .net, got %v", got)
	}

	// More specific delegation should win over the ancestor.
	d.put("example.com.", []string{"198.51.100.1:53"}, 300)
	got := d.get("www.example.com.")
	if len(got) != 1 || got[0] != "198.51.100.1:53" {
		t.Fatalf("expected most-specific (example.com.) delegation, got %v", got)
	}
}

func TestDelegCacheExpiry(t *testing.T) {
	d := newDelegCache()
	d.put("com.", []string{"192.0.2.1:53"}, 0) // ttl 0 => not stored
	if d.get("x.com.") != nil {
		t.Fatal("ttl=0 entries must not be cached")
	}
}
