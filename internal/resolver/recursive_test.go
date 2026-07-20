package resolver

import "testing"

func TestRootHintsPresent(t *testing.T) {
	addrs := getRootAddrs()
	if len(addrs) < 13 {
		t.Fatalf("expected >=13 root addrs, got %d", len(addrs))
	}
	for _, a := range addrs {
		if a == "" {
			t.Fatal("empty root addr")
		}
	}
}
