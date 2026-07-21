package config

import "testing"

func TestNormalizeResolverModeDefaultRecursive(t *testing.T) {
	if NormalizeResolverMode("") != "recursive" {
		t.Fatal(NormalizeResolverMode(""))
	}
	if NormalizeResolverMode("FORWARD") != "forward" {
		t.Fatal(NormalizeResolverMode("FORWARD"))
	}
}

func TestNormalizeForwarders(t *testing.T) {
	got, err := NormalizeForwarders([]string{"1.1.1.1", "8.8.8.8:53", "1.1.1.1:53"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "1.1.1.1:53" || got[1] != "8.8.8.8:53" {
		t.Fatalf("%v", got)
	}
	if _, err := NormalizeForwarders([]string{"bad host"}); err == nil {
		t.Fatal("expected error")
	}
}
