package tproxy

import "testing"

func TestNormalizeMode(t *testing.T) {
	cases := map[string]string{
		"": "public", "PUBLIC": "public", "all": "all", "Custom": "custom", "x": "public",
	}
	for in, want := range cases {
		if got := normalizeMode(in); got != want {
			t.Fatalf("normalizeMode(%q)=%q want %q", in, got, want)
		}
	}
}

func TestUniqueIPs(t *testing.T) {
	got := uniqueIPs([]string{"8.8.8.8", " 1.1.1.1 ", "8.8.8.8", "not-ip", "2001:db8::1", ""})
	if len(got) != 2 || got[0] != "8.8.8.8" || got[1] != "1.1.1.1" {
		t.Fatalf("got %#v", got)
	}
}

func TestResolversFor(t *testing.T) {
	pub := resolversFor(InterceptConfig{Mode: "public"})
	if len(pub) < 4 {
		t.Fatalf("public resolvers too short: %d", len(pub))
	}
	all := resolversFor(InterceptConfig{Mode: "all"})
	if all != nil {
		t.Fatalf("all mode should have nil resolvers, got %v", all)
	}
	custom := resolversFor(InterceptConfig{Mode: "custom", Resolvers: []string{"9.9.9.9"}})
	if len(custom) != 1 || custom[0] != "9.9.9.9" {
		t.Fatalf("custom: %#v", custom)
	}
}

func TestSupported(t *testing.T) {
	_ = Supported() // platform-dependent; just ensure it does not panic
}
