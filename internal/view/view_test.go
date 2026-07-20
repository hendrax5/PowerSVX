package view

import "testing"

func TestMatchInternal(t *testing.T) {
	m := FromConfig(true, "default", map[string][]string{
		"internal": {"10.0.0.0/8", "192.168.0.0/16"},
		"vpn":      {"100.64.0.0/10"},
	})
	if m.Match("10.1.2.3") != "internal" {
		t.Fatal(m.Match("10.1.2.3"))
	}
	if m.Match("100.64.1.1") != "vpn" {
		t.Fatal(m.Match("100.64.1.1"))
	}
	if m.Match("8.8.8.8") != "default" {
		t.Fatal(m.Match("8.8.8.8"))
	}
}

func TestDisabled(t *testing.T) {
	m := FromConfig(false, "default", map[string][]string{"internal": {"10.0.0.0/8"}})
	if m.Match("10.0.0.1") != "default" {
		t.Fatal("disabled should return default")
	}
}
