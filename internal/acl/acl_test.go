package acl

import "testing"

func TestAllowsEmptyOpen(t *testing.T) {
	l := Open()
	if !l.Allows("8.8.8.8") {
		t.Fatal("open should allow")
	}
}

func TestAllowList(t *testing.T) {
	l, err := Parse([]string{"10.0.0.0/8", "192.168.1.10"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !l.Allows("10.1.2.3") {
		t.Fatal("10/8")
	}
	if !l.Allows("192.168.1.10") {
		t.Fatal("exact")
	}
	if l.Allows("192.168.1.11") {
		t.Fatal("should deny")
	}
}

func TestDenyWins(t *testing.T) {
	l, err := Parse([]string{"10.0.0.0/8"}, []string{"10.0.0.5/32"})
	if err != nil {
		t.Fatal(err)
	}
	if l.Allows("10.0.0.5") {
		t.Fatal("deny should win")
	}
	if !l.Allows("10.0.0.6") {
		t.Fatal("other 10 should allow")
	}
}

func TestParseInvalid(t *testing.T) {
	if _, err := Parse([]string{"not-an-ip"}, nil); err == nil {
		t.Fatal("expected error")
	}
}
