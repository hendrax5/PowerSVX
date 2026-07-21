package allowlist

import "testing"

func TestAddAllowsParent(t *testing.T) {
	l := New("")
	if _, err := l.Add("example.com"); err != nil {
		t.Fatal(err)
	}
	if !l.Allows("example.com") {
		t.Fatal("exact")
	}
	if !l.Allows("ads.example.com") {
		t.Fatal("parent should allow")
	}
	if l.Allows("other.com") {
		t.Fatal("other")
	}
	if ok, err := l.Remove("example.com"); !ok || err != nil {
		t.Fatalf("remove %v %v", ok, err)
	}
	if l.Allows("ads.example.com") {
		t.Fatal("removed")
	}
}

func TestWildcard(t *testing.T) {
	l := New("")
	if _, err := l.Add("*.blocked.test"); err != nil {
		t.Fatal(err)
	}
	if !l.Allows("a.blocked.test") {
		t.Fatal("wild")
	}
}
