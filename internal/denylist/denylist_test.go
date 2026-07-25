package denylist

import "testing"

func TestAddBlocksParent(t *testing.T) {
	l := New("")
	if _, err := l.Add("evil.com"); err != nil {
		t.Fatal(err)
	}
	if !l.Blocks("evil.com") {
		t.Fatal("exact")
	}
	if !l.Blocks("ads.evil.com") {
		t.Fatal("parent should block")
	}
	if l.Blocks("other.com") {
		t.Fatal("other")
	}
	if ok, err := l.Remove("evil.com"); !ok || err != nil {
		t.Fatalf("remove %v %v", ok, err)
	}
	if l.Blocks("ads.evil.com") {
		t.Fatal("removed")
	}
}

func TestWildcard(t *testing.T) {
	l := New("")
	if _, err := l.Add("*.blocked.test"); err != nil {
		t.Fatal(err)
	}
	if !l.Blocks("a.blocked.test") {
		t.Fatal("wild")
	}
}
