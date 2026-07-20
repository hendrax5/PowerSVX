package bloom

import "testing"

func TestFilterBasic(t *testing.T) {
	f := New(100, 0.01)
	f.Add("evil.example.")
	if !f.MightContain("evil.example.") {
		t.Fatal("expected hit")
	}
	if f.MightContain("clean.example.") {
		t.Fatal("unexpected hit (possible FP but unlikely at n=1)")
	}
}
