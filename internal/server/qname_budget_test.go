package server

import (
	"strings"
	"testing"
)

func TestQnameTooDeep(t *testing.T) {
	ok := []string{
		"google.com.",
		"www.google.com.",
		"putatgede.kendalkab.go.id.",
		"prod-lt-playstoregatewayadapter-pa.googleapis.com.",
		"www.spanishfood.stage.origin.rivian.com.",
		"a.b.c.d.e.f.example.com.",
	}
	for _, n := range ok {
		if qnameTooDeep(n) {
			t.Fatalf("should allow %q", n)
		}
	}
	if !qnameTooDeep("a.b.c.d.e.f.g.example.com.") {
		t.Fatal("9 labels should reject")
	}
	if !qnameTooDeep(strings.Repeat("x", 201) + ".com.") {
		t.Fatal("overlong name should reject")
	}
}
