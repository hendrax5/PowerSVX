package database

import (
	"strings"
	"testing"
)

func TestMaskClientIP(t *testing.T) {
	if got := MaskClientIP("192.168.1.42"); got != "192.168.1.0" {
		t.Fatalf("v4 got %s", got)
	}
	got := MaskClientIP("2001:db8:abcd:0012::1")
	if !strings.HasPrefix(got, "2001:db8:abcd:") {
		t.Fatalf("v6 got %s", got)
	}
}
