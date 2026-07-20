package server

import "testing"

func TestTransferAllowedFrom(t *testing.T) {
	if !transferAllowedFrom(nil, "1.2.3.4") {
		t.Fatal("empty ACL should allow")
	}
	if !transferAllowedFrom([]string{"10.0.0.0/8"}, "10.1.2.3") {
		t.Fatal("cidr miss")
	}
	if transferAllowedFrom([]string{"10.0.0.0/8"}, "192.168.1.1") {
		t.Fatal("should deny")
	}
	if !transferAllowedFrom([]string{"192.0.2.10"}, "192.0.2.10") {
		t.Fatal("exact IP")
	}
}
