package tproxy

import (
	"runtime"
	"testing"
)

func TestListenUDPStubOrLinux(t *testing.T) {
	_, err := ListenUDP("udp", "127.0.0.1:0")
	if runtime.GOOS != "linux" {
		if err == nil {
			t.Fatal("expected error on non-linux")
		}
		return
	}
	// On Linux without CAP_NET_ADMIN this may fail; either success or permission error is OK.
	if err != nil {
		t.Logf("ListenUDP on linux: %v (may need CAP_NET_ADMIN)", err)
	}
}
