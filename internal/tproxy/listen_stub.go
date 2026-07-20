//go:build !linux

package tproxy

import (
	"fmt"
	"net"
	"runtime"
)

// ListenUDP is unavailable off Linux (no kernel TPROXY / IP_TRANSPARENT).
func ListenUDP(network, address string) (net.PacketConn, error) {
	return nil, fmt.Errorf("tproxy: UDP listen not supported on %s (Linux only)", runtime.GOOS)
}

// ListenTCP is unavailable off Linux (no kernel TPROXY / IP_TRANSPARENT).
func ListenTCP(network, address string) (net.Listener, error) {
	return nil, fmt.Errorf("tproxy: TCP listen not supported on %s (Linux only)", runtime.GOOS)
}
