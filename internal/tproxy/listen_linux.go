//go:build linux

package tproxy

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// ListenUDP binds a UDP socket with IP_TRANSPARENT for Linux TPROXY.
func ListenUDP(network, address string) (net.PacketConn, error) {
	var lc net.ListenConfig
	lc.Control = transparentControl
	return lc.ListenPacket(context.Background(), network, address)
}

// ListenTCP binds a TCP socket with IP_TRANSPARENT for Linux TPROXY.
func ListenTCP(network, address string) (net.Listener, error) {
	var lc net.ListenConfig
	lc.Control = transparentControl
	return lc.Listen(context.Background(), network, address)
}

func transparentControl(_, _ string, c syscall.RawConn) error {
	var opErr error
	if err := c.Control(func(fd uintptr) {
		f := int(fd)
		_ = unix.SetsockoptInt(f, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
		// SO_REUSEPORT lets multiple TPROXY UDP sockets share :53 (one per CPU).
		_ = unix.SetsockoptInt(f, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		err4 := unix.SetsockoptInt(f, unix.SOL_IP, unix.IP_TRANSPARENT, 1)
		err6 := unix.SetsockoptInt(f, unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
		// Success if either address family accepts IP_TRANSPARENT.
		if err4 != nil && err6 != nil {
			opErr = err4
		}
	}); err != nil {
		return err
	}
	return opErr
}
