// Package server runs the UDP and TCP DNS listeners (Phase 3 request path +
// Phase 4 socket tuning).
//
//   - UDP uses SO_REUSEPORT with one bound socket per worker so the kernel load
//     balances datagrams across workers without a shared user-space queue. Each
//     worker is a single goroutine running a recv->process->send loop (NO
//     goroutine-per-request), with a per-worker reusable read buffer.
//   - SO_RCVBUF / SO_SNDBUF are raised per socket for burst tolerance.
//   - TCP uses a bounded accept model (goroutine per connection, which is fine
//     because TCP volume is a small fraction of UDP).
package server

import (
	"context"
	"net"
	"sync"
	"syscall"

	"github.com/miekg/dns"
	"golang.org/x/sys/unix"

	"powersvx/internal/config"
	"powersvx/internal/logx"
)

// Handler turns a parsed query into a reply. nil => drop.
type Handler func(*dns.Msg) *dns.Msg

type Server struct {
	cfg     *config.Config
	handler Handler
	log     *logx.Logger
	wg      sync.WaitGroup
	conns   []net.PacketConn
	tcpLn   net.Listener
}

func New(cfg *config.Config, h Handler, log *logx.Logger) *Server {
	return &Server{cfg: cfg, handler: h, log: log}
}

func (s *Server) Start(ctx context.Context) error {
	// UDP reuseport workers.
	for i := 0; i < s.cfg.Workers; i++ {
		pc, err := s.listenUDP()
		if err != nil {
			return err
		}
		s.conns = append(s.conns, pc)
		s.wg.Add(1)
		go s.udpWorker(pc)
	}

	// Single TCP listener (also reuseport-capable) with per-conn handling.
	ln, err := s.listenTCP()
	if err != nil {
		return err
	}
	s.tcpLn = ln
	s.wg.Add(1)
	go s.tcpAccept(ln)

	go func() {
		<-ctx.Done()
		s.Close()
	}()
	return nil
}

func (s *Server) Close() {
	for _, c := range s.conns {
		c.Close()
	}
	if s.tcpLn != nil {
		s.tcpLn.Close()
	}
}

func (s *Server) Wait() { s.wg.Wait() }

// controlFn applies SO_REUSEPORT + buffer sizes to each new socket.
func (s *Server) controlFn(network, address string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		f := int(fd)
		if s.cfg.Socket.ReusePort {
			if e := unix.SetsockoptInt(f, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); e != nil {
				serr = e
				return
			}
		}
		unix.SetsockoptInt(f, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
		if s.cfg.Socket.RcvBuf > 0 {
			unix.SetsockoptInt(f, unix.SOL_SOCKET, unix.SO_RCVBUF, s.cfg.Socket.RcvBuf)
		}
		if s.cfg.Socket.SndBuf > 0 {
			unix.SetsockoptInt(f, unix.SOL_SOCKET, unix.SO_SNDBUF, s.cfg.Socket.SndBuf)
		}
	})
	if err != nil {
		return err
	}
	return serr
}

func (s *Server) listenUDP() (net.PacketConn, error) {
	lc := net.ListenConfig{Control: s.controlFn}
	return lc.ListenPacket(context.Background(), "udp", s.cfg.Addr())
}

func (s *Server) listenTCP() (net.Listener, error) {
	lc := net.ListenConfig{Control: s.controlFn}
	return lc.Listen(context.Background(), "tcp", s.cfg.Addr())
}

func (s *Server) udpWorker(pc net.PacketConn) {
	defer s.wg.Done()
	buf := make([]byte, 65535) // reused across iterations, single-threaded loop
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return // socket closed on shutdown
		}
		req := new(dns.Msg)
		if err := req.Unpack(buf[:n]); err != nil {
			continue
		}
		resp := s.handler(req)
		if resp == nil {
			continue // RPZ drop
		}
		// Respect the client's advertised UDP size; set TC to trigger TCP retry
		// rather than sending a fragmented/oversized datagram.
		udpsize := 512
		if opt := req.IsEdns0(); opt != nil {
			if sz := int(opt.UDPSize()); sz > udpsize {
				udpsize = sz
			}
		}
		resp.Truncate(udpsize)
		out, err := resp.Pack()
		if err != nil {
			continue
		}
		pc.WriteTo(out, addr)
	}
}

func (s *Server) tcpAccept(ln net.Listener) {
	defer s.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go s.handleTCPConn(conn)
	}
}

func (s *Server) handleTCPConn(conn net.Conn) {
	defer conn.Close()
	c := &dns.Conn{Conn: conn}
	for {
		req, err := c.ReadMsg()
		if err != nil {
			return
		}
		resp := s.handler(req)
		if resp == nil {
			return
		}
		if err := c.WriteMsg(resp); err != nil {
			return
		}
	}
}
