// Package server runs the UDP and TCP DNS listeners (Phase 3 request path +
// Phase 4 socket tuning).
//
//   - UDP uses SO_REUSEPORT with one bound socket per worker so the kernel load
//     balances datagrams across workers without a shared user-space queue. Each
//     worker is a single goroutine (NO goroutine-per-request) with reusable
//     buffers and sync.Pool-backed message/packing reuse.
//   - When socket.batch is set, each worker drains packets with recvmmsg and
//     replies with sendmmsg (via golang.org/x/net/ipv4), amortizing syscalls
//     across many packets per call.
//   - SO_RCVBUF / SO_SNDBUF are raised per socket for burst tolerance.
//   - TCP uses a bounded accept model (goroutine per connection; TCP volume is a
//     small fraction of UDP).
package server

import (
	"context"
	"net"
	"sync"
	"syscall"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"

	"powersvx/internal/config"
	"powersvx/internal/dnspool"
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
	for i := 0; i < s.cfg.Workers; i++ {
		pc, err := s.listenUDP()
		if err != nil {
			return err
		}
		s.conns = append(s.conns, pc)
		s.wg.Add(1)
		if s.cfg.Socket.Batch {
			go s.udpBatchWorker(pc)
		} else {
			go s.udpWorker(pc)
		}
	}

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

// udpWorker is the classic one-packet-per-syscall loop with pooled msg/buffers.
func (s *Server) udpWorker(pc net.PacketConn) {
	defer s.wg.Done()
	buf := make([]byte, 65535) // reused across iterations, single-threaded loop
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		out, ok := s.process(buf[:n])
		if !ok {
			continue
		}
		pc.WriteTo(*out, addr)
		dnspool.PutBuf(out)
	}
}

// batchConn abstracts the recvmmsg/sendmmsg batch API shared by ipv4 and ipv6
// PacketConns. ipv4.Message and ipv6.Message are aliases for the same underlying
// type, so a single []ipv4.Message works for both.
type batchConn interface {
	ReadBatch(ms []ipv4.Message, flags int) (int, error)
	WriteBatch(ms []ipv4.Message, flags int) (int, error)
}

// udpBatchWorker drains multiple datagrams per recvmmsg and replies with a
// single sendmmsg. It auto-selects the IPv4 or IPv6 batch path based on the
// listening socket's address family so v6 traffic gets the same syscall savings.
func (s *Server) udpBatchWorker(pc net.PacketConn) {
	defer s.wg.Done()
	uc, ok := pc.(*net.UDPConn)
	if !ok {
		s.udpWorker(pc) // fallback
		return
	}
	var bc batchConn
	if isIPv6(uc) {
		bc = ipv6.NewPacketConn(uc)
	} else {
		bc = ipv4.NewPacketConn(uc)
	}

	bs := s.cfg.Socket.BatchSize
	if bs < 1 {
		bs = 1
	}
	rms := make([]ipv4.Message, bs)
	for i := range rms {
		rms[i].Buffers = [][]byte{make([]byte, 65535)}
	}
	wms := make([]ipv4.Message, bs)
	wbufs := make([][]byte, bs)
	for i := range wbufs {
		wbufs[i] = make([]byte, 0, 1232)
	}

	for {
		n, err := bc.ReadBatch(rms, 0)
		if err != nil {
			return
		}
		w := 0
		for i := 0; i < n; i++ {
			data := rms[i].Buffers[0][:rms[i].N]
			out := s.processInto(data, wbufs[w][:0])
			if out == nil {
				continue
			}
			wbufs[w] = out
			wms[w].Buffers = [][]byte{out}
			wms[w].Addr = rms[i].Addr
			w++
		}
		for off := 0; off < w; {
			nw, err := bc.WriteBatch(wms[off:w], 0)
			if err != nil || nw <= 0 {
				break
			}
			off += nw
		}
	}
}

func isIPv6(uc *net.UDPConn) bool {
	la, ok := uc.LocalAddr().(*net.UDPAddr)
	if !ok {
		return false
	}
	return la.IP.To4() == nil && la.IP.To16() != nil
}

// process unpacks a query, runs the handler, and returns a pooled buffer holding
// the packed reply (caller must PutBuf). ok=false means "nothing to send".
func (s *Server) process(data []byte) (*[]byte, bool) {
	req := dnspool.GetMsg()
	if err := req.Unpack(data); err != nil {
		dnspool.PutMsg(req)
		return nil, false
	}
	udpsize := udpSize(req)
	resp := s.handler(req)
	dnspool.PutMsg(req)
	if resp == nil {
		return nil, false
	}
	resp.Truncate(udpsize)
	bp := dnspool.GetBuf()
	out, err := resp.PackBuffer(*bp)
	dnspool.PutMsg(resp)
	if err != nil {
		dnspool.PutBuf(bp)
		return nil, false
	}
	*bp = out
	return bp, true
}

// processInto packs the reply into dst (a per-worker reusable buffer) and
// returns the resulting slice, or nil if nothing to send. No pool involved so
// the batch worker can retain buffer capacity across iterations.
func (s *Server) processInto(data, dst []byte) []byte {
	req := dnspool.GetMsg()
	if err := req.Unpack(data); err != nil {
		dnspool.PutMsg(req)
		return nil
	}
	udpsize := udpSize(req)
	resp := s.handler(req)
	dnspool.PutMsg(req)
	if resp == nil {
		return nil
	}
	resp.Truncate(udpsize)
	out, err := resp.PackBuffer(dst)
	dnspool.PutMsg(resp)
	if err != nil {
		return nil
	}
	return out
}

func udpSize(req *dns.Msg) int {
	size := 512
	if opt := req.IsEdns0(); opt != nil {
		if sz := int(opt.UDPSize()); sz > size {
			size = sz
		}
	}
	return size
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
