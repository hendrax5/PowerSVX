package server

import (
	"net"
	"strings"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/proxyproto"
)

// proxyMode reads [server] proxy_protocol. Unknown values mean "optional": a typo must not
// turn the Auth Backend into something that refuses its Dataplane.
func (s *Server) proxyMode() (proxyproto.Mode, bool) {
	v := "optional"
	if s.cfg != nil && strings.TrimSpace(s.cfg.Server.ProxyProtocol) != "" {
		v = strings.ToLower(strings.TrimSpace(s.cfg.Server.ProxyProtocol))
	}
	switch v {
	case "off", "false", "no", "0":
		return 0, false
	case "required":
		return proxyproto.Required, true
	case "optional":
		return proxyproto.Optional, true
	}
	if s.log != nil {
		s.log.Warn("unknown [server] proxy_protocol value, using \"optional\"", "value", v)
	}
	return proxyproto.Optional, true
}

// listenProxied runs the Auth Backend listeners behind the PROXY protocol wrappers: one UDP
// socket (a PacketConn the wrapper reads datagrams from; the SO_REUSEPORT shards of the plain
// path need the concrete UDP socket) and one TCP listener.
func (s *Server) listenProxied(mode proxyproto.Mode, udpAddr, tcpAddr string, tsigMap map[string]string,
	accept dns.MsgAcceptFunc, invalid dns.MsgInvalidFunc, decorate dns.DecorateReader, handler dns.Handler) error {
	pc, err := net.ListenPacket("udp", udpAddr)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", tcpAddr)
	if err != nil {
		_ = pc.Close()
		return err
	}
	name := map[proxyproto.Mode]string{proxyproto.Optional: "optional", proxyproto.Required: "required"}[mode]
	errCh := make(chan error, 2)
	udp := &dns.Server{PacketConn: &proxyproto.PacketConn{PacketConn: pc, Mode: mode}, Net: "udp", Handler: handler,
		UDPSize: int(s.udpBufSize()), MsgAcceptFunc: accept, MsgInvalidFunc: invalid, TsigSecret: tsigMap, DecorateReader: decorate}
	s.addUDP(udp, true)
	tcp := &dns.Server{Listener: &proxyproto.Listener{Listener: ln, Mode: mode}, Net: "tcp", Handler: handler,
		MsgAcceptFunc: accept, MsgInvalidFunc: invalid, TsigSecret: tsigMap, DecorateReader: decorate}
	s.setTCP(tcp)
	go func() {
		s.log.Info("UDP listener starting", "addr", udpAddr, "proxy_protocol", name)
		errCh <- udp.ActivateAndServe()
	}()
	go func() {
		s.log.Info("TCP listener starting", "addr", tcpAddr, "proxy_protocol", name)
		errCh <- tcp.ActivateAndServe()
	}()
	return <-errCh
}

func (s *Server) addUDP(srv *dns.Server, first bool) {
	s.lnMu.Lock()
	defer s.lnMu.Unlock()
	if first {
		s.udp = srv
	}
	s.udps = append(s.udps, srv)
}

func (s *Server) setTCP(srv *dns.Server) {
	s.lnMu.Lock()
	defer s.lnMu.Unlock()
	s.tcp = srv
}
