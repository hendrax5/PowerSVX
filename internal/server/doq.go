package server

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

const (
	doqALPN            = "doq"
	doqProtocolError   = 0x2
	doqNoError         = 0x0
	doqStreamReadLimit = 65537
)

func (s *Server) startDoQ(ctx context.Context, addr string) error {
	tlsConf := s.tlsCfg.Clone()
	tlsConf.NextProtos = []string{doqALPN}

	ln, err := quic.ListenAddr(addr, tlsConf, &quic.Config{
		MaxIdleTimeout:        5 * time.Minute,
		MaxIncomingStreams:    256,
		MaxIncomingUniStreams: 0,
		Allow0RTT:             false,
	})
	if err != nil {
		return err
	}
	s.doqLn = ln
	s.doqOn = true

	go func() {
		for {
			conn, err := ln.Accept(ctx)
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					s.log.Debug("doq accept", "err", err)
					return
				}
			}
			go s.serveDoQConn(ctx, conn)
		}
	}()
	return nil
}

func (s *Server) serveDoQConn(ctx context.Context, conn *quic.Conn) {
	defer func() { _ = conn.CloseWithError(doqNoError, "") }()
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go s.handleDoQStream(conn, stream)
	}
}

func (s *Server) handleDoQStream(conn *quic.Conn, stream *quic.Stream) {
	defer func() { _ = stream.Close() }()
	_ = stream.SetReadDeadline(time.Now().Add(10 * time.Second))

	wire, err := readDoQMessage(stream)
	if err != nil {
		_ = conn.CloseWithError(doqProtocolError, "bad framing")
		return
	}
	req := new(dns.Msg)
	if err := req.Unpack(wire); err != nil {
		_ = conn.CloseWithError(doqProtocolError, "bad dns")
		return
	}
	// RFC 9250: Message ID MUST be 0
	if req.Id != 0 {
		_ = conn.CloseWithError(doqProtocolError, "nonzero id")
		return
	}

	_, respWire, err := s.ServeDNSMsg(req)
	if err != nil || len(respWire) == 0 {
		return
	}
	// Force ID 0 on response
	if len(respWire) >= 2 {
		respWire[0], respWire[1] = 0, 0
	}
	_ = stream.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := writeDoQMessage(stream, respWire); err != nil {
		return
	}
}

func readDoQMessage(r io.Reader) ([]byte, error) {
	var n uint16
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	if n == 0 || int(n) > doqStreamReadLimit {
		return nil, errors.New("invalid doq length")
	}
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return buf, err
}

func writeDoQMessage(w io.Writer, payload []byte) error {
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}
