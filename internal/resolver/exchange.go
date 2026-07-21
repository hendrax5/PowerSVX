package resolver

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/config"
)

func (r *Resolver) exchangeUpstream(ctx context.Context, msg *dns.Msg, target config.ForwardTarget) (*dns.Msg, error) {
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	switch target.Network {
	case "https":
		return r.exchangeDoH(ctx, msg, target, timeout)
	case "tcp-tls":
		return r.exchangeDoT(ctx, msg, target, timeout)
	default:
		c := r.client
		if c == nil {
			c = &dns.Client{Net: "udp", Timeout: timeout, UDPSize: r.BufSize}
		}
		type result struct {
			resp *dns.Msg
			err  error
		}
		ch := make(chan result, 1)
		go func() {
			resp, _, err := c.Exchange(msg, target.Addr)
			ch <- result{resp, err}
		}()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case res := <-ch:
			return res.resp, res.err
		}
	}
}

func (r *Resolver) exchangeDoT(ctx context.Context, msg *dns.Msg, target config.ForwardTarget, timeout time.Duration) (*dns.Msg, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if target.ServerName != "" {
		tlsCfg.ServerName = target.ServerName
	} else {
		// IP without SNI: still attempt TLS (common for lab); production should use hostname or #sni.
		tlsCfg.InsecureSkipVerify = true
	}
	c := &dns.Client{
		Net:       "tcp-tls",
		Timeout:   timeout,
		UDPSize:   r.BufSize,
		TLSConfig: tlsCfg,
	}
	type result struct {
		resp *dns.Msg
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		resp, _, err := c.Exchange(msg, target.Addr)
		ch <- result{resp, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		return res.resp, res.err
	}
}

func (r *Resolver) exchangeDoH(ctx context.Context, msg *dns.Msg, target config.ForwardTarget, timeout time.Duration) (*dns.Msg, error) {
	wire, err := msg.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.URL, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				ServerName: target.ServerName,
			},
			DialContext: (&net.Dialer{Timeout: timeout}).DialContext,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh status %d", resp.StatusCode)
	}
	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, err
	}
	return out, nil
}
