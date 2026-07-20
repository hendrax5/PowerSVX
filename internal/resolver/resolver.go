package resolver

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/dnssec"
	"github.com/powersvx/powersvx/internal/ecs"
)

// Resolver resolves DNS queries via forward or recursive mode.
type Resolver struct {
	Mode        string
	Forwarders  []string
	Timeout     time.Duration
	BufSize     uint16
	WantDO      bool
	ECSEnabled  bool
	ECSPrefixV4 uint8
	ECSPrefixV6 uint8
	client      *dns.Client
}

func New(cfg config.ResolverConfig) *Resolver {
	timeout := time.Duration(cfg.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	buf := cfg.EDNSBufferSize
	if buf == 0 {
		buf = 1232
	}
	mode := strings.ToLower(cfg.Mode)
	if mode == "" {
		mode = "forward"
	}
	secMode := dnssec.ParseMode(cfg.DNSSECMode, cfg.DNSSECValidation)
	v4, v6 := cfg.ECSPrefixV4, cfg.ECSPrefixV6
	if v4 == 0 {
		v4 = 24
	}
	if v6 == 0 {
		v6 = 56
	}
	return &Resolver{
		Mode:        mode,
		Forwarders:  cfg.Forwarders,
		Timeout:     timeout,
		BufSize:     buf,
		WantDO:      secMode != dnssec.ModeOff,
		ECSEnabled:  cfg.ECSEnabled,
		ECSPrefixV4: v4,
		ECSPrefixV6: v6,
		client: &dns.Client{
			Net:     "udp",
			Timeout: timeout,
			UDPSize: buf,
		},
	}
}

func (r *Resolver) Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	return r.ResolveWithECS(ctx, req, nil)
}

// ResolveWithECS forwards/resolves, optionally attaching ECS subnet.
func (r *Resolver) ResolveWithECS(ctx context.Context, req *dns.Msg, sub *ecs.Subnet) (*dns.Msg, error) {
	if len(req.Question) == 0 {
		return nil, fmt.Errorf("empty question")
	}
	q := req.Question[0]
	q.Name = config.NormalizeName(q.Name)

	switch r.Mode {
	case "recursive":
		msg, err := r.resolveRecursive(ctx, q.Name, q.Qtype)
		if err != nil && len(r.Forwarders) > 0 {
			return r.forward(ctx, req, sub)
		}
		return msg, err
	default:
		return r.forward(ctx, req, sub)
	}
}

func (r *Resolver) forward(ctx context.Context, req *dns.Msg, sub *ecs.Subnet) (*dns.Msg, error) {
	if len(r.Forwarders) == 0 {
		return nil, fmt.Errorf("no forwarders configured")
	}
	var lastErr error
	for _, fwd := range r.Forwarders {
		addr := fwd
		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr = net.JoinHostPort(fwd, "53")
		}
		msg := req.Copy()
		msg.RecursionDesired = true
		setEDNS0(msg, r.BufSize, r.WantDO)
		if r.ECSEnabled && sub != nil {
			ecs.Apply(msg, sub, r.BufSize)
		}

		type result struct {
			resp *dns.Msg
			err  error
		}
		ch := make(chan result, 1)
		go func() {
			resp, _, err := r.client.Exchange(msg, addr)
			ch <- result{resp, err}
		}()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case res := <-ch:
			if res.err != nil {
				lastErr = res.err
				continue
			}
			if res.resp == nil {
				lastErr = fmt.Errorf("nil response from %s", addr)
				continue
			}
			return res.resp, nil
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("all forwarders failed")
	}
	return nil, lastErr
}

func setEDNS0(msg *dns.Msg, size uint16, do bool) {
	msg.SetEdns0(size, do)
}

func MinTTL(msg *dns.Msg) uint32 {
	var min uint32
	first := true
	scan := func(rrs []dns.RR) {
		for _, rr := range rrs {
			ttl := rr.Header().Ttl
			if first || ttl < min {
				min = ttl
				first = false
			}
		}
	}
	scan(msg.Answer)
	scan(msg.Ns)
	if first {
		return 60
	}
	return min
}

func PackResponse(msg *dns.Msg) ([]byte, error) {
	msg.Compress = true
	return msg.Pack()
}

func RewriteID(wire []byte, id uint16) []byte {
	out := make([]byte, len(wire))
	copy(out, wire)
	if len(out) >= 2 {
		out[0] = byte(id >> 8)
		out[1] = byte(id)
	}
	return out
}
