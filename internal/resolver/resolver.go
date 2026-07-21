package resolver

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/dnssec"
	"github.com/powersvx/powersvx/internal/ecs"
)

// Resolver resolves DNS queries via forward or recursive mode.
type Resolver struct {
	Mode          string
	Forwarders    []string
	ForwardOnFail bool
	RootHintsFile string
	Timeout       time.Duration
	BufSize       uint16
	WantDO        bool
	ECSEnabled    bool
	ECSPrefixV4   uint8
	ECSPrefixV6   uint8
	client        *dns.Client
	extraRoots    []string
	// OnForwarder is called after each forwarder attempt (addr, ok, latencyMS, errMsg).
	OnForwarder func(addr string, ok bool, latencyMS int64, errMsg string)
}

func (r *Resolver) SetECSEnabled(on bool) {
	if r == nil {
		return
	}
	r.ECSEnabled = on
}

func (r *Resolver) SetMode(mode string) {
	if r == nil {
		return
	}
	r.Mode = config.NormalizeResolverMode(mode)
}

func (r *Resolver) SetForwardOnFail(on bool) {
	if r == nil {
		return
	}
	r.ForwardOnFail = on
}

func (r *Resolver) SetForwarders(addrs []string) {
	if r == nil {
		return
	}
	r.Forwarders = append([]string(nil), addrs...)
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
	mode := config.NormalizeResolverMode(cfg.Mode)
	secMode := dnssec.ParseMode(cfg.DNSSECMode, cfg.DNSSECValidation)
	v4, v6 := cfg.ECSPrefixV4, cfg.ECSPrefixV6
	if v4 == 0 {
		v4 = 24
	}
	if v6 == 0 {
		v6 = 56
	}
	r := &Resolver{
		Mode:          mode,
		Forwarders:    cfg.Forwarders,
		ForwardOnFail: cfg.ForwardOnFail,
		RootHintsFile: cfg.RootHintsFile,
		Timeout:       timeout,
		BufSize:       buf,
		WantDO:        secMode != dnssec.ModeOff,
		ECSEnabled:    cfg.ECSEnabled,
		ECSPrefixV4:   v4,
		ECSPrefixV6:   v6,
		client: &dns.Client{
			Net:     "udp",
			Timeout: timeout,
			UDPSize: buf,
		},
	}
	if cfg.RootHintsFile != "" {
		if addrs, err := loadRootHintsFile(cfg.RootHintsFile); err == nil {
			r.extraRoots = addrs
		}
	}
	return r
}

func (r *Resolver) Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	msg, _, err := r.ResolveWithECS(ctx, req, nil)
	return msg, err
}

// ResolveWithECS forwards/resolves, optionally attaching ECS subnet.
// Path is "recursive", "forward", or "fallback" (recursive failed then forwarder succeeded/failed).
func (r *Resolver) ResolveWithECS(ctx context.Context, req *dns.Msg, sub *ecs.Subnet) (*dns.Msg, string, error) {
	if len(req.Question) == 0 {
		return nil, "", fmt.Errorf("empty question")
	}
	q := req.Question[0]
	q.Name = config.NormalizeName(q.Name)

	switch r.Mode {
	case "recursive":
		// Leave headroom so forward_on_fail can still answer before clients time out.
		recBudget := r.Timeout * 2 / 3
		if recBudget < time.Second {
			recBudget = r.Timeout
		}
		rctx, cancel := context.WithTimeout(ctx, recBudget)
		msg, err := r.resolveRecursive(rctx, q.Name, q.Qtype)
		cancel()
		if err != nil && r.ForwardOnFail && len(r.Forwarders) > 0 {
			// Recursive often exhausts its budget; give forwarders a fresh timeout.
			fctx, fcancel := context.WithTimeout(context.WithoutCancel(ctx), r.Timeout)
			defer fcancel()
			msg, err = r.forward(fctx, req, sub)
			return msg, "fallback", err
		}
		return msg, "recursive", err
	default:
		msg, err := r.forward(ctx, req, sub)
		return msg, "forward", err
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
		started := time.Now()
		go func() {
			resp, _, err := r.client.Exchange(msg, addr)
			ch <- result{resp, err}
		}()
		select {
		case <-ctx.Done():
			if r.OnForwarder != nil {
				r.OnForwarder(addr, false, time.Since(started).Milliseconds(), ctx.Err().Error())
			}
			return nil, ctx.Err()
		case res := <-ch:
			ms := time.Since(started).Milliseconds()
			if res.err != nil {
				lastErr = res.err
				if r.OnForwarder != nil {
					r.OnForwarder(addr, false, ms, res.err.Error())
				}
				continue
			}
			if res.resp == nil {
				lastErr = fmt.Errorf("nil response from %s", addr)
				if r.OnForwarder != nil {
					r.OnForwarder(addr, false, ms, lastErr.Error())
				}
				continue
			}
			if r.OnForwarder != nil {
				r.OnForwarder(addr, true, ms, "")
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
