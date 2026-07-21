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
	Mode          string
	Forwarders    []string
	ForwardZones  []config.ForwardZoneConfig
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

func (r *Resolver) SetForwardZones(zones []config.ForwardZoneConfig) {
	if r == nil {
		return
	}
	r.ForwardZones = append([]config.ForwardZoneConfig(nil), zones...)
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
	fz, _ := config.NormalizeForwardZones(cfg.ForwardZones)
	fwd, _ := config.NormalizeForwarders(cfg.Forwarders)
	r := &Resolver{
		Mode:          mode,
		Forwarders:    fwd,
		ForwardZones:  fz,
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
// Path is "recursive", "forward", "conditional", or "fallback".
func (r *Resolver) ResolveWithECS(ctx context.Context, req *dns.Msg, sub *ecs.Subnet) (*dns.Msg, string, error) {
	if len(req.Question) == 0 {
		return nil, "", fmt.Errorf("empty question")
	}
	q := req.Question[0]
	q.Name = config.NormalizeName(q.Name)

	// Conditional / stub forwarders always win (longest-suffix match).
	if addrs := r.matchForwardZone(q.Name); len(addrs) > 0 {
		msg, err := r.forwardTo(ctx, req, sub, addrs)
		return msg, "conditional", err
	}

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

func (r *Resolver) matchForwardZone(qname string) []string {
	if r == nil || len(r.ForwardZones) == 0 {
		return nil
	}
	qname = config.NormalizeName(qname)
	best := ""
	var addrs []string
	for _, z := range r.ForwardZones {
		zone := config.NormalizeName(z.Zone)
		if qname == zone || strings.HasSuffix(qname, "."+zone) {
			if len(zone) > len(best) {
				best = zone
				addrs = z.Forwarders
			}
		}
	}
	return addrs
}

func (r *Resolver) forward(ctx context.Context, req *dns.Msg, sub *ecs.Subnet) (*dns.Msg, error) {
	return r.forwardTo(ctx, req, sub, r.Forwarders)
}

func (r *Resolver) forwardTo(ctx context.Context, req *dns.Msg, sub *ecs.Subnet, forwarders []string) (*dns.Msg, error) {
	if len(forwarders) == 0 {
		return nil, fmt.Errorf("no forwarders configured")
	}
	var lastErr error
	for _, fwd := range forwarders {
		target, err := config.ParseForwardTarget(fwd)
		if err != nil {
			// Legacy host without port / normalize failure: treat as UDP :53
			addr := fwd
			if _, _, e := net.SplitHostPort(addr); e != nil {
				addr = net.JoinHostPort(fwd, "53")
			}
			target = config.ForwardTarget{Network: "udp", Addr: addr, Display: addr}
		}
		msg := req.Copy()
		msg.RecursionDesired = true
		setEDNS0(msg, r.BufSize, r.WantDO)
		if r.ECSEnabled && sub != nil {
			ecs.Apply(msg, sub, r.BufSize)
		}

		started := time.Now()
		resp, err := r.exchangeUpstream(ctx, msg, target)
		ms := time.Since(started).Milliseconds()
		label := target.Display
		if label == "" {
			label = target.Addr
		}
		if err != nil {
			lastErr = err
			if r.OnForwarder != nil {
				r.OnForwarder(label, false, ms, err.Error())
			}
			continue
		}
		if resp == nil {
			lastErr = fmt.Errorf("nil response from %s", label)
			if r.OnForwarder != nil {
				r.OnForwarder(label, false, ms, lastErr.Error())
			}
			continue
		}
		if r.OnForwarder != nil {
			r.OnForwarder(label, true, ms, "")
		}
		return resp, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("all forwarders failed")
	}
	return nil, lastErr
}

func setEDNS0(msg *dns.Msg, size uint16, do bool) {
	// miekg's SetEdns0 always appends. Dig (BIND 9.18+) already sends OPT+COOKIE,
	// so a second OPT makes upstream answer FORMERR / a malformed packet.
	stripOPT(msg)
	if size == 0 {
		size = 1232
	}
	msg.SetEdns0(size, do)
}

func stripOPT(msg *dns.Msg) {
	if msg == nil || len(msg.Extra) == 0 {
		return
	}
	kept := make([]dns.RR, 0, len(msg.Extra))
	for _, rr := range msg.Extra {
		if rr == nil || rr.Header().Rrtype == dns.TypeOPT {
			continue
		}
		kept = append(kept, rr)
	}
	msg.Extra = kept
}

// PrepareClientResponse strips upstream OPT and attaches client-facing EDNS
// (UDP size, DO bit, echoed COOKIE) so dig does not report cookie mismatch
// or a second mangled OPT record.
func PrepareClientResponse(req, resp *dns.Msg) {
	if resp == nil {
		return
	}
	stripOPT(resp)
	if req == nil {
		return
	}
	opt := req.IsEdns0()
	if opt == nil {
		return
	}
	size := opt.UDPSize()
	if size == 0 {
		size = 1232
	}
	resp.SetEdns0(size, opt.Do())
	ropt := resp.IsEdns0()
	if ropt == nil {
		return
	}
	for _, o := range opt.Option {
		if c, ok := o.(*dns.EDNS0_COOKIE); ok {
			ropt.Option = append(ropt.Option, &dns.EDNS0_COOKIE{
				Code:   dns.EDNS0COOKIE,
				Cookie: c.Cookie,
			})
		}
	}
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
