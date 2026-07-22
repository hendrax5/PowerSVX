package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/dnssec"
	"github.com/powersvx/powersvx/internal/ecs"
)

// ErrAdmitRejected is returned when max_inflight is full (fail-fast, no queue wait).
var ErrAdmitRejected = errors.New("resolve admission rejected")

// Resolver resolves DNS queries via forward or recursive mode.
type Resolver struct {
	Mode            string
	Forwarders      []string
	ForwardZones    []config.ForwardZoneConfig
	ForwardOnFail   bool
	RootHintsFile   string
	Timeout         time.Duration
	FallbackTimeout time.Duration
	BufSize         uint16
	WantDO          bool
	ECSEnabled      bool
	ECSPrefixV4     uint8
	ECSPrefixV6     uint8
	client          *dns.Client
	extraRoots      []string
	sem             chan struct{}
	semCap          int
	inflight        atomic.Int64
	nsCache         *nsAddrCache
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
	inflight := cfg.MaxInflight
	if inflight <= 0 {
		inflight = 1024
	}
	fb := time.Duration(cfg.FallbackTimeoutMS) * time.Millisecond
	r := &Resolver{
		Mode:            mode,
		Forwarders:      fwd,
		ForwardZones:    fz,
		ForwardOnFail:   cfg.ForwardOnFail,
		RootHintsFile:   cfg.RootHintsFile,
		Timeout:         timeout,
		FallbackTimeout: fb,
		BufSize:         buf,
		WantDO:          secMode != dnssec.ModeOff,
		ECSEnabled:      cfg.ECSEnabled,
		ECSPrefixV4:     v4,
		ECSPrefixV6:     v6,
		client: &dns.Client{
			Net:     "udp",
			Timeout: timeout,
			UDPSize: buf,
		},
		sem:     make(chan struct{}, inflight),
		semCap:  inflight,
		nsCache: newNSAddrCache(4096),
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

	release, err := r.acquire(ctx)
	if err != nil {
		return nil, "", err
	}
	defer release()

	// Conditional / stub forwarders always win (longest-suffix match).
	if addrs := r.matchForwardZone(q.Name); len(addrs) > 0 {
		msg, err := r.forwardTo(ctx, req, sub, addrs)
		return msg, "conditional", err
	}

	switch r.Mode {
	case "recursive":
		fbBudget := r.fallbackBudget()
		recBudget := r.Timeout
		if r.ForwardOnFail && len(r.Forwarders) > 0 && fbBudget > 0 && r.Timeout > fbBudget {
			recBudget = r.Timeout - fbBudget
		}
		// Load shed: when >75% of admit slots busy, shorten recursive or skip to fallback.
		if r.loadShed() {
			if r.ForwardOnFail && len(r.Forwarders) > 0 {
				recBudget = fbBudget
				if recBudget > 200*time.Millisecond {
					recBudget = 200 * time.Millisecond
				}
			} else {
				recBudget = recBudget / 2
				if recBudget < 200*time.Millisecond {
					recBudget = 200 * time.Millisecond
				}
			}
		}
		rctx, cancel := context.WithTimeout(ctx, recBudget)
		msg, err := r.resolveRecursive(rctx, q.Name, q.Qtype)
		cancel()
		if err != nil && r.ForwardOnFail && len(r.Forwarders) > 0 && shouldFallback(err) {
			fctx, fcancel := context.WithTimeout(context.WithoutCancel(ctx), fbBudget)
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

func (r *Resolver) loadShed() bool {
	if r == nil || r.semCap <= 0 {
		return false
	}
	return int(r.inflight.Load())*4 >= r.semCap*3 // >= 75%
}

func (r *Resolver) Inflight() int {
	if r == nil {
		return 0
	}
	return int(r.inflight.Load())
}

func (r *Resolver) InflightCap() int {
	if r == nil {
		return 0
	}
	return r.semCap
}

func (r *Resolver) fallbackBudget() time.Duration {
	if r == nil {
		return 400 * time.Millisecond
	}
	if r.FallbackTimeout > 0 {
		return r.FallbackTimeout
	}
	d := r.Timeout / 5
	if d < 200*time.Millisecond {
		d = 200 * time.Millisecond
	}
	if d > 500*time.Millisecond {
		d = 500 * time.Millisecond
	}
	return d
}

// shouldFallback is true for transport/timeout/iteration failures — not for
// successful NXDOMAIN (those return err=nil from resolveRecursive).
func shouldFallback(err error) bool {
	if err == nil {
		return false
	}
	return true
}

func (r *Resolver) acquire(ctx context.Context) (func(), error) {
	if r == nil || r.sem == nil {
		return func() {}, nil
	}
	// Fail-fast: never wait on the semaphore (Unbound-like jostle / no queue pile-up).
	select {
	case r.sem <- struct{}{}:
		r.inflight.Add(1)
		return func() {
			<-r.sem
			r.inflight.Add(-1)
		}, nil
	default:
		_ = ctx // reserved for future soft-wait; deliberately unused
		return func() {}, ErrAdmitRejected
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
	// Single forwarder: keep simple path.
	if len(forwarders) == 1 {
		fwd := forwarders[0]
		started := time.Now()
		resp, err := r.forwardOne(ctx, req, sub, fwd)
		ms := time.Since(started).Milliseconds()
		label := fwd
		if t, e := config.ParseForwardTarget(fwd); e == nil && t.Display != "" {
			label = t.Display
		}
		if err != nil {
			if r.OnForwarder != nil {
				r.OnForwarder(label, false, ms, err.Error())
			}
			return nil, err
		}
		if resp == nil {
			err = fmt.Errorf("nil response from %s", label)
			if r.OnForwarder != nil {
				r.OnForwarder(label, false, ms, err.Error())
			}
			return nil, err
		}
		if r.OnForwarder != nil {
			r.OnForwarder(label, true, ms, "")
		}
		return resp, nil
	}

	// Race all forwarders; first usable answer wins so a slow/dead #2
	// does not wait behind a timed-out #1 (fixes 8.8.8.8 "100% fail" UI).
	type result struct {
		resp  *dns.Msg
		err   error
		label string
		ms    int64
	}
	ch := make(chan result, len(forwarders))
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	for _, fwd := range forwarders {
		fwd := fwd
		go func() {
			started := time.Now()
			resp, err := r.forwardOne(raceCtx, req, sub, fwd)
			label := fwd
			if t, e := config.ParseForwardTarget(fwd); e == nil && t.Display != "" {
				label = t.Display
			}
			ch <- result{resp: resp, err: err, label: label, ms: time.Since(started).Milliseconds()}
		}()
	}

	var lastErr error
	for range forwarders {
		select {
		case <-ctx.Done():
			if lastErr == nil {
				lastErr = ctx.Err()
			}
			return nil, lastErr
		case res := <-ch:
			if res.err != nil || res.resp == nil {
				if res.err != nil {
					lastErr = res.err
				} else {
					lastErr = fmt.Errorf("nil response from %s", res.label)
				}
				if r.OnForwarder != nil {
					r.OnForwarder(res.label, false, res.ms, lastErr.Error())
				}
				continue
			}
			cancel()
			if r.OnForwarder != nil {
				r.OnForwarder(res.label, true, res.ms, "")
			}
			return res.resp, nil
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("all forwarders failed")
	}
	return nil, lastErr
}

func (r *Resolver) forwardOne(ctx context.Context, req *dns.Msg, sub *ecs.Subnet, fwd string) (*dns.Msg, error) {
	target, err := config.ParseForwardTarget(fwd)
	if err != nil {
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
	return r.exchangeUpstream(ctx, msg, target)
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
