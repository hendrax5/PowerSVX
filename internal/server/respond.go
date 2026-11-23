package server

import (
	"net"
	"reflect"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/config"
)

// write sends resp to the client. It attaches the client-facing EDNS record,
// drops invalid records and writes the packed wire form.
func (s *Server) write(w dns.ResponseWriter, req, resp *dns.Msg, ecs *dns.EDNS0_SUBNET) {
	prepareClientResponse(req, resp, s.udpBufSize(), ecs)
	sanitizeRRSlice(&resp.Answer)
	sanitizeRRSlice(&resp.Ns)
	sanitizeRRSlice(&resp.Extra)
	resp.Compress = true
	wire, err := resp.Pack()
	if err != nil {
		_ = w.WriteMsg(resp)
		return
	}
	_, _ = w.Write(wire)
}

// prepareClientResponse replaces any OPT record in resp with one built for the
// client: its UDP size (clamped to maxUDP), its DO bit and its echoed COOKIE.
// ecs is the client subnet the answer was steered by, echoed with the scope RFC 7871 asks for
// so a resolver caches the answer for that subnet only; nil when the answer did not use it.
func prepareClientResponse(req, resp *dns.Msg, maxUDP uint16, ecs *dns.EDNS0_SUBNET) {
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
	if maxUDP == 0 {
		maxUDP = config.EDNSBufferMin
	}
	size := opt.UDPSize()
	if size < 512 || size > maxUDP {
		size = maxUDP
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
	if ecs != nil {
		ropt.Option = append(ropt.Option, &dns.EDNS0_SUBNET{
			Code: dns.EDNS0SUBNET, Family: ecs.Family, SourceNetmask: ecs.SourceNetmask,
			SourceScope: ecs.SourceNetmask, Address: ecs.Address,
		})
	}
}

func stripOPT(msg *dns.Msg) {
	if msg == nil || len(msg.Extra) == 0 {
		return
	}
	kept := make([]dns.RR, 0, len(msg.Extra))
	for _, rr := range msg.Extra {
		if !rrOK(rr) || rr.Header().Rrtype == dns.TypeOPT {
			continue
		}
		kept = append(kept, rr)
	}
	msg.Extra = kept
}

func sanitizeRRSlice(rrs *[]dns.RR) {
	if rrs == nil || len(*rrs) == 0 {
		return
	}
	dst := (*rrs)[:0]
	for _, rr := range *rrs {
		if rrOK(rr) {
			dst = append(dst, rr)
		}
	}
	*rrs = dst
}

// rrOK is false for a nil interface or a typed-nil RR pointer (Header() would panic).
func rrOK(rr dns.RR) bool {
	if rr == nil {
		return false
	}
	v := reflect.ValueOf(rr)
	return !(v.Kind() == reflect.Ptr && v.IsNil())
}

// clientSubnet returns the EDNS client subnet option of a query when it names a usable
// subnet: IPv4 or IPv6, a non-zero source prefix, an address of the matching length.
func clientSubnet(req *dns.Msg) *dns.EDNS0_SUBNET {
	if req == nil {
		return nil
	}
	opt := req.IsEdns0()
	if opt == nil {
		return nil
	}
	for _, o := range opt.Option {
		e, ok := o.(*dns.EDNS0_SUBNET)
		if !ok || e.SourceNetmask == 0 {
			continue
		}
		switch {
		case e.Family == 1 && len(e.Address.To4()) == net.IPv4len && e.SourceNetmask <= 32:
			return e
		case e.Family == 2 && len(e.Address) == net.IPv6len && e.SourceNetmask <= 128:
			return e
		}
	}
	return nil
}
