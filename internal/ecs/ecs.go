package ecs

import (
	"net"

	"github.com/miekg/dns"
)

// Subnet is an EDNS Client Subnet scope.
type Subnet struct {
	Family  uint16 // 1=IPv4, 2=IPv6
	Source  uint8  // prefix length
	Scope   uint8
	Address net.IP
}

func (s *Subnet) String() string {
	if s == nil || s.Address == nil {
		return ""
	}
	ones := int(s.Source)
	ip := s.Address
	if s.Family == 1 && len(ip) > 4 {
		ip = ip.To4()
	}
	mask := net.CIDRMask(ones, 8*len(ip))
	return (&net.IPNet{IP: ip.Mask(mask), Mask: mask}).String()
}

// Extract returns ECS from request EDNS0 options, if any.
func Extract(msg *dns.Msg) *Subnet {
	opt := msg.IsEdns0()
	if opt == nil {
		return nil
	}
	for _, o := range opt.Option {
		if e, ok := o.(*dns.EDNS0_SUBNET); ok {
			return &Subnet{
				Family:  e.Family,
				Source:  e.SourceNetmask,
				Scope:   e.SourceScope,
				Address: e.Address,
			}
		}
	}
	return nil
}

// FromIP builds an ECS subnet from a client IP with given prefix lengths.
func FromIP(ip net.IP, v4Prefix, v6Prefix uint8) *Subnet {
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		if v4Prefix == 0 {
			v4Prefix = 24
		}
		return &Subnet{Family: 1, Source: v4Prefix, Address: v4}
	}
	if v6Prefix == 0 {
		v6Prefix = 56
	}
	return &Subnet{Family: 2, Source: v6Prefix, Address: ip}
}

// Apply sets or replaces ECS on msg (creates EDNS0 if needed).
func Apply(msg *dns.Msg, sub *Subnet, udpSize uint16) {
	if msg == nil || sub == nil || sub.Address == nil {
		return
	}
	if udpSize == 0 {
		udpSize = 1232
	}
	opt := msg.IsEdns0()
	if opt == nil {
		msg.SetEdns0(udpSize, false)
		opt = msg.IsEdns0()
	}
	// drop existing ECS
	kept := opt.Option[:0]
	for _, o := range opt.Option {
		if _, ok := o.(*dns.EDNS0_SUBNET); !ok {
			kept = append(kept, o)
		}
	}
	opt.Option = kept
	e := &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        sub.Family,
		SourceNetmask: sub.Source,
		SourceScope:   sub.Scope,
		Address:       sub.Address,
	}
	opt.Option = append(opt.Option, e)
}
