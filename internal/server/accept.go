package server

import "github.com/miekg/dns"

// msgAcceptFunc is more permissive than miekg's DefaultMsgAcceptFunc.
// dig (BIND 9.18+) often sends EDNS OPT + COOKIE (+ optional padding/NSID) which can
// exceed Arcount>2 and get FORMERR with an empty question section (12-byte reply).
func msgAcceptFunc(dh dns.Header) dns.MsgAcceptAction {
	if dh.Bits&0x8000 != 0 { // QR — ignore responses
		return dns.MsgIgnore
	}
	// Accept essentially any query/notify; let ServeDNS validate.
	opcode := int(dh.Bits>>11) & 0xF
	if opcode != dns.OpcodeQuery && opcode != dns.OpcodeNotify && opcode != dns.OpcodeUpdate {
		return dns.MsgRejectNotImplemented
	}
	if dh.Qdcount == 0 {
		return dns.MsgReject
	}
	return dns.MsgAccept
}
