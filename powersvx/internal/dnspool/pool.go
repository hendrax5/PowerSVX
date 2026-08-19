// Package dnspool provides sync.Pool reuse for DNS message structs and packing
// buffers to cut per-query allocations and GC pressure on the hot path.
//
// Safety contract:
//   - GetMsg returns a zeroed *dns.Msg; Unpack fully repopulates it.
//   - PutMsg must only be called on messages the caller exclusively owns. In the
//     server this is the freshly-unpacked request and the freshly-built response
//     (cache/RPZ/upstream replies are always independent copies), so returning
//     them is safe. The backing arrays are never mutated after handoff, so any
//     shared question slice remains valid.
package dnspool

import (
	"sync"

	"github.com/miekg/dns"
)

var msgPool = sync.Pool{New: func() interface{} { return new(dns.Msg) }}

func GetMsg() *dns.Msg { return msgPool.Get().(*dns.Msg) }

func PutMsg(m *dns.Msg) {
	if m == nil {
		return
	}
	*m = dns.Msg{}
	msgPool.Put(m)
}

// Default UDP payload we optimistically size buffers for; grows on demand.
const defaultBufCap = 1232

var bufPool = sync.Pool{New: func() interface{} {
	b := make([]byte, 0, defaultBufCap)
	return &b
}}

func GetBuf() *[]byte { return bufPool.Get().(*[]byte) }

func PutBuf(b *[]byte) {
	*b = (*b)[:0]
	bufPool.Put(b)
}
