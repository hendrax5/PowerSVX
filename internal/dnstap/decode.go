package dnstap

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Filter actions the Dataplane records in the dnstap "extra" field, as
// "action=<name>". They name what dnsdist actually did with the query.
const (
	ActionAllowed       = "allowed"        // whitelist: bypassed every Filter rule
	ActionBlockedFilter = "blocked-filter" // Filter Feed (Kominfo) name
	ActionBlockedCustom = "blocked-custom" // operator's custom blacklist
	ActionAuth          = "auth"           // answered by the Auth Backend
	ActionRecursed      = "recursed"       // sent to Unbound
	ActionRefused       = "refused"        // refused (rate cap or backend)
)

// Entry is one sampled client query with the answer dnsdist returned.
type Entry struct {
	Time     time.Time
	ClientIP string
	QName    string
	QType    string
	RCode    string
	RCodeNum int
	Protocol string
	Latency  time.Duration // zero when the message carries no query time
	Action   string        // one of the Action constants, or "" when unknown
}

// Blocked reports whether the Filter blocked the query.
func (e Entry) Blocked() bool {
	return e.Action == ActionBlockedFilter || e.Action == ActionBlockedCustom
}

// dnstap.proto field numbers (https://github.com/dnstap/dnstap.pb).
const (
	tapExtra   = 3
	tapMessage = 14

	msgType        = 1
	msgSocketProto = 3
	msgQueryAddr   = 4
	msgQuerySec    = 8
	msgQueryNsec   = 9
	msgRespSec     = 12
	msgRespNsec    = 13
	msgRespMessage = 14

	typeClientResponse = 6 // Message.Type CLIENT_RESPONSE

	wireVarint  = 0
	wireFixed64 = 1
	wireBytes   = 2
	wireFixed32 = 5

	maxExtraLen = 64
)

var protocols = map[uint64]string{1: "udp", 2: "tcp", 3: "dot", 4: "doh", 5: "dnscrypt", 6: "dnscrypt", 7: "doq"}

var errTruncated = errors.New("truncated protobuf field")

// field is one decoded protobuf field.
type field struct {
	num   uint64
	wire  uint64
	value uint64 // varint or fixed value
	data  []byte // length-delimited value
}

func nextField(b []byte) (f field, rest []byte, err error) {
	key, n := binary.Uvarint(b)
	if n <= 0 {
		return f, nil, errTruncated
	}
	b = b[n:]
	f.num, f.wire = key>>3, key&7
	switch f.wire {
	case wireVarint:
		v, n := binary.Uvarint(b)
		if n <= 0 {
			return f, nil, errTruncated
		}
		f.value = v
		return f, b[n:], nil
	case wireFixed64:
		if len(b) < 8 {
			return f, nil, errTruncated
		}
		f.value = binary.LittleEndian.Uint64(b)
		return f, b[8:], nil
	case wireFixed32:
		if len(b) < 4 {
			return f, nil, errTruncated
		}
		f.value = uint64(binary.LittleEndian.Uint32(b))
		return f, b[4:], nil
	case wireBytes:
		l, n := binary.Uvarint(b)
		if n <= 0 || l > uint64(len(b)-n) {
			return f, nil, errTruncated
		}
		f.data = b[n : n+int(l)]
		return f, b[n+int(l):], nil
	}
	return f, nil, errors.New("unsupported protobuf wire type")
}

// Decode turns one dnstap frame into an Entry. ok is false for messages that are
// not client responses (the sampled log only produces those). An error means the
// frame is malformed.
func Decode(frame []byte) (e Entry, ok bool, err error) {
	var msg, extra []byte
	for rest := frame; len(rest) > 0; {
		var f field
		if f, rest, err = nextField(rest); err != nil {
			return e, false, err
		}
		switch {
		case f.num == tapMessage && f.wire == wireBytes:
			msg = f.data
		case f.num == tapExtra && f.wire == wireBytes:
			extra = f.data
		}
	}
	if msg == nil {
		return e, false, nil
	}

	var (
		kind, proto            uint64
		qsec, qnsec, rsec, rns uint64
		addr, resp             []byte
	)
	for rest := msg; len(rest) > 0; {
		var f field
		if f, rest, err = nextField(rest); err != nil {
			return e, false, err
		}
		switch f.num {
		case msgType:
			kind = f.value
		case msgSocketProto:
			proto = f.value
		case msgQueryAddr:
			addr = f.data
		case msgQuerySec:
			qsec = f.value
		case msgQueryNsec:
			qnsec = f.value
		case msgRespSec:
			rsec = f.value
		case msgRespNsec:
			rns = f.value
		case msgRespMessage:
			resp = f.data
		}
	}
	if kind != typeClientResponse || len(resp) == 0 {
		return e, false, nil
	}

	var m dns.Msg
	if err := m.Unpack(resp); err != nil || len(m.Question) == 0 {
		return e, false, errors.New("dnstap response carries no readable question")
	}
	q := m.Question[0]
	e.QName = strings.ToLower(strings.TrimSuffix(q.Name, "."))
	e.QType = dns.TypeToString[q.Qtype]
	if e.QType == "" {
		e.QType = "TYPE" + strconv.Itoa(int(q.Qtype))
	}
	e.RCodeNum = m.Rcode
	e.RCode = dns.RcodeToString[m.Rcode]
	if e.RCode == "" {
		e.RCode = "RCODE" + strconv.Itoa(m.Rcode)
	}
	e.Protocol = protocols[proto]
	if a, ok := netip.AddrFromSlice(addr); ok {
		e.ClientIP = a.Unmap().String()
	}
	switch {
	case rsec != 0:
		e.Time = time.Unix(int64(rsec), int64(rns)).UTC()
	case qsec != 0:
		e.Time = time.Unix(int64(qsec), int64(qnsec)).UTC()
	default:
		e.Time = time.Now().UTC()
	}
	if qsec != 0 && rsec != 0 {
		if d := e.Time.Sub(time.Unix(int64(qsec), int64(qnsec))); d > 0 {
			e.Latency = d
		}
	}
	e.Action = parseAction(extra)
	return e, true, nil
}

// parseAction reads "action=<name>" from the extra field and accepts only the
// known names, so a stray value never reaches the console or the database.
func parseAction(extra []byte) string {
	if len(extra) == 0 || len(extra) > maxExtraLen {
		return ""
	}
	v, ok := strings.CutPrefix(string(extra), "action=")
	if !ok {
		return ""
	}
	switch v {
	case ActionAllowed, ActionBlockedFilter, ActionBlockedCustom, ActionAuth, ActionRecursed, ActionRefused:
		return v
	}
	return ""
}
