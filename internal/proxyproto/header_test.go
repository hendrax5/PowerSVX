package proxyproto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

func v2(cmd, famProto byte, body []byte) []byte {
	out := append([]byte(nil), Signature...)
	out = append(out, cmd, famProto)
	out = binary.BigEndian.AppendUint16(out, uint16(len(body)))
	return append(out, body...)
}

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func TestParseAddressFamilies(t *testing.T) {
	for _, tc := range []struct {
		name string
		h    Header
	}{
		{"IPv4 over UDP", Header{Transport: Dgram, Src: ap("203.0.113.9:40000"), Dst: ap("192.0.2.1:53")}},
		{"IPv4 over TCP", Header{Transport: Stream, Src: ap("198.51.100.7:51000"), Dst: ap("192.0.2.1:53")}},
		{"IPv6 over UDP", Header{Transport: Dgram, Src: ap("[2001:db8::9]:40000"), Dst: ap("[2001:db8::1]:53")}},
		{"IPv6 over TCP", Header{Transport: Stream, Src: ap("[2001:db8:1::9]:51000"), Dst: ap("[2001:db8::1]:53")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := Encode(tc.h)
			got, n, err := Parse(wire)
			if err != nil || n != len(wire) {
				t.Fatalf("Parse: n=%d err=%v", n, err)
			}
			if got.Local || got.Src != tc.h.Src || got.Dst != tc.h.Dst || got.Transport != tc.h.Transport {
				t.Fatalf("got %+v, want %+v", got, tc.h)
			}
		})
	}
}

func TestParseLocalCommandHasNoClient(t *testing.T) {
	// dnsdist's own health checks: LOCAL, no address block.
	got, n, err := Parse(v2(0x20, 0x00, nil))
	if err != nil || n != 16 || !got.Local || got.Src.IsValid() {
		t.Fatalf("LOCAL: %+v n=%d err=%v", got, n, err)
	}
	// A LOCAL header may carry bytes (TLVs); they are skipped and counted.
	got, n, err = Parse(v2(0x20, 0x11, make([]byte, 20)))
	if err != nil || n != 36 || !got.Local {
		t.Fatalf("LOCAL with a body: %+v n=%d err=%v", got, n, err)
	}
	// PROXY with an unspecified family names no client either.
	got, _, err = Parse(v2(0x21, 0x00, nil))
	if err != nil || !got.Local {
		t.Fatalf("PROXY/UNSPEC: %+v err=%v", got, err)
	}
}

func TestParseSkipsTLVsAfterTheAddresses(t *testing.T) {
	h := Header{Transport: Dgram, Src: ap("203.0.113.9:40000"), Dst: ap("192.0.2.1:53")}
	wire := Encode(h)
	tlv := []byte{0xE0, 0x00, 0x02, 0xAA, 0xBB}
	wire = append(wire, tlv...)
	binary.BigEndian.PutUint16(wire[14:], uint16(lenInet+len(tlv)))
	got, n, err := Parse(wire)
	if err != nil || n != len(wire) || got.Src != h.Src {
		t.Fatalf("with TLV: %+v n=%d err=%v", got, n, err)
	}
}

func TestParseRejectsWhatIsNotAHeader(t *testing.T) {
	good := Encode(Header{Transport: Dgram, Src: ap("203.0.113.9:40000"), Dst: ap("192.0.2.1:53")})
	badSig := append([]byte(nil), good...)
	badSig[3] ^= 0xff
	v1 := []byte("PROXY TCP4 203.0.113.9 192.0.2.1 40000 53\r\n")
	badVer := append([]byte(nil), good...)
	badVer[12] = 0x11
	badCmd := append([]byte(nil), good...)
	badCmd[12] = 0x22
	badTransport := append([]byte(nil), good...)
	badTransport[13] = 0x13
	unix := v2(0x21, 0x31, make([]byte, 216))
	short4 := v2(0x21, 0x12, make([]byte, 8))
	short6 := v2(0x21, 0x22, make([]byte, 20))
	huge := v2(0x21, 0x12, make([]byte, MaxHeaderLen))
	for _, tc := range []struct {
		name string
		in   []byte
		want error
	}{
		{"empty", nil, ErrShort}, // an empty prefix agrees with the signature: not complete yet
		{"wrong signature", badSig, ErrNoHeader},
		{"PROXY protocol version 1 text", v1, ErrNoHeader},
		{"plain DNS", []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 3, 'w', 'w', 'w'}, ErrNoHeader},
		{"truncated inside the signature", good[:7], ErrShort},
		{"truncated inside the fixed part", good[:15], ErrShort},
		{"truncated inside the address block", good[:len(good)-1], ErrShort},
		{"version 1 nibble", badVer, ErrMalformed},
		{"unknown command", badCmd, ErrMalformed},
		{"unknown transport", badTransport, ErrMalformed},
		{"AF_UNIX family", unix, ErrMalformed},
		{"IPv4 block too short", short4, ErrMalformed},
		{"IPv6 block too short", short6, ErrMalformed},
		{"oversize length field", huge, ErrTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := Parse(tc.in)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestReadHeaderStopsAtTheEndOfTheHeader(t *testing.T) {
	h := Header{Transport: Stream, Src: ap("203.0.113.9:40000"), Dst: ap("192.0.2.1:53")}
	r := bytes.NewReader(append(Encode(h), []byte("dns bytes follow")...))
	got, err := ReadHeader(r)
	if err != nil || got.Src != h.Src {
		t.Fatalf("ReadHeader: %+v %v", got, err)
	}
	rest := make([]byte, 64)
	n, _ := r.Read(rest)
	if string(rest[:n]) != "dns bytes follow" {
		t.Fatalf("ReadHeader consumed past the header: rest=%q", rest[:n])
	}
}

func TestReadHeaderRejectsTruncatedAndOversize(t *testing.T) {
	wire := Encode(Header{Transport: Stream, Src: ap("203.0.113.9:40000"), Dst: ap("192.0.2.1:53")})
	if _, err := ReadHeader(bytes.NewReader(wire[:20])); !errors.Is(err, ErrShort) {
		t.Fatalf("truncated stream: %v", err)
	}
	if _, err := ReadHeader(bytes.NewReader(v2(0x21, 0x11, make([]byte, MaxHeaderLen)))); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversize: %v", err)
	}
	if _, err := ReadHeader(bytes.NewReader([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))); !errors.Is(err, ErrNoHeader) {
		t.Fatalf("not a header: %v", err)
	}
}
