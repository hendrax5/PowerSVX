// Package dnstap receives the sampled query log that dnsdist sends over a unix
// socket: Frame Streams carrying dnstap messages (protobuf). Only the few fields
// the Control Plane needs are decoded, so no protobuf library is linked in.
package dnstap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// ContentType is the Frame Streams content type of a dnstap stream.
const ContentType = "protobuf:dnstap.Dnstap"

// MaxFrame bounds one frame. dnstap messages carrying a DNS message are far
// smaller; the cap stops a bad peer from making the listener allocate without limit.
const MaxFrame = 1 << 20

// Frame Streams control frame types.
const (
	ctlAccept = 0x01
	ctlStart  = 0x02
	ctlStop   = 0x03
	ctlReady  = 0x04
	ctlFinish = 0x05

	fieldContentType = 0x01
)

type controlFrame struct {
	kind         uint32
	contentTypes []string
}

// readFrame returns the next frame: a data frame (payload, nil control) or a control frame.
func readFrame(r io.Reader) (payload []byte, ctl *controlFrame, err error) {
	var n [4]byte
	if _, err = io.ReadFull(r, n[:]); err != nil {
		return nil, nil, err
	}
	size := binary.BigEndian.Uint32(n[:])
	if size != 0 {
		if size > MaxFrame {
			return nil, nil, fmt.Errorf("data frame of %d bytes exceeds the %d byte limit", size, MaxFrame)
		}
		payload = make([]byte, size)
		_, err = io.ReadFull(r, payload)
		return payload, nil, err
	}
	// Escape sequence: a zero length announces a control frame.
	if _, err = io.ReadFull(r, n[:]); err != nil {
		return nil, nil, err
	}
	clen := binary.BigEndian.Uint32(n[:])
	if clen < 4 || clen > 512 {
		return nil, nil, fmt.Errorf("control frame length %d out of range", clen)
	}
	body := make([]byte, clen)
	if _, err = io.ReadFull(r, body); err != nil {
		return nil, nil, err
	}
	ctl = &controlFrame{kind: binary.BigEndian.Uint32(body[:4])}
	rest := body[4:]
	for len(rest) > 0 {
		if len(rest) < 8 {
			return nil, nil, errors.New("truncated control field")
		}
		ft := binary.BigEndian.Uint32(rest[:4])
		fl := binary.BigEndian.Uint32(rest[4:8])
		rest = rest[8:]
		if uint32(len(rest)) < fl {
			return nil, nil, errors.New("truncated control field value")
		}
		if ft == fieldContentType {
			ctl.contentTypes = append(ctl.contentTypes, string(rest[:fl]))
		}
		rest = rest[fl:]
	}
	return nil, ctl, nil
}

func writeControl(w io.Writer, kind uint32, contentType string) error {
	body := make([]byte, 4, 16+len(contentType))
	binary.BigEndian.PutUint32(body, kind)
	if contentType != "" {
		var f [8]byte
		binary.BigEndian.PutUint32(f[:4], fieldContentType)
		binary.BigEndian.PutUint32(f[4:], uint32(len(contentType)))
		body = append(body, f[:]...)
		body = append(body, contentType...)
	}
	out := make([]byte, 8, 8+len(body))
	binary.BigEndian.PutUint32(out[4:], uint32(len(body)))
	out = append(out, body...)
	_, err := w.Write(out)
	return err
}

func hasContentType(types []string) bool {
	if len(types) == 0 {
		return true // the writer did not constrain the type
	}
	for _, t := range types {
		if t == ContentType {
			return true
		}
	}
	return false
}

// ReadStream runs the receiving side of one Frame Streams connection and calls
// onFrame for every data frame. It handles both the bidirectional handshake
// (READY, ACCEPT, START ... STOP, FINISH) and the unidirectional form (START ...
// STOP). It returns nil when the peer ends the stream cleanly or closes the
// connection between frames.
func ReadStream(rw io.ReadWriter, onFrame func([]byte)) error {
	started := false
	bidirectional := false
	for {
		payload, ctl, err := readFrame(rw)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if ctl == nil {
			if !started {
				return errors.New("data frame before START")
			}
			onFrame(payload)
			continue
		}
		switch ctl.kind {
		case ctlReady:
			if started {
				return errors.New("READY after START")
			}
			if !hasContentType(ctl.contentTypes) {
				return fmt.Errorf("unsupported content type %q", ctl.contentTypes)
			}
			bidirectional = true
			if err := writeControl(rw, ctlAccept, ContentType); err != nil {
				return err
			}
		case ctlStart:
			if !hasContentType(ctl.contentTypes) {
				return fmt.Errorf("unsupported content type %q", ctl.contentTypes)
			}
			started = true
		case ctlStop:
			if bidirectional {
				return writeControl(rw, ctlFinish, "")
			}
			return nil
		default:
			return fmt.Errorf("unexpected control frame %d", ctl.kind)
		}
	}
}
