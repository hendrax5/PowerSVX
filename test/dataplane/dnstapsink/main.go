// Command dnstapsink is the Control Plane's dnstap listener reduced to what the
// Dataplane test needs. It runs in a container that shares a volume with dnsdist,
// accepts dnsdist's Frame Streams connection with the production decoder, prints
// one JSON line per decoded query and records the raw bytes it received.
//
//	dnstapsink <socket path> [raw stream file]
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/powersvx/powersvx/internal/dnstap"
)

type line struct {
	Time     string `json:"time"`
	ClientIP string `json:"client_ip"`
	QName    string `json:"qname"`
	QType    string `json:"qtype"`
	RCode    string `json:"rcode"`
	Protocol string `json:"protocol"`
	Action   string `json:"action"`
	Frame    string `json:"frame_hex"`
}

// recorder copies everything read from the peer into a file.
type recorder struct {
	net.Conn
	mu  *sync.Mutex
	out *os.File
}

func (r recorder) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	if n > 0 && r.out != nil {
		r.mu.Lock()
		_, _ = r.out.Write(p[:n])
		r.mu.Unlock()
	}
	return n, err
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: dnstapsink <socket> [raw stream file]")
		os.Exit(2)
	}
	_ = os.Remove(os.Args[1])
	ln, err := net.Listen("unix", os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
	var raw *os.File
	if len(os.Args) > 2 {
		if raw, err = os.Create(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, "raw file:", err)
			os.Exit(1)
		}
	}
	var mu sync.Mutex
	fmt.Println(`{"ready":true}`)
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			err := dnstap.ReadStream(recorder{Conn: c, mu: &mu, out: raw}, func(frame []byte) {
				e, ok, derr := dnstap.Decode(frame)
				if derr != nil || !ok {
					return
				}
				b, _ := json.Marshal(line{
					Time: e.Time.Format("2006-01-02T15:04:05.000000000Z"), ClientIP: e.ClientIP, QName: e.QName,
					QType: e.QType, RCode: e.RCode, Protocol: e.Protocol, Action: e.Action,
					Frame: fmt.Sprintf("%x", frame),
				})
				mu.Lock()
				fmt.Println(string(b))
				mu.Unlock()
			})
			if err != nil {
				fmt.Fprintln(os.Stderr, "stream:", err)
			}
		}()
	}
}
