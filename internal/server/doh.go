package server

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const dohPath = "/dns-query"
const mimeDNSMessage = "application/dns-message"

func (s *Server) startDoH(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc(dohPath, s.handleDoH)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			writeDoHUsage(w, http.StatusOK)
			return
		}
		http.NotFound(w, r)
	})

	tlsCfg := s.tlsCfg.Clone()
	// HTTP/2 over TLS (DoH) + keep existing certs
	if len(tlsCfg.NextProtos) == 0 {
		tlsCfg.NextProtos = []string{"h2", "http/1.1"}
	}

	h3 := &http3.Server{
		Addr:      addr,
		Handler:   mux,
		TLSConfig: http3.ConfigureTLSConfig(s.tlsCfg.Clone()),
		QUICConfig: &quic.Config{
			Allow0RTT: false,
		},
	}
	s.dohHTTP3 = h3

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = h3.SetQUICHeaders(w.Header())
		mux.ServeHTTP(w, r)
	})

	s.dohHTTP = &http.Server{
		Addr:      addr,
		Handler:   handler,
		TLSConfig: tlsCfg,
	}
	return nil
}

func (s *Server) handleDoH(w http.ResponseWriter, r *http.Request) {
	var wire []byte
	var err error

	switch r.Method {
	case http.MethodGet, http.MethodHead:
		wire, err = decodeDoHGET(r)
		if err != nil {
			if err == errDoHUsage {
				writeDoHUsage(w, http.StatusBadRequest)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("Content-Type", mimeDNSMessage)
			w.WriteHeader(http.StatusOK)
			return
		}
	case http.MethodPost:
		ct := r.Header.Get("Content-Type")
		if ct != "" && !strings.HasPrefix(strings.ToLower(ct), mimeDNSMessage) {
			http.Error(w, "unsupported media type (want application/dns-message)", http.StatusUnsupportedMediaType)
			return
		}
		wire, err = io.ReadAll(io.LimitReader(r.Body, 65535))
		if err != nil || len(wire) == 0 {
			http.Error(w, "empty body", http.StatusBadRequest)
			return
		}
	default:
		w.Header().Set("Allow", "GET, HEAD, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	req := new(dns.Msg)
	if err := req.Unpack(wire); err != nil {
		http.Error(w, "invalid DNS message", http.StatusBadRequest)
		return
	}
	if len(req.Question) == 0 {
		http.Error(w, "DNS message missing question", http.StatusBadRequest)
		return
	}

	clientIP := ""
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		clientIP = host
	} else {
		clientIP = r.RemoteAddr
	}
	_, respWire, err := s.ServeDNSMsgFrom(req, clientIP)
	if err != nil || len(respWire) == 0 {
		http.Error(w, "resolution failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", mimeDNSMessage)
	w.Header().Set("Cache-Control", "max-age=0")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respWire)
}

var errDoHUsage = errString("doh usage")

type errString string

func (e errString) Error() string { return string(e) }

func decodeDoHGET(r *http.Request) ([]byte, error) {
	q := r.URL.Query()

	// RFC 8484: ?dns=<base64url>
	if dnsParam := q.Get("dns"); dnsParam != "" {
		wire, err := base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil {
			wire, err = base64.URLEncoding.DecodeString(dnsParam)
		}
		if err != nil {
			return nil, errString("invalid dns parameter (need base64url)")
		}
		return wire, nil
	}

	// Convenience for browsers / manual tests: ?name=example.com&type=A
	name := q.Get("name")
	if name == "" {
		name = q.Get("q")
	}
	if name == "" {
		return nil, errDoHUsage
	}
	qtype := dns.TypeA
	if t := q.Get("type"); t != "" {
		if v, ok := dns.StringToType[strings.ToUpper(t)]; ok {
			qtype = v
		} else {
			return nil, errString("invalid type parameter")
		}
	}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.RecursionDesired = true
	return msg.Pack()
}

func writeDoHUsage(w http.ResponseWriter, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"service": "PowerSVX DoH / DoH3",
		"path":    dohPath,
		"usage": []string{
			"POST /dns-query  Content-Type: application/dns-message  (RFC 8484)",
			"GET  /dns-query?dns=<base64url>  (RFC 8484)",
			"GET  /dns-query?name=example.com&type=A  (convenience)",
			"HTTP/3 (DoH3): same path over QUIC (ALPN h3); Alt-Svc advertised on DoH responses",
		},
		"example": "https://127.0.0.1:8443/dns-query?name=example.com&type=A",
		"cli":     "go run ./cmd/dohquery https://127.0.0.1:8443/dns-query example.com A",
	})
}
