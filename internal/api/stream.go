package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/dnsdistctl"
	"github.com/powersvx/powersvx/internal/queryring"
)

// StartLiveQuerySampler periodically polls dnsdist grepq ring buffer into Server.QueryRing()
// so Live Query Stream shows real-time edge DNS traffic with zero Postgres disk writes.
func (a *API) StartLiveQuerySampler() {
	if a == nil || a.srv == nil || a.srv.QueryRing() == nil || !config.DNSDistDataplane() {
		return
	}
	go func() {
		var mu sync.Mutex
		seen := make(map[string]time.Time)
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for range t.C {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			samples, err := dnsdistctl.DefaultClient().GrepQueries(ctx, 100, "")
			cancel()
			if err != nil || len(samples) == 0 {
				continue
			}
			now := time.Now().UTC()
			mu.Lock()
			for k, ts := range seen {
				if now.Sub(ts) > 2*time.Minute {
					delete(seen, k)
				}
			}
			ring := a.srv.QueryRing()
			for _, s := range samples {
				key := s.Timestamp + "|" + s.Client + "|" + s.ID + "|" + s.QName + "|" + s.QType
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = now
				clientHost := s.Client
				if h, _, err := net.SplitHostPort(clientHost); err == nil {
					clientHost = h
				}
				lat, _ := strconv.ParseFloat(strings.TrimSuffix(s.LatencyMS, "ms"), 64)
				rcode := s.RCode
				if rcode == "" {
					rcode = "NOERROR"
				}
				blocked := strings.Contains(strings.ToUpper(rcode), "NXDOMAIN") && strings.Contains(s.LatencyMS, "0.")
				ring.Push(queryring.QueryEvent{
					Time:      now,
					ClientIP:  clientHost,
					QName:     s.QName,
					QType:     s.QType,
					Protocol:  "dnsdist",
					RCode:     rcode,
					Path:      "dnsdist",
					LatencyMS: lat,
					Blocked:   blocked,
					Source:    "dnsdist",
				})
			}
			mu.Unlock()
		}
	}()
}

func parseQueryFilter(r *http.Request) queryring.QueryFilter {
	q := r.URL.Query()
	limit := 200
	if raw := q.Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	blockedOnly := q.Get("blocked") == "1" || strings.EqualFold(q.Get("blocked"), "true")
	return queryring.QueryFilter{
		QName:       q.Get("q"),
		ClientIP:    q.Get("client"),
		RCode:       q.Get("rcode"),
		BlockedOnly: blockedOnly,
		Limit:       limit,
	}
}

func (a *API) handleLiveQueries(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ring := a.srv.QueryRing()
	if ring == nil {
		writeJSON(w, http.StatusOK, map[string]any{"queries": []any{}, "buffered": 0})
		return
	}
	f := parseQueryFilter(r)
	events := ring.Recent(f)
	if events == nil {
		events = []queryring.QueryEvent{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"queries":  events,
		"buffered": ring.Len(),
		"capacity": queryring.DefaultCap,
	})
}

func (a *API) handleQueryStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	flusher, ok := w.(http.Flusher)
	ring := a.srv.QueryRing()
	if !ok || ring == nil {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	f := parseQueryFilter(r)
	qnFilter := strings.ToLower(strings.TrimSpace(f.QName))
	ipFilter := strings.TrimSpace(f.ClientIP)
	rcFilter := strings.ToUpper(strings.TrimSpace(f.RCode))

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ctx := r.Context()
	ch := ring.Subscribe(ctx, 256)

	for _, ev := range ring.Recent(queryring.QueryFilter{
		QName:       f.QName,
		ClientIP:    f.ClientIP,
		RCode:       f.RCode,
		BlockedOnly: f.BlockedOnly,
		Limit:       50,
	}) {
		if err := writeQuerySSE(w, ev); err != nil {
			return
		}
	}
	flusher.Flush()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = w.Write([]byte(": ping\n\n"))
			flusher.Flush()
		case ev, ok := <-ch:
			if !ok {
				return
			}
			if f.BlockedOnly && !ev.Blocked {
				continue
			}
			if qnFilter != "" && !strings.Contains(strings.ToLower(ev.QName), qnFilter) {
				continue
			}
			if ipFilter != "" && !strings.Contains(ev.ClientIP, ipFilter) {
				continue
			}
			if rcFilter != "" && strings.ToUpper(ev.RCode) != rcFilter {
				continue
			}
			if err := writeQuerySSE(w, ev); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func writeQuerySSE(w http.ResponseWriter, ev queryring.QueryEvent) error {
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	_, err = w.Write([]byte("event: query\ndata: " + string(b) + "\n\n"))
	return err
}
