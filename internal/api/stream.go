package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/powersvx/powersvx/internal/queryring"
)

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
