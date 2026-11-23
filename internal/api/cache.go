package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/powersvx/powersvx/internal/apiauth"
	"github.com/powersvx/powersvx/internal/audit"
	"github.com/powersvx/powersvx/internal/dnsdistctl"
	"github.com/powersvx/powersvx/internal/unboundrpz"
)

func (a *API) handleCacheStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	out := map[string]any{}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if st, err := dnsdistctl.DefaultClient().Stats(ctx); err == nil {
		out["dnsdist"] = map[string]any{
			"status":         "ok",
			"queries":        st["queries"],
			"cache_hits":     st["cache-hits"],
			"cache_misses":   st["cache-misses"],
			"entries":        st["cache-entries"],
			"self_answered":  st["self-answered"],
			"latency_avg100": st["latency-avg100"],
			"dyn_blocked":    st["dyn-blocked"],
			"rule_drop":      st["rule-drop"],
			"rule_nxdomain":  st["rule-nxdomain"],
			"rule_refused":   st["rule-refused"],
		}
	} else {
		out["dnsdist"] = map[string]any{"status": "unavailable", "err": err.Error()}
	}
	if ust, err := unboundrpz.Stats(); err == nil {
		q := ust["total.num.queries"]
		h := ust["total.num.cachehits"]
		ratio := 0.0
		if q > 0 {
			ratio = h / q
		}
		out["unbound"] = map[string]any{
			"status":       "ok",
			"queries":      q,
			"cache_hits":   h,
			"cache_misses": ust["total.num.cachemiss"],
			"hit_ratio":    ratio,
			"mem_rrset":    ust["mem.cache.rrset"],
			"mem_msg":      ust["mem.cache.message"],
			"bogus":        ust["num.rrset.bogus"],
			"expired":      ust["total.num.expired"],
		}
	} else {
		out["unbound"] = map[string]any{"status": "unavailable", "err": err.Error()}
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) handleCacheInspect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	lines, err := unboundrpz.DumpCache(q, limit)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"entries": []string{},
			"filter":  q,
			"error":   err.Error(),
		})
		return
	}
	if lines == nil {
		lines = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"entries": lines,
		"count":   len(lines),
		"filter":  q,
	})
}

func (a *API) handleCacheFlush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Scope  string `json:"scope"` // all | domain | zone | type | negative
		Domain string `json:"domain"`
		Type   string `json:"type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	scope := strings.ToLower(strings.TrimSpace(body.Scope))
	if scope == "" {
		scope = "all"
	}
	domain := strings.TrimSpace(body.Domain)
	qtype := strings.ToUpper(strings.TrimSpace(body.Type))

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	results := map[string]any{}
	switch scope {
	case "all":
		if err := dnsdistctl.DefaultClient().FlushCache(ctx); err != nil {
			results["dnsdist"] = "error: " + err.Error()
		} else {
			results["dnsdist"] = "flushed"
		}
		if out, err := unboundrpz.FlushZone("."); err != nil {
			results["unbound"] = "error: " + err.Error()
		} else {
			results["unbound"] = out
		}
	case "domain":
		if domain == "" {
			http.Error(w, "domain required", http.StatusBadRequest)
			return
		}
		if err := dnsdistctl.DefaultClient().ExpungeByName(ctx, domain); err != nil {
			results["dnsdist"] = "error: " + err.Error()
		} else {
			results["dnsdist"] = "expunged " + domain
		}
		if out, err := unboundrpz.FlushDomain(domain); err != nil {
			results["unbound"] = "error: " + err.Error()
		} else {
			results["unbound"] = out
		}
	case "zone":
		if domain == "" {
			http.Error(w, "domain (zone) required", http.StatusBadRequest)
			return
		}
		if err := dnsdistctl.DefaultClient().FlushCache(ctx); err != nil {
			results["dnsdist"] = "error: " + err.Error()
		} else {
			results["dnsdist"] = "flushed"
		}
		if out, err := unboundrpz.FlushZone(domain); err != nil {
			results["unbound"] = "error: " + err.Error()
		} else {
			results["unbound"] = out
		}
	case "type":
		if domain == "" || qtype == "" {
			http.Error(w, "domain and type required", http.StatusBadRequest)
			return
		}
		if err := dnsdistctl.DefaultClient().ExpungeByName(ctx, domain); err != nil {
			results["dnsdist"] = "error: " + err.Error()
		} else {
			results["dnsdist"] = "expunged " + domain
		}
		if out, err := unboundrpz.FlushType(domain, qtype); err != nil {
			results["unbound"] = "error: " + err.Error()
		} else {
			results["unbound"] = out
		}
	case "negative":
		if err := dnsdistctl.DefaultClient().FlushCache(ctx); err != nil {
			results["dnsdist"] = "error: " + err.Error()
		} else {
			results["dnsdist"] = "flushed"
		}
		if out, err := unboundrpz.FlushNegative(); err != nil {
			results["unbound"] = "error: " + err.Error()
		} else {
			results["unbound"] = out
		}
	default:
		http.Error(w, "invalid scope (use all, domain, zone, type, negative)", http.StatusBadRequest)
		return
	}

	if a.audit != nil {
		p, _ := apiauth.PrincipalFrom(r.Context())
		a.audit.Record(audit.Event{
			Actor:  p.Name,
			Role:   p.Role,
			Action: "cache_flush",
			Path:   r.URL.Path,
			Status: http.StatusOK,
			Meta:   map[string]string{"scope": scope, "domain": domain, "type": qtype},
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"scope":   scope,
		"domain":  domain,
		"type":    qtype,
		"results": results,
	})
}
