package config

import (
	"os"
	"strings"
)

// QueryLogForcedOff is set on production compose so UI/runtime-settings cannot
// re-enable Go-edge Postgres query log (that burned CPU under multi-k QPS).
func QueryLogForcedOff() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("POWERSVX_DISABLE_QUERY_LOG")))
	return v == "1" || v == "true" || v == "yes"
}

func ApplyQueryLogGuard(c *Config) {
	if c == nil {
		return
	}
	// Filter dataplane (Unbound/dnsdist): Go is not on :53; keep QueryLogEnabled
	// as the UI toggle for Unbound log sampling (see UnboundQueryLogAllowed).
	if FilterDataplane() {
		return
	}
	if QueryLogForcedOff() {
		c.Logging.QueryLogEnabled = false
	}
}

// UnboundQueryLogAllowed enables the Unbound logfile → Postgres sampler.
// Default on when dataplane=unbound unless POWERSVX_UNBOUND_QUERYLOG=0.
func UnboundQueryLogAllowed() bool {
	if !UnboundDataplane() {
		return false
	}
	v := strings.ToLower(strings.TrimSpace(os.Getenv("POWERSVX_UNBOUND_QUERYLOG")))
	if v == "" {
		// Default OFF: Unbound log-queries + 9.5M RPZ saturated JLA (Recv-Q millions).
		return false
	}
	return v == "1" || v == "true" || v == "yes" || v == "on"
}
