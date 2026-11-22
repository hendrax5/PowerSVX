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
	// dnsdist Dataplane: Go is not on :53, so the guard has nothing to protect.
	if DNSDistDataplane() {
		return
	}
	if QueryLogForcedOff() {
		c.Logging.QueryLogEnabled = false
	}
}
