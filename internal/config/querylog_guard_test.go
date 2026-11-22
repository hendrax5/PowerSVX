package config

import "testing"

func TestQueryLogForcedOff(t *testing.T) {
	t.Setenv("POWERSVX_DISABLE_QUERY_LOG", "1")
	if !QueryLogForcedOff() {
		t.Fatal("expected forced off")
	}
}

// The Go process is never on :53, so the guard has nothing to protect and the
// query_log toggle is kept, whatever POWERSVX_DNS_DATAPLANE says.
func TestQueryLogGuardKeepsTheToggle(t *testing.T) {
	t.Setenv("POWERSVX_DISABLE_QUERY_LOG", "1")
	for _, mode := range []string{"dnsdist", "", "powersvx"} {
		t.Setenv("POWERSVX_DNS_DATAPLANE", mode)
		cfg := &Config{}
		cfg.Logging.QueryLogEnabled = true
		ApplyQueryLogGuard(cfg)
		if !cfg.Logging.QueryLogEnabled {
			t.Fatalf("mode %q: the query_log toggle must be kept", mode)
		}
	}
}
