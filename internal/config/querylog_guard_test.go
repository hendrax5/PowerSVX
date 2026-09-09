package config

import "testing"

func TestQueryLogForcedOff(t *testing.T) {
	t.Setenv("POWERSVX_DISABLE_QUERY_LOG", "1")
	t.Setenv("POWERSVX_DNS_DATAPLANE", "powersvx")
	if !QueryLogForcedOff() {
		t.Fatal("expected forced off")
	}
	cfg := &Config{}
	cfg.Logging.QueryLogEnabled = true
	ApplyQueryLogGuard(cfg)
	if cfg.Logging.QueryLogEnabled {
		t.Fatal("guard should disable query log on Go dataplane")
	}
}

func TestQueryLogGuardSkipsUnboundDataplane(t *testing.T) {
	t.Setenv("POWERSVX_DISABLE_QUERY_LOG", "1")
	t.Setenv("POWERSVX_DNS_DATAPLANE", "unbound")
	cfg := &Config{}
	cfg.Logging.QueryLogEnabled = true
	ApplyQueryLogGuard(cfg)
	if !cfg.Logging.QueryLogEnabled {
		t.Fatal("unbound dataplane should keep query_log for sampler toggle")
	}
	t.Setenv("POWERSVX_UNBOUND_QUERYLOG", "")
	if UnboundQueryLogAllowed() {
		t.Fatal("unbound querylog must default OFF")
	}
	t.Setenv("POWERSVX_UNBOUND_QUERYLOG", "1")
	if !UnboundQueryLogAllowed() {
		t.Fatal("expected unbound querylog when explicitly enabled")
	}
}
