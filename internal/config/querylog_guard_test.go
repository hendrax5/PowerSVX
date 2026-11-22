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

func TestQueryLogGuardSkipsDnsdistDataplane(t *testing.T) {
	t.Setenv("POWERSVX_DISABLE_QUERY_LOG", "1")
	t.Setenv("POWERSVX_DNS_DATAPLANE", "dnsdist")
	cfg := &Config{}
	cfg.Logging.QueryLogEnabled = true
	ApplyQueryLogGuard(cfg)
	if !cfg.Logging.QueryLogEnabled {
		t.Fatal("dnsdist dataplane keeps the query_log toggle")
	}
}
