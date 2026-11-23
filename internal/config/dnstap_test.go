package config

import (
	"math"
	"path/filepath"
	"testing"
)

func TestQueryLogRate(t *testing.T) {
	cases := []struct {
		enabled bool
		rate    float64
		want    float64
	}{
		{false, 0.5, 0}, // disabled: no sampling whatever the rate says
		{true, 0, 0},    // enabled at 0: no sampling, no cost
		{true, -1, 0},
		{true, math.NaN(), 0},
		{true, 0.05, 0.05},
		{true, 1, 1},
		{true, 7, 1},
	}
	for _, c := range cases {
		cfg := &Config{}
		cfg.Logging.QueryLogEnabled = c.enabled
		cfg.Logging.QueryLogSampleRate = c.rate
		if got := cfg.QueryLogRate(); got != c.want {
			t.Errorf("enabled=%v rate=%v: got %v, want %v", c.enabled, c.rate, got, c.want)
		}
	}
	if (*Config)(nil).QueryLogRate() != 0 {
		t.Error("nil config must not sample")
	}
}

// The default configuration never samples: the query log is off until switched on.
func TestDefaultConfigDoesNotSample(t *testing.T) {
	if got := Default().QueryLogRate(); got != 0 {
		t.Fatalf("default config samples at %v", got)
	}
}

func TestDNSTapDir(t *testing.T) {
	t.Setenv("POWERSVX_DNSTAP_DIR", "")
	if got, want := DNSTapDir("/data"), filepath.Join("/data", "dnstap"); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	t.Setenv("POWERSVX_DNSTAP_DIR", "/run/dnstap")
	if got := DNSTapDir("/data"); got != "/run/dnstap" {
		t.Fatalf("got %q", got)
	}
}
