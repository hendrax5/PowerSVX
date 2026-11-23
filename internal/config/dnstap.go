package config

import (
	"os"
	"path/filepath"
	"strings"
)

// DNSTapDir is the directory the Control Plane shares with dnsdist for the sampled
// query log: the Control Plane listens on query.sock in it and writes the sample
// rate to the file "rate". dnsdist sees the same directory as /etc/dnsdist/dnstap.
func DNSTapDir(dataDir string) string {
	if d := strings.TrimSpace(os.Getenv("POWERSVX_DNSTAP_DIR")); d != "" {
		return d
	}
	if dataDir == "" {
		dataDir = "./data"
	}
	return filepath.Join(dataDir, "dnstap")
}

// QueryLogRate is the fraction of answered queries the Dataplane samples into the
// query log. It is 0 (no sampling, no cost) unless the query log is enabled and the
// sample rate is above 0.
func (c *Config) QueryLogRate() float64 {
	if c == nil || !c.Logging.QueryLogEnabled {
		return 0
	}
	r := c.Logging.QueryLogSampleRate
	switch {
	case r != r || r <= 0:
		return 0
	case r > 1:
		return 1
	}
	return r
}
