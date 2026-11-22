package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDatabaseEnabledEnvOverride(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.toml")
	if err := os.WriteFile(path, []byte("[database]\nenabled = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		env  string
		want bool
	}{{"", true}, {"0", false}, {"false", false}, {"1", true}, {"junk", true}}
	for _, c := range cases {
		t.Setenv("POWERSVX_DATABASE_ENABLED", c.env)
		cfg, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Database.Enabled != c.want {
			t.Errorf("POWERSVX_DATABASE_ENABLED=%q: enabled=%v, want %v", c.env, cfg.Database.Enabled, c.want)
		}
	}
}
