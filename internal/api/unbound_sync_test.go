package api

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/server"
	"github.com/powersvx/powersvx/internal/unboundrpz"
)

func newSyncAPI(t *testing.T, cfg *config.Config) (*API, *bytes.Buffer, string) {
	t.Helper()
	rpzDir := t.TempDir()
	t.Setenv("POWERSVX_UNBOUND_RPZ_DIR", rpzDir)
	t.Setenv("POWERSVX_HOST_DEPLOYMENT", "1")
	// Nothing listens here: the reload fails like a disabled control interface does.
	t.Setenv("POWERSVX_UNBOUND_CONTROL", "127.0.0.1:1")
	old := unboundReloadRetryDelays
	unboundReloadRetryDelays = nil
	t.Cleanup(func() { unboundReloadRetryDelays = old })

	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	srv := server.New(cfg, server.Deps{}, log)
	a := New(cfg, srv, nil, nil, log)
	a.dataDir = t.TempDir()
	return a, &logs, rpzDir
}

func TestSyncSkipsAForwarderToUnboundAndReportsIt(t *testing.T) {
	cfg := config.Default()
	cfg.Resolver.Mode = "forward"
	cfg.Resolver.Forwarders = []string{"127.0.0.1:5353"}
	a, logs, rpzDir := newSyncAPI(t, cfg)

	a.syncUnboundRuntime([]string{"example.co.id"})

	zones, err := os.ReadFile(filepath.Join(rpzDir, unboundrpz.RuntimeZonesFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(zones), "forward-zone") {
		t.Fatalf("a forward-zone to Unbound was written:\n%s", zones)
	}
	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "forwarder skipped") {
		t.Fatalf("expected a warning in the log, got:\n%s", logs.String())
	}
	rt := a.unboundSync.health()
	if rt == nil || rt["status"] != "degraded" || rt["skipped_forwarders"] == nil {
		t.Fatalf("health must report the skipped forwarder, got %v", rt)
	}
}

func TestSyncWritesARealForwarder(t *testing.T) {
	cfg := config.Default()
	cfg.Resolver.Mode = "forward"
	cfg.Resolver.Forwarders = []string{"1.1.1.1:53"}
	a, _, rpzDir := newSyncAPI(t, cfg)

	a.syncUnboundRuntime(nil)

	zones, _ := os.ReadFile(filepath.Join(rpzDir, unboundrpz.RuntimeZonesFile))
	if !strings.Contains(string(zones), "forward-addr: 1.1.1.1@53") {
		t.Fatalf("a real forwarder must be written:\n%s", zones)
	}
	if rt := a.unboundSync.health(); rt["skipped_forwarders"] != nil {
		t.Fatalf("nothing should be skipped: %v", rt)
	}
}

func TestFailedReloadIsLoggedAsAnErrorAndShownInHealth(t *testing.T) {
	cfg := config.Default()
	a, logs, _ := newSyncAPI(t, cfg)

	a.syncUnboundRuntime(nil)

	if !strings.Contains(logs.String(), "level=ERROR") || !strings.Contains(logs.String(), "unbound reload failed") {
		t.Fatalf("expected an error in the log, got:\n%s", logs.String())
	}
	health := a.healthPayload(context.Background())
	checks, _ := health["checks"].(map[string]any)
	rt, _ := checks["unbound_runtime"].(map[string]any)
	if rt == nil || rt["status"] != "degraded" || rt["reload_error"] == nil {
		t.Fatalf("health must show the failed reload, got %v", checks)
	}
	if health["status"] == "healthy" {
		t.Fatalf("a failed reload must not report healthy: %v", health["status"])
	}
}

func TestReloadFailureIsQuietOutsideAHostDeployment(t *testing.T) {
	cfg := config.Default()
	a, logs, _ := newSyncAPI(t, cfg)
	t.Setenv("POWERSVX_HOST_DEPLOYMENT", "")

	a.syncUnboundRuntime(nil)

	if strings.Contains(logs.String(), "level=ERROR") {
		t.Fatalf("no Unbound is expected outside a host deployment:\n%s", logs.String())
	}
}

const savedLoopSettings = `{
  "resolver_mode": "forward",
  "forwarders": ["127.0.0.1:5353"],
  "forward_zones": [{"zone": "corp.local", "forwarders": ["127.0.0.1:5353", "10.0.0.53:53"]}]
}`

// The TOML is clean (recursive, no forwarders) but the settings file the console saved earlier
// holds the loop. The settings file wins over the TOML, so this is the case that matters on
// nodes where someone ever saved the settings page.
func loadSavedSettings(t *testing.T, cfg *config.Config, dataDir string, normalize bool) (config.RuntimeSettings, string) {
	t.Helper()
	path := config.RuntimeSettingsPath(dataDir)
	if err := os.WriteFile(path, []byte(savedLoopSettings), 0o644); err != nil {
		t.Fatal(err)
	}
	rs, err := config.LoadRuntimeSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	if normalize {
		rs = NormalizeSavedResolver(path, rs, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	}
	cfg.ApplyRuntimeSettings(rs)
	return rs, path
}

func TestSavedSettingsWithTheLoopNeverReachUnbound(t *testing.T) {
	cfg := config.Default() // what a clean TOML gives
	a, logs, rpzDir := newSyncAPI(t, cfg)
	loadSavedSettings(t, cfg, a.dataDir, false)
	if cfg.Resolver.Mode != "forward" || len(cfg.Resolver.Forwarders) != 1 {
		t.Fatalf("the saved settings must override the TOML here: mode=%s forwarders=%v", cfg.Resolver.Mode, cfg.Resolver.Forwarders)
	}

	a.syncUnboundRuntime(nil)

	zones, err := os.ReadFile(filepath.Join(rpzDir, unboundrpz.RuntimeZonesFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(zones), "127.0.0.1") || strings.Contains(string(zones), `name: "."`) {
		t.Fatalf("the saved loop was written to Unbound:\n%s", zones)
	}
	if !strings.Contains(string(zones), "forward-addr: 10.0.0.53@53") || !strings.Contains(string(zones), `name: "corp.local."`) {
		t.Fatalf("the real forwarder of the zone must still be written:\n%s", zones)
	}
	if !strings.Contains(logs.String(), "forwarder skipped") {
		t.Fatalf("expected a warning:\n%s", logs.String())
	}
	if rt := a.unboundSync.health(); rt == nil || rt["skipped_forwarders"] == nil {
		t.Fatalf("health must report it: %v", rt)
	}
}

func TestStartNormalisesSavedSettingsThatPointAtUnbound(t *testing.T) {
	cfg := config.Default()
	a, _, rpzDir := newSyncAPI(t, cfg)
	rs, path := loadSavedSettings(t, cfg, a.dataDir, true)

	if *rs.ResolverMode != "recursive" || len(rs.Forwarders) != 0 {
		t.Fatalf("mode=%s forwarders=%v", *rs.ResolverMode, rs.Forwarders)
	}
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), "127.0.0.1") || !strings.Contains(string(b), "10.0.0.53:53") || !strings.Contains(string(b), `"recursive"`) {
		t.Fatalf("the settings file must be rewritten without the loop and keep the real forwarder:\n%s", b)
	}
	if cfg.Resolver.Mode != "recursive" || len(cfg.Resolver.Forwarders) != 0 {
		t.Fatalf("the running configuration must follow: %s %v", cfg.Resolver.Mode, cfg.Resolver.Forwarders)
	}

	a.syncUnboundRuntime(nil)
	zones, _ := os.ReadFile(filepath.Join(rpzDir, unboundrpz.RuntimeZonesFile))
	if strings.Contains(string(zones), "127.0.0.1") {
		t.Fatalf("loop written:\n%s", zones)
	}
	if rt := a.unboundSync.health(); rt["skipped_forwarders"] != nil {
		t.Fatalf("nothing is left to skip once the file is clean: %v", rt)
	}
}

func TestNormaliseLeavesCleanSettingsAlone(t *testing.T) {
	dir := t.TempDir()
	path := config.RuntimeSettingsPath(dir)
	mode := "forward"
	rs := config.RuntimeSettings{ResolverMode: &mode, Forwarders: []string{"1.1.1.1:53"}}
	if err := config.SaveRuntimeSettings(path, rs); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	out := NormalizeSavedResolver(path, rs, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	after, _ := os.ReadFile(path)
	if string(before) != string(after) || *out.ResolverMode != "forward" || len(out.Forwarders) != 1 {
		t.Fatalf("clean settings were changed:\n%s\n%s", before, after)
	}
}
