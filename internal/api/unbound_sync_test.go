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
