package unboundrpz

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/powersvx/powersvx/internal/config"
)

func TestForwarderLoop(t *testing.T) {
	cases := []struct {
		addr string
		port int
		loop bool
	}{
		// Unbound's own listener, written every way a configuration or the console writes it.
		{"127.0.0.1:5353", 5353, true},
		{"127.0.0.1@5353", 5353, true},
		{"[::1]:5353", 5353, true},
		{"::1@5353", 5353, true},
		{"localhost:5353", 5353, true},
		{"127.0.0.53:5353", 5353, true},
		{" 127.0.0.1:5353 ", 5353, true},
		{"[::ffff:127.0.0.1]:5353", 5353, true},
		{"0.0.0.0:5353", 5353, true},
		// No port means 53, where dnsdist listens and sends the query back to Unbound.
		{"127.0.0.1", 5353, true},
		{"::1", 5353, true},
		{"[::1]", 5353, true},
		{"localhost", 5353, true},
		{"127.0.0.1:53", 5353, true},
		// A non-default backend port follows the configuration.
		{"127.0.0.1:5399", 5399, true},
		{"127.0.0.1:5353", 5399, false},
		// Another resolver keeps working: remote hosts, or loopback on an unrelated port.
		{"1.1.1.1", 5353, false},
		{"1.1.1.1:53", 5353, false},
		{"1.1.1.1:5353", 5353, false},
		{"[2606:4700:4700::1111]:53", 5353, false},
		{"9.9.9.9@53", 5353, false},
		{"10.0.0.53:5353", 5353, false},
		{"127.0.0.1:5354", 5353, false}, // the Auth Backend is not Unbound
		{"127.0.0.1:9953", 5353, false},
		{"unbound.example:5353", 5353, false},
		{"", 5353, false},
		{"127.0.0.1@notaport", 5353, false},
	}
	for _, tc := range cases {
		loop, why := ForwarderLoop(tc.addr, tc.port)
		if loop != tc.loop {
			t.Errorf("ForwarderLoop(%q, %d) = %v, want %v", tc.addr, tc.port, loop, tc.loop)
		}
		if loop && why == "" {
			t.Errorf("ForwarderLoop(%q, %d) gave no reason", tc.addr, tc.port)
		}
	}
}

func TestBackendPortFromEnvironment(t *testing.T) {
	t.Setenv("POWERSVX_UNBOUND_BACKEND_PORT", "")
	if got := BackendPort(); got != 5353 {
		t.Fatalf("default backend port = %d", got)
	}
	t.Setenv("POWERSVX_UNBOUND_BACKEND_PORT", "5399")
	if got := BackendPort(); got != 5399 {
		t.Fatalf("backend port = %d, want 5399", got)
	}
	t.Setenv("POWERSVX_UNBOUND_BACKEND_PORT", "nope")
	if got := BackendPort(); got != 5353 {
		t.Fatalf("invalid backend port = %d, want the default", got)
	}
}

func writeAndRead(t *testing.T, spec RuntimeSyncSpec) (zones string, report RuntimeReport) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("POWERSVX_UNBOUND_RPZ_DIR", "")
	report, err := WriteRuntimeConfig(dir, spec)
	if err != nil {
		t.Fatalf("WriteRuntimeConfig: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(Dir(dir), RuntimeZonesFile))
	if err != nil {
		t.Fatal(err)
	}
	return string(b), report
}

func TestWriterNeverEmitsAForwarderToItself(t *testing.T) {
	zones, report := writeAndRead(t, RuntimeSyncSpec{
		ResolverMode: "forward",
		Forwarders:   []string{"127.0.0.1:5353"},
		AuthZones:    []string{"example.co.id"},
	})
	if strings.Contains(zones, "forward-zone") || strings.Contains(zones, "forward-addr") {
		t.Fatalf("a forward-zone to Unbound itself was written:\n%s", zones)
	}
	if !strings.Contains(zones, "stub-zone") {
		t.Fatalf("the hosted zone's stub-zone must still be written:\n%s", zones)
	}
	if len(report.SkippedForwarders) != 1 || report.SkippedForwarders[0].Zone != "." || report.SkippedForwarders[0].Addr != "127.0.0.1:5353" {
		t.Fatalf("report = %+v", report)
	}
}

func TestWriterSkipsOnlyTheLoopingForwarders(t *testing.T) {
	zones, report := writeAndRead(t, RuntimeSyncSpec{
		ResolverMode: "forward",
		Forwarders:   []string{"127.0.0.1:5353", "[::1]:5353", "1.1.1.1:53"},
		ForwardZones: []config.ForwardZoneConfig{
			{Zone: "corp.local", Forwarders: []string{"localhost:5353", "10.0.0.53"}},
			{Zone: "loop.local", Forwarders: []string{"127.0.0.1:5353"}},
		},
	})
	if !strings.Contains(zones, "forward-addr: 1.1.1.1@53") || !strings.Contains(zones, "forward-addr: 10.0.0.53") {
		t.Fatalf("real forwarders must be written:\n%s", zones)
	}
	if strings.Contains(zones, "127.0.0.1") || strings.Contains(zones, "::1") || strings.Contains(zones, "loop.local") {
		t.Fatalf("a looping forwarder was written:\n%s", zones)
	}
	if len(report.SkippedForwarders) != 4 {
		t.Fatalf("want 4 skipped forwarders, got %+v", report.SkippedForwarders)
	}
}

func TestWriterHonoursTheConfiguredBackendPort(t *testing.T) {
	t.Setenv("POWERSVX_UNBOUND_BACKEND_PORT", "5399")
	zones, report := writeAndRead(t, RuntimeSyncSpec{
		ResolverMode: "forward",
		Forwarders:   []string{"127.0.0.1:5399", "127.0.0.1:5353"},
	})
	if !strings.Contains(zones, "forward-addr: 127.0.0.1@5353") || strings.Contains(zones, "5399") {
		t.Fatalf("only the configured backend port is Unbound's own:\n%s", zones)
	}
	if len(report.SkippedForwarders) != 1 {
		t.Fatalf("report = %+v", report)
	}
}

func TestRecursiveModeWritesNoForwardZone(t *testing.T) {
	zones, report := writeAndRead(t, RuntimeSyncSpec{ResolverMode: "recursive", AuthZones: []string{"example.co.id"}})
	if strings.Contains(zones, "forward-zone") || len(report.SkippedForwarders) != 0 {
		t.Fatalf("recursive mode must leave Unbound to recurse:\n%s\n%+v", zones, report)
	}
}
