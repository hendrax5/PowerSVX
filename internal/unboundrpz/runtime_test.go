package unboundrpz

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/powersvx/powersvx/internal/config"
)

func TestWriteRuntimeConfig(t *testing.T) {
	dir := t.TempDir()
	spec := RuntimeSyncSpec{
		ResolverMode:  "forward",
		ForwardOnFail: true,
		Forwarders:    []string{"1.1.1.1:53", "9.9.9.9"},
		ForwardZones: []config.ForwardZoneConfig{
			{Zone: "corp.local", Forwarders: []string{"10.0.0.53"}},
			{Zone: "bad\nzone", Forwarders: []string{"not-an-ip"}},
		},
		DNSSECMode: "permissive",
		ECSEnabled: true,
		AuthZones:  []string{"example.co.id."},
	}
	if err := WriteRuntimeConfig(dir, spec); err != nil {
		t.Fatalf("WriteRuntimeConfig failed: %v", err)
	}

	srvBytes, err := os.ReadFile(filepath.Join(Dir(dir), RuntimeServerFile))
	if err != nil {
		t.Fatal(err)
	}
	srv := string(srvBytes)
	if !strings.Contains(srv, "send-client-subnet: 0.0.0.0/0") || !strings.Contains(srv, `domain-insecure: "example.co.id."`) {
		t.Fatalf("unexpected runtime-server.conf:\n%s", srv)
	}

	zBytes, err := os.ReadFile(filepath.Join(Dir(dir), RuntimeZonesFile))
	if err != nil {
		t.Fatal(err)
	}
	zs := string(zBytes)
	if !strings.Contains(zs, `stub-addr: 127.0.0.1@5354`) || !strings.Contains(zs, `forward-addr: 1.1.1.1@53`) || !strings.Contains(zs, `name: "corp.local."`) {
		t.Fatalf("unexpected runtime-zones.conf:\n%s", zs)
	}
	if strings.Contains(zs, "bad\nzone") || strings.Contains(zs, "not-an-ip") {
		t.Fatalf("unsanitized forward zone leaked:\n%s", zs)
	}
}
