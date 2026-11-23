package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadReportsRemovedKeysAndStillLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.toml")
	body := `
[server]
udp_port = 5353
dot_port = 853
doh_port = 443

[server.tls]
enabled = true
cert_file = "x"

[cache]
type = "badger"
max_size_mb = 512

[resolver]
forwarders = ["9.9.9.9:53"]
max_inflight = 2048

[plugins]
enabled = true
dir = "/var/lib/powersvx/plugins"

[api]
rest_bind = "127.0.0.1:5380"
grpc_enabled = true
grpc_bind = "127.0.0.1:5381"

[metrics]
otel_enabled = true

[rpz]
hot_cache_max = 1000
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("a file with removed keys must still load: %v", err)
	}
	want := []string{"api.grpc_bind", "api.grpc_enabled", "cache", "metrics.otel_enabled", "plugins", "resolver.max_inflight", "rpz.hot_cache_max", "server.doh_port", "server.dot_port", "server.tls"}
	if !reflect.DeepEqual(cfg.RemovedKeys, want) {
		t.Fatalf("removed keys = %v, want %v", cfg.RemovedKeys, want)
	}
	if cfg.Server.UDPPort != 5353 || cfg.API.RESTBind != "127.0.0.1:5380" || len(cfg.Resolver.Forwarders) != 1 {
		t.Fatalf("kept keys lost: %+v", cfg.Server)
	}
}

func TestLoadWarnsOnceForServerTProxy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tproxy.toml")
	body := "[server]\nudp_port = 5353\ntproxy = true\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("a file with server.tproxy must still load: %v", err)
	}
	if want := []string{"server.tproxy"}; !reflect.DeepEqual(cfg.RemovedKeys, want) {
		t.Fatalf("removed keys = %v, want %v", cfg.RemovedKeys, want)
	}
	if cfg.Server.UDPPort != 5353 {
		t.Fatalf("kept keys lost: %+v", cfg.Server)
	}
}
