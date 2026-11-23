package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// TestControlPlaneRunsWithoutDatabase builds the real binary and starts it with
// [database] enabled = false, as a Core Profile node does.
func TestControlPlaneRunsWithoutDatabase(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the binary")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "powersvx")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	dnsPort, apiPort := freePort(t), freePort(t)
	cfg := fmt.Sprintf(`
[server]
bind_address = "127.0.0.1"
udp_port = %d
tcp_port = %d

[database]
enabled = false

[cache]
type = "memory"
ttl_seconds = 300

[resolver]
mode = "forward"
forwarders = ["127.0.0.1:9"]

[api]
rest_enabled = true
rest_bind = "127.0.0.1:%d"
auth_type = "none"
`, dnsPort, dnsPort, apiPort)
	cfgPath := filepath.Join(dir, "powersvx.toml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(bin, "-config", cfgPath, "-data-dir", filepath.Join(dir, "data"))
	cmd.Env = append(os.Environ(), "POWERSVX_DNS_DATAPLANE=", "POWERSVX_HOST_DEPLOYMENT=", "POWERSVX_DATABASE_ENABLED=0")
	var logs strings.Builder
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-exited
		if t.Failed() {
			t.Logf("control plane output:\n%s", logs.String())
		}
	})

	base := fmt.Sprintf("http://127.0.0.1:%d", apiPort)
	get := func(path string) (int, []byte) {
		resp, err := http.Get(base + path)
		if err != nil {
			return 0, nil
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}

	// Generous: on a busy machine or CI runner the process can take a long time to come up.
	deadline := time.Now().Add(120 * time.Second)
	var health []byte
	for {
		select {
		case <-exited:
			t.Fatal("control plane exited before answering health")
		default:
		}
		if c, b := get("/api/v1/health"); c == http.StatusOK {
			health = b
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("health endpoint did not answer in 120s")
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Logf("health: %s", health)
	var h struct {
		Status string                    `json:"status"`
		Checks map[string]map[string]any `json:"checks"`
	}
	if err := json.Unmarshal(health, &h); err != nil {
		t.Fatal(err)
	}
	if h.Status == "degraded" || h.Status == "unhealthy" {
		t.Fatalf("health status %q with no database", h.Status)
	}
	if h.Checks["database"]["status"] != "disabled" {
		t.Fatalf("database check %v", h.Checks["database"])
	}

	resp, err := http.Post(base+"/api/v1/zones", "application/json", strings.NewReader(`{"name":"example.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create zone: %d", resp.StatusCode)
	}
	if c, b := get("/api/v1/zones/example.com"); c != http.StatusOK {
		t.Fatalf("read zone: %d %s", c, b)
	}
	if c, b := get("/api/v1/query-logs"); c != http.StatusServiceUnavailable || !strings.Contains(string(b), "Observability Profile") {
		t.Fatalf("query-logs: %d %s", c, b)
	}
}
