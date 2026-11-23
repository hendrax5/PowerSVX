package unboundloop_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// buildTool builds ./test/unboundloop/<name> for the Docker host (Linux) into a scratch directory.
func buildTool(t *testing.T, name string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), name)
	build := exec.Command("go", "build", "-o", bin, "./test/unboundloop/"+name)
	build.Dir = repoRoot(t)
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build %s: %v\n%s", name, err, out)
	}
	return bin
}

// client is a container on the default Docker bridge with an address of its own, from which
// dnsq sends requests: dnsdist sees that address as the client.
type client struct {
	name, ip string
	t        *testing.T
}

func startClient(t *testing.T, dnsq string) *client {
	t.Helper()
	c := &client{name: fmt.Sprintf("powersvx-pp-client-%d", time.Now().UnixNano()), t: t}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", "-v", c.name).Run() })
	docker(t, "create", "--name", c.name, cpImage, "sleep", "3600")
	docker(t, "cp", dnsq, c.name+":/dnsq")
	docker(t, "start", c.name)
	c.ip = docker(t, "inspect", "-f", "{{(index .NetworkSettings.Networks \"bridge\").IPAddress}}", c.name)
	if c.ip == "" {
		t.Fatalf("container %s has no bridge address", c.name)
	}
	return c
}

// ask runs dnsq in the client container and returns its one line of output.
func (c *client) ask(server string, args ...string) string {
	c.t.Helper()
	out, err := exec.Command("docker", append([]string{"exec", c.name, "/dnsq", "-s", server}, args...)...).CombinedOutput()
	if err != nil {
		c.t.Fatalf("dnsq %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// dnsdistAddr is the address of a dnsdist container on the default bridge, reachable from the clients.
func dnsdistAddr(t *testing.T, ctr string) string {
	t.Helper()
	ip := docker(t, "inspect", "-f", "{{(index .NetworkSettings.Networks \"bridge\").IPAddress}}", ctr)
	if ip == "" {
		t.Fatalf("container %s has no bridge address", ctr)
	}
	return ip + ":53"
}
