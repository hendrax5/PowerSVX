package linux_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// generateWith runs both generators for a node of the given size with extra environment
// variables, the way an operator sets a tuning knob in powersvx.env.
func generateWith(t *testing.T, cpus, memMB string, extra ...string) (unbound, dnsdist string) {
	t.Helper()
	root := node(t)
	env := append([]string{"POWERSVX_HOST_CPUS=" + cpus, "POWERSVX_HOST_MEM_MB=" + memMB, "POWERSVX_DNSDIST_IPV6=1"}, extra...)
	ub := filepath.Join(root, "unbound.conf")
	dd := filepath.Join(root, "dnsdist.conf")
	if out, err := sh(t, root, env, "gen-unbound-conf.sh", ub); err != nil {
		t.Fatalf("gen-unbound-conf.sh: %v\n%s", err, out)
	}
	if out, err := sh(t, root, env, "gen-dnsdist-conf.sh", dd); err != nil {
		t.Fatalf("gen-dnsdist-conf.sh: %v\n%s", err, out)
	}
	ubText, err := os.ReadFile(ub)
	if err != nil {
		t.Fatal(err)
	}
	ddText, err := os.ReadFile(dd)
	if err != nil {
		t.Fatal(err)
	}
	return string(ubText), string(ddText)
}

func golden(t *testing.T, kind, cpus, mem string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "default", fmt.Sprintf("%s-%scpu-%smb.conf", kind, cpus, mem)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// With no knob set, the generated configuration is byte for byte what the generators wrote
// before the knobs existed (testdata/default was produced by the integration branch's
// generators with every knob unset, not by this branch's code).
//
// This test breaks on ANY change to what the generators write by default. When that change is
// intended, refresh the golden files from the repository root on a Linux host (sh, nproc) and
// review the diff of testdata/default/ as part of the generator change itself:
//
//	for s in "2 2048" "12 16384"; do set -- $s; \
//	  POWERSVX_DNS_DATAPLANE=dnsdist POWERSVX_DNSDIST_IPV6=1 POWERSVX_HOST_CPUS=$1 POWERSVX_HOST_MEM_MB=$2 \
//	    sh deploy/linux/gen-unbound-conf.sh deploy/linux/testdata/default/unbound-$1cpu-$2mb.conf; \
//	  POWERSVX_DNS_DATAPLANE=dnsdist POWERSVX_DNSDIST_IPV6=1 POWERSVX_HOST_CPUS=$1 POWERSVX_HOST_MEM_MB=$2 \
//	    sh deploy/linux/gen-dnsdist-conf.sh deploy/linux/testdata/default/dnsdist-$1cpu-$2mb.conf; \
//	done
//
// (The generators also create data/ under the repository root; delete it afterwards.) Never
// refresh to make a failure go away without knowing which generator change caused it.
func TestDefaultConfigurationIsUnchangedByTheKnobs(t *testing.T) {
	for _, size := range []struct{ cpus, mem string }{{"2", "2048"}, {"12", "16384"}} {
		t.Run(size.cpus+"cpu-"+size.mem+"mb", func(t *testing.T) {
			ub, dd := generateWith(t, size.cpus, size.mem)
			if ub != golden(t, "unbound", size.cpus, size.mem) {
				t.Error("unbound configuration for the default environment changed")
			}
			if dd != golden(t, "dnsdist", size.cpus, size.mem) {
				t.Error("dnsdist configuration for the default environment changed")
			}
		})
	}
	t.Run("explicit default values", func(t *testing.T) {
		ub, dd := generateWith(t, "12", "16384",
			"POWERSVX_DNSDIST_UDP_LISTENERS=1", "POWERSVX_UNBOUND_THREADS=half", "POWERSVX_UNBOUND_PREFETCH=no")
		if ub != golden(t, "unbound", "12", "16384") || dd != golden(t, "dnsdist", "12", "16384") {
			t.Error("explicit default values change the generated configuration")
		}
	})
}

func TestDnsdistUDPListeners(t *testing.T) {
	cases := []struct {
		name, value, cpus string
		wantEach          int // listeners per address
	}{
		{"one is today", "1", "12", 1},
		{"auto follows the CPUs", "auto", "12", 12},
		{"auto on a small node", "auto", "2", 2},
		{"auto is capped", "auto", "128", 64},
		{"explicit", "4", "12", 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, dd := generateWith(t, tc.cpus, "16384", "POWERSVX_DNSDIST_UDP_LISTENERS="+tc.value)
			if tc.wantEach == 1 {
				mustContain(t, "dnsdist", dd, "addLocal(\"0.0.0.0:53\")\n", "addLocal(\"[::]:53\")\n")
				if strings.Contains(dd, "reusePort") {
					t.Error("one listener must not set reusePort")
				}
				return
			}
			if n := strings.Count(dd, "addLocal(\"0.0.0.0:53\", {reusePort=true})\n"); n != tc.wantEach {
				t.Errorf("IPv4 listeners: want %d, got %d", tc.wantEach, n)
			}
			if n := strings.Count(dd, "addLocal(\"[::]:53\", {reusePort=true})\n"); n != tc.wantEach {
				t.Errorf("IPv6 listeners: want %d, got %d", tc.wantEach, n)
			}
			if strings.Contains(dd, "addLocal(\"0.0.0.0:53\")") || strings.Contains(dd, "addLocal(\"[::]:53\")") {
				t.Error("a listener without reusePort next to reusePort listeners cannot bind")
			}
		})
	}
	t.Run("IPv6 off", func(t *testing.T) {
		_, dd := generateWith(t, "4", "4096", "POWERSVX_DNSDIST_UDP_LISTENERS=3", "POWERSVX_DNSDIST_IPV6=0")
		if n := strings.Count(dd, "reusePort=true"); n != 3 {
			t.Errorf("want 3 IPv4 listeners and no IPv6 ones, got %d reusePort listeners", n)
		}
	})
}

func TestDnsdistCacheShards(t *testing.T) {
	cases := []struct{ name, value, cpus, want string }{
		{"unset is today", "", "12", "maxNegativeTTL=300})\n"},
		{"auto follows the CPUs", "auto", "12", "maxNegativeTTL=300, numberOfShards=12})\n"},
		{"auto is capped", "auto", "128", "maxNegativeTTL=300, numberOfShards=64})\n"},
		{"explicit", "8", "12", "maxNegativeTTL=300, numberOfShards=8})\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, dd := generateWith(t, tc.cpus, "16384", "POWERSVX_DNSDIST_CACHE_SHARDS="+tc.value)
			mustContain(t, "dnsdist", dd, "pc = newPacketCache(1000000,{maxTTL=86400, minTTL=60, "+tc.want)
			// With the PROXY protocol (the default) the Auth Backend pool has no cache at all.
			if strings.Contains(dd, "pcAuth") {
				t.Error("the Auth Backend pool has a packet cache in PROXY mode")
			}
			// Only the main cache is sharded; with the PROXY protocol off, the Authoritative
			// Zone cache is left as it is.
			_, dd = generateWith(t, tc.cpus, "16384", "POWERSVX_DNSDIST_CACHE_SHARDS="+tc.value, "POWERSVX_AUTH_PROXY_PROTOCOL=0")
			mustContain(t, "dnsdist", dd, "pc = newPacketCache(1000000,{maxTTL=86400, minTTL=60, "+tc.want,
				"pcAuth = newPacketCache(50000,{maxTTL=300, minTTL=0, maxNegativeTTL=60})\n")
		})
	}
}

func TestUnboundPrefetch(t *testing.T) {
	ub, _ := generateWith(t, "4", "4096")
	mustContain(t, "unbound default", ub, "    prefetch: no\n")
	ub, _ = generateWith(t, "4", "4096", "POWERSVX_UNBOUND_PREFETCH=yes")
	mustContain(t, "unbound prefetch", ub, "    prefetch: yes\n", "    prefetch-key: yes\n")
}

func TestUnboundThreads(t *testing.T) {
	cases := []struct {
		name, value, cpus string
		threads, slabs    int
	}{
		{"half is today", "half", "12", 6, 8},
		{"half on a small node", "half", "2", 2, 2},
		{"half is capped", "half", "64", 16, 16},
		{"all", "all", "12", 12, 16},
		{"all on one CPU keeps two threads", "all", "1", 2, 2},
		{"all is capped", "all", "64", 32, 32},
		{"explicit", "5", "12", 5, 8},
		{"explicit power of two", "8", "12", 8, 8},
		{"explicit one", "1", "12", 1, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ub, _ := generateWith(t, tc.cpus, "16384", "POWERSVX_UNBOUND_THREADS="+tc.value)
			mustContain(t, "unbound", ub,
				fmt.Sprintf("    num-threads: %d\n", tc.threads),
				fmt.Sprintf("    msg-cache-slabs: %d\n", tc.slabs),
				fmt.Sprintf("    rrset-cache-slabs: %d\n", tc.slabs),
				fmt.Sprintf("    infra-cache-slabs: %d\n", tc.slabs),
				fmt.Sprintf("    key-cache-slabs: %d\n", tc.slabs))
		})
	}
}

func TestKnobsRejectInvalidValues(t *testing.T) {
	root := node(t)
	cases := []struct{ script, env string }{
		{"gen-dnsdist-conf.sh", "POWERSVX_DNSDIST_UDP_LISTENERS=many"},
		{"gen-dnsdist-conf.sh", "POWERSVX_DNSDIST_UDP_LISTENERS=0"},
		{"gen-dnsdist-conf.sh", "POWERSVX_DNSDIST_UDP_LISTENERS=-2"},
		{"gen-dnsdist-conf.sh", "POWERSVX_DNSDIST_UDP_LISTENERS=65"},
		{"gen-dnsdist-conf.sh", "POWERSVX_DNSDIST_UDP_LISTENERS=2.5"},
		{"gen-dnsdist-conf.sh", "POWERSVX_DNSDIST_CACHE_SHARDS=lots"},
		{"gen-dnsdist-conf.sh", "POWERSVX_DNSDIST_CACHE_SHARDS=0"},
		{"gen-dnsdist-conf.sh", "POWERSVX_DNSDIST_CACHE_SHARDS=65"},
		{"gen-dnsdist-conf.sh", "POWERSVX_DNSDIST_CACHE_SHARDS=-1"},
		{"gen-unbound-conf.sh", "POWERSVX_UNBOUND_THREADS=most"},
		{"gen-unbound-conf.sh", "POWERSVX_UNBOUND_THREADS=0"},
		{"gen-unbound-conf.sh", "POWERSVX_UNBOUND_THREADS=33"},
		{"gen-unbound-conf.sh", "POWERSVX_UNBOUND_THREADS=-4"},
		{"gen-unbound-conf.sh", "POWERSVX_UNBOUND_PREFETCH=maybe"},
		{"gen-unbound-conf.sh", "POWERSVX_UNBOUND_PREFETCH=1"},
	}
	for _, tc := range cases {
		t.Run(tc.env, func(t *testing.T) {
			out, err := sh(t, root, []string{tc.env}, tc.script, filepath.Join(root, tc.script+".out"))
			if err == nil {
				t.Fatalf("expected %s to refuse %s, it succeeded:\n%s", tc.script, tc.env, out)
			}
			name, _, _ := strings.Cut(tc.env, "=")
			if !strings.Contains(out, name+" must be") {
				t.Errorf("refusal does not name %s: %s", name, out)
			}
		})
	}
}

func TestGeneratorSummaryShowsTheKnobsInEffect(t *testing.T) {
	root := node(t)
	env := []string{"POWERSVX_HOST_CPUS=4", "POWERSVX_HOST_MEM_MB=4096", "POWERSVX_DNSDIST_UDP_LISTENERS=auto",
		"POWERSVX_DNSDIST_CACHE_SHARDS=4", "POWERSVX_UNBOUND_THREADS=all", "POWERSVX_UNBOUND_PREFETCH=yes"}
	out, err := sh(t, root, env, "gen-dnsdist-conf.sh", filepath.Join(root, "d.conf"))
	if err != nil {
		t.Fatal(err, out)
	}
	mustContain(t, "dnsdist summary", out, "udp-listeners=4", "cache-shards=4")
	out, err = sh(t, root, env, "gen-unbound-conf.sh", filepath.Join(root, "u.conf"))
	if err != nil {
		t.Fatal(err, out)
	}
	mustContain(t, "unbound summary", out, "threads=4", "prefetch=yes")
}
