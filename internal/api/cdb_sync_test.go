package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/rpz"
	"github.com/powersvx/powersvx/internal/server"
)

func TestMultiPolicyCachePreservesUnchangedAXFRAndHostsFeeds(t *testing.T) {
	dir := t.TempDir()
	hostsFile := filepath.Join(dir, "local-hosts.txt")
	if err := os.WriteFile(hostsFile, []byte("0.0.0.0 custom-ad.example\n"), 0644); err != nil {
		t.Fatal(err)
	}

	axfrPol := rpz.PolicyConfig{
		Name:   "trustpositifkominfo",
		Format: "axfr",
		Zone:   "trustpositifkominfo.",
	}
	hostsPol := rpz.PolicyConfig{
		Name:   "custom-hosts",
		Format: "hosts",
		Source: hostsFile,
	}

	// Pre-populate per-policy cache file for AXFR policy (simulates SOA unchanged skip on refresh).
	axfrCache := rpzFeedCachePath(dir, axfrPol)
	if err := os.MkdirAll(filepath.Dir(axfrCache), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(axfrCache, []byte("blocked-gambling.example\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Simulate partial update affecting only custom-hosts.
	hostsCache := rpzFeedCachePath(dir, hostsPol)
	if err := streamHostsFileToFeedFile(hostsFile, hostsCache); err != nil {
		t.Fatal(err)
	}

	outPath := filepath.Join(dir, "merged.txt")
	n, err := mergeFeedFiles([]string{axfrCache, hostsCache}, outPath)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("merged entries=%d want 2", n)
	}
	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if !strings.Contains(s, "blocked-gambling.example") || !strings.Contains(s, "custom-ad.example") {
		t.Fatalf("merged output missing expected domain: %s", s)
	}

	// Apply an incremental IXFR update on the AXFR policy without touching hostsCache.
	if err := applyIXFRToFeedFile(axfrCache, []string{"added-malware.example"}, []string{"blocked-gambling.example"}); err != nil {
		t.Fatal(err)
	}
	n2, err := mergeFeedFiles([]string{axfrCache, hostsCache}, outPath)
	if err != nil {
		t.Fatal(err)
	}
	if n2 != 2 {
		t.Fatalf("merged after IXFR entries=%d want 2", n2)
	}
	raw2, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	s2 := string(raw2)
	if strings.Contains(s2, "blocked-gambling.example") || !strings.Contains(s2, "added-malware.example") || !strings.Contains(s2, "custom-ad.example") {
		t.Fatalf("unexpected merged state after IXFR: %s", s2)
	}
}

func TestHandleRPZNotifyMasterAuthorization(t *testing.T) {
	cfg := &config.Config{
		RPZ: config.RPZConfig{
			Enabled: true,
			Policies: []config.RPZPolicyTOML{
				{
					Name:    "kominfo",
					Format:  "axfr",
					Zone:    "trustpositifkominfo.",
					Masters: []string{"192.0.2.50:53"},
				},
			},
		},
	}
	a := &API{cfg: cfg, srv: &server.Server{}}
	if !notifyMasterMatch([]string{"192.0.2.50:53"}, "192.0.2.50") {
		t.Fatal("expected exact master IP to match")
	}
	if notifyMasterMatch([]string{"192.0.2.50:53"}, "198.51.100.7") {
		t.Fatal("unexpected IP match")
	}
	// Unauthorized source without TSIG must be refused (false).
	if a.HandleRPZNotify("trustpositifkominfo.", "198.51.100.7", false) {
		t.Fatal("unauthorized NOTIFY must be refused")
	}
}
