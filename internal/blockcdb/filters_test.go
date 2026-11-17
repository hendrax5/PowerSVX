package blockcdb

import (
	"path/filepath"
	"testing"
)

func TestSyncWhitelistBlacklistAndAuthZones(t *testing.T) {
	dir := t.TempDir()

	wn, err := SyncWhitelist(dir, []string{"trusted.partner.id."})
	if err != nil {
		t.Fatalf("SyncWhitelist failed: %v", err)
	}
	if wn < 1 {
		t.Fatalf("expected merged whitelist count >= 1, got %d", wn)
	}
	if rule, ok, err := LookupCDBSuffix(filepath.Join(Dir(dir), WhitelistCDBFile), "api.trusted.partner.id"); err != nil || !ok || rule != "trusted.partner.id" {
		t.Fatalf("expected custom whitelist hit, got rule=%q ok=%v err=%v", rule, ok, err)
	}

	bn, err := SyncCustomBlacklist(dir, []string{"*.phish.bad"})
	if err != nil {
		t.Fatalf("SyncCustomBlacklist failed: %v", err)
	}
	if bn != 1 {
		t.Fatalf("expected 1 custom blacklist entry, got %d", bn)
	}
	if rule, ok, err := LookupCDBSuffix(filepath.Join(Dir(dir), CustomBlackCDBFile), "login.phish.bad"); err != nil || !ok || rule != "phish.bad" {
		t.Fatalf("expected custom blacklist suffix hit, got rule=%q ok=%v err=%v", rule, ok, err)
	}

	an, err := SyncAuthZones(dir, []string{"isp-customer.co.id."})
	if err != nil {
		t.Fatalf("SyncAuthZones failed: %v", err)
	}
	if an != 1 {
		t.Fatalf("expected 1 auth zone entry, got %d", an)
	}
	if rule, ok, err := LookupCDBSuffix(filepath.Join(Dir(dir), AuthZonesCDBFile), "www.isp-customer.co.id"); err != nil || !ok || rule != "isp-customer.co.id" {
		t.Fatalf("expected auth zone hit, got rule=%q ok=%v err=%v", rule, ok, err)
	}
}
