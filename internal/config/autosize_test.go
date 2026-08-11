package config

import (
	"os"
	"testing"
)

func TestAutosizeZeroMeansDerive(t *testing.T) {
	t.Setenv("GOMEMLIMIT", "")
	cfg := Default()
	cfg.Cache.MaxSizeMB = 0
	cfg.Resolver.MaxInflight = 0
	cacheMB, inflight, memMB, cpus := cfg.Autosize()
	if cacheMB < 256 || cacheMB > 16384 {
		t.Fatalf("cacheMB=%d memMB=%d", cacheMB, memMB)
	}
	if inflight < 1024 || inflight > 16384 {
		t.Fatalf("inflight=%d cpus=%d", inflight, cpus)
	}
	if cfg.Cache.MaxSizeMB != cacheMB || cfg.Resolver.MaxInflight != inflight {
		t.Fatal("cfg not updated")
	}
}

func TestAutosizeRespectsExplicit(t *testing.T) {
	cfg := Default()
	cfg.Cache.MaxSizeMB = 777
	cfg.Resolver.MaxInflight = 3333
	cacheMB, inflight, _, _ := cfg.Autosize()
	if cacheMB != 777 || inflight != 3333 {
		t.Fatalf("got cache=%d inflight=%d", cacheMB, inflight)
	}
}

func TestGoMemLimitMB(t *testing.T) {
	t.Setenv("GOMEMLIMIT", "2147483648B")
	if goMemLimitMB() != 2048 {
		t.Fatalf("got %d", goMemLimitMB())
	}
	t.Setenv("GOMEMLIMIT", "2GiB")
	if goMemLimitMB() != 2048 {
		t.Fatalf("got %d", goMemLimitMB())
	}
	_ = os.Unsetenv("GOMEMLIMIT")
}
