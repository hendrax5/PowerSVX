package config

import (
	"os"
	"testing"
)

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
	if goMemLimitMB() != 0 {
		t.Fatalf("unset want 0 got %d", goMemLimitMB())
	}
}

func TestRSSDegradeThresholdMB(t *testing.T) {
	t.Setenv("GOMEMLIMIT", "")
	if RSSDegradeThresholdMB() != 4096 {
		t.Fatalf("fallback got %v", RSSDegradeThresholdMB())
	}
	t.Setenv("GOMEMLIMIT", "4GiB")
	got := RSSDegradeThresholdMB()
	want := float64(4096) * 0.95
	if got != want {
		t.Fatalf("got %v want %v", got, want)
	}
}
