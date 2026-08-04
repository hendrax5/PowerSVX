package conntrack

import "testing"

func TestNormalize(t *testing.T) {
	cfg, err := Normalize(Config{Managed: true, Max: 0})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Max != DefaultMax {
		t.Fatalf("default max: %d", cfg.Max)
	}
	if cfg.Hashsize != DefaultMax/4 {
		t.Fatalf("auto hash: %d", cfg.Hashsize)
	}
	if _, err := Normalize(Config{Max: 1000}); err == nil {
		t.Fatal("expected min error")
	}
	if _, err := Normalize(Config{Max: MaxMax + 1}); err == nil {
		t.Fatal("expected max error")
	}
	if _, err := Normalize(Config{Max: 100000, Hashsize: 200000}); err == nil {
		t.Fatal("expected hashsize > max error")
	}
}

func TestSuggestHashsize(t *testing.T) {
	if SuggestHashsize(2_000_000) != 500_000 {
		t.Fatalf("got %d", SuggestHashsize(2_000_000))
	}
	if SuggestHashsize(1000) < 16384 {
		t.Fatal("floor")
	}
}

func TestGetStatusNonLinuxOrMissing(t *testing.T) {
	st := GetStatus(Config{})
	if !Supported() {
		if st.Supported {
			t.Fatal("expected unsupported")
		}
		return
	}
	// On Linux CI without conntrack, Available may be false — just ensure no panic.
	_ = st
}
