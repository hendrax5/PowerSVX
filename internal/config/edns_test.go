package config

import "testing"

func TestNormalizeEDNSBufferSize(t *testing.T) {
	cases := []struct {
		in, want uint16
	}{
		{0, 1232},
		{512, 1232},
		{1232, 1232},
		{1472, 1472},
		{4096, 4096},
		{8192, 4096},
	}
	for _, tc := range cases {
		if got := NormalizeEDNSBufferSize(tc.in); got != tc.want {
			t.Fatalf("NormalizeEDNSBufferSize(%d)=%d want %d", tc.in, got, tc.want)
		}
	}
}

func TestLoadNormalizesEDNSBuffer(t *testing.T) {
	cfg := Default()
	cfg.Resolver.EDNSBufferSize = 512
	normalizeResolverBuffers(cfg)
	if cfg.Resolver.EDNSBufferSize != 1232 {
		t.Fatalf("got %d", cfg.Resolver.EDNSBufferSize)
	}
}
