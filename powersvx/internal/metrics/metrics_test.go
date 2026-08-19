package metrics

import (
	"testing"
	"time"
)

func TestHistogramQuantileInterpolates(t *testing.T) {
	h := newHistogram()
	// 1000 observations uniformly at 3ms, which falls in bucket (0.0025, 0.005].
	for i := 0; i < 1000; i++ {
		h.Observe(3 * time.Millisecond)
	}
	p50 := h.Quantile(0.50)
	if p50 <= 0.0025 || p50 > 0.005 {
		t.Errorf("p50 should interpolate within (0.0025,0.005], got %g", p50)
	}
	// Interpolation should NOT just return the bucket edge for a partial fill.
	if p50 == 0.005 {
		t.Errorf("expected an interpolated value, got the bucket upper edge")
	}
}

func TestHistogramQuantileSpread(t *testing.T) {
	h := newHistogram()
	for i := 0; i < 90; i++ {
		h.Observe(1 * time.Millisecond) // bucket <=0.001
	}
	for i := 0; i < 10; i++ {
		h.Observe(200 * time.Millisecond) // tail, bucket <=0.25
	}
	p50 := h.Quantile(0.50)
	p99 := h.Quantile(0.99)
	if p50 > 0.001 {
		t.Errorf("p50 should sit in the fast bucket, got %g", p50)
	}
	if p99 <= 0.1 {
		t.Errorf("p99 should reflect the slow tail, got %g", p99)
	}
}

func TestHistogramEmpty(t *testing.T) {
	h := newHistogram()
	if h.Quantile(0.99) != 0 {
		t.Error("empty histogram quantile should be 0")
	}
}
