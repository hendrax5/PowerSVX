package monitor

import "testing"

func TestRecordBulkQPS(t *testing.T) {
	c := New()
	c.RecordBulk("unbound_cache", 10)
	c.RecordBulk("unbound_recurse", 5)
	c.RecordPathOnly("rpz", 3)
	snap := c.Snapshot(nil, nil)
	if snap.QueriesTotal != 15 {
		t.Fatalf("queries=%d", snap.QueriesTotal)
	}
	var seriesSum float64
	for _, p := range snap.QPSSeries {
		seriesSum += p.QPS
	}
	if seriesSum < 1 {
		t.Fatalf("expected qps series to include bulk samples, series=%v", snap.QPSSeries)
	}
	if snap.BlockedTotal != 3 {
		t.Fatalf("blocked=%d paths=%v", snap.BlockedTotal, snap.Paths)
	}
}
