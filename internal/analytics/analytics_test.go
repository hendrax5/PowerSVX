package analytics

import "testing"

func TestSnapshotTop(t *testing.T) {
	c := New(50)
	c.Observe("a.example.", "NOERROR")
	c.Observe("a.example.", "NOERROR")
	c.Observe("b.example.", "NXDOMAIN")
	names, rcodes := c.Snapshot(10)
	if len(names) != 2 || names[0].Name != "a.example" || names[0].Count != 2 {
		t.Fatalf("names=%v", names)
	}
	if len(rcodes) != 2 {
		t.Fatalf("rcodes=%v", rcodes)
	}
}
