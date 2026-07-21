package kominfo

import "testing"

func TestNormalizeTargets(t *testing.T) {
	got := normalizeTargets([]string{"182.23.79.202", "139.255.196.202:53", "182.23.79.202:53"})
	if len(got) != 2 {
		t.Fatalf("%v", got)
	}
	if got[0] != "182.23.79.202:53" || got[1] != "139.255.196.202:53" {
		t.Fatalf("%v", got)
	}
}

func TestDefaultDisabled(t *testing.T) {
	m := New(nil, nil, nil)
	if m.Enabled() {
		t.Fatal("default must be disabled")
	}
	if len(m.Targets()) != 2 {
		t.Fatal(m.Targets())
	}
	m.SetEnabled(true)
	if !m.IsTargetIP("182.23.79.202") {
		t.Fatal("expected target")
	}
	if m.IsTargetIP("1.2.3.4") {
		t.Fatal("not a target")
	}
}

func TestSetTargets(t *testing.T) {
	m := New(nil, nil, nil)
	if err := m.SetTargets([]string{"10.0.0.9"}); err != nil {
		t.Fatal(err)
	}
	if got := m.Targets(); len(got) != 1 || got[0] != "10.0.0.9:53" {
		t.Fatalf("%v", got)
	}
	if err := m.SetTargets(nil); err != nil {
		t.Fatal(err)
	}
	if len(m.Targets()) != 2 {
		t.Fatalf("empty should restore defaults: %v", m.Targets())
	}
}
