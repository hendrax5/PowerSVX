package anomaly

import "testing"

func TestDetectorWarmNoAlert(t *testing.T) {
	d := New(10)
	for i := 0; i < 5; i++ {
		d.Observe("NOERROR")
	}
	snap := d.Snapshot()
	alerts, _ := snap["alerts"].([]Alert)
	if len(alerts) != 0 {
		t.Fatalf("unexpected alerts: %+v", alerts)
	}
}
