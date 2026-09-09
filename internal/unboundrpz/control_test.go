package unboundrpz

import "testing"

func TestControlCommandEmpty(t *testing.T) {
	if _, err := ControlCommand(""); err == nil {
		t.Fatal("expected error for empty command")
	}
}
