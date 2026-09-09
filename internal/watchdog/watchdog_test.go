package watchdog

import "testing"

func TestParseGoMemLimit(t *testing.T) {
	if parseGoMemLimit("4294967296B") != 4294967296 {
		t.Fatal(parseGoMemLimit("4294967296B"))
	}
	if parseGoMemLimit("4GiB") != 4<<30 {
		t.Fatal(parseGoMemLimit("4GiB"))
	}
	if parseGoMemLimit("") != 0 {
		t.Fatal("empty")
	}
}
