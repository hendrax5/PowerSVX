package unboundlog

import "testing"

func TestParseQueryLine(t *testing.T) {
	cases := []struct {
		line       string
		ip, name, typ string
		ok         bool
	}{
		{"[1788544000] unbound[1:0] info: 103.172.70.91 google.com. A IN", "103.172.70.91", "google.com", "A", true},
		{"info: 1.2.3.4 example.com. AAAA IN", "1.2.3.4", "example.com", "AAAA", true},
		{"info: 1.2.3.4 example.com. A IN", "1.2.3.4", "example.com", "A", true},
		{"info: 1.2.3.4 example.com. A IN response: NOERROR", "", "", "", false},
		{"notice: start of service", "", "", "", false},
		{"info: not-an-ip example.com. A IN", "", "", "", false},
	}
	for _, c := range cases {
		ip, name, typ, ok := ParseQueryLine(c.line)
		if ok != c.ok || ip != c.ip || name != c.name || typ != c.typ {
			t.Fatalf("line=%q got (%q,%q,%q,%v) want (%q,%q,%q,%v)",
				c.line, ip, name, typ, ok, c.ip, c.name, c.typ, c.ok)
		}
	}
}
