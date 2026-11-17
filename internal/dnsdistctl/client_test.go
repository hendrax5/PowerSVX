package dnsdistctl

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseShowDynBlocks(t *testing.T) {
	sample := `
What                      Seconds    Blocks Warning  Action               Reason
192.0.2.44/32             45         1230   true     Drop                 Exceeded query rate
2001:db8::1/128           10         99     false    Truncate (TC=1)      NXDOMAIN flood
`
	got := ParseShowDynBlocks(sample)
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d (%#v)", len(got), got)
	}
	if got[0].Prefix != "192.0.2.44/32" || got[0].Seconds != 45 || got[0].Blocks != 1230 {
		t.Fatalf("unexpected first entry: %#v", got[0])
	}
	if got[1].Prefix != "2001:db8::1/128" {
		t.Fatalf("unexpected second entry: %#v", got[1])
	}
}

func TestParseGrepQ(t *testing.T) {
	sample := `
Time     Client         ID    Name                    Type  Lat.  TC RD AA RCode
-0.2     10.10.1.5:53412 1234  api.example.com.        A     0.4   RD No Error
`
	got := ParseGrepQ(sample)
	if len(got) != 1 {
		t.Fatalf("expected 1 query sample, got %d", len(got))
	}
	if got[0].QName != "api.example.com" || got[0].QType != "A" || got[0].Client != "10.10.1.5:53412" {
		t.Fatalf("unexpected sample: %#v", got[0])
	}
}

func TestWriteManualBans(t *testing.T) {
	dir := t.TempDir()
	err := WriteManualBans(dir, []string{"198.51.100.7", "203.0.113.0/24", "invalid\nbad"})
	if err != nil {
		t.Fatalf("WriteManualBans failed: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "bans.txt"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, "198.51.100.7/32") || !strings.Contains(s, "203.0.113.0/24") {
		t.Fatalf("missing valid CIDRs in bans.txt:\n%s", s)
	}
	if strings.Contains(s, "invalid") {
		t.Fatalf("invalid line leaked into bans.txt:\n%s", s)
	}
}
