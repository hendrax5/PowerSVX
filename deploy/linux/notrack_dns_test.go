package linux_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const (
	oldPre  = "PREROUTING -p udp --dport 53 -j NOTRACK"
	newPre  = "PREROUTING -p udp -m addrtype --dst-type LOCAL --dport 53 -j NOTRACK"
	outRule = "OUTPUT -p udp --sport 53 -j NOTRACK"
	other   = "PREROUTING -p tcp --dport 853 -j NOTRACK"
)

// fakeIptables keeps the raw table in $STATE, one rule per line, and compares
// rules as whole strings the way `iptables -C` and `-D` do.
const fakeIptables = `#!/bin/sh
[ "$1" = "-t" ] && [ "$2" = "raw" ] || exit 2
shift 2
op="$1"; shift
rule="$*"
touch "$STATE"
case "$op" in
  -C) grep -qxF -- "$rule" "$STATE" ;;
  -A) printf '%s\n' "$rule" >> "$STATE" ;;
  -D) n=$(grep -nxF -- "$rule" "$STATE" | head -n1 | cut -d: -f1)
      [ -n "$n" ] || exit 1
      sed -i "${n}d" "$STATE" ;;
  *) exit 2 ;;
esac
`

// runNotrack runs notrack-dns.sh against a fake raw table preloaded with rules.
func runNotrack(t *testing.T, rules []string, saved string, runs int) ([]string, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell")
	}
	src, err := os.ReadFile("notrack-dns.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "notrack-dns.sh")
	if err := os.WriteFile(script, src, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"sh", "bash", "grep", "sed", "cat", "cut", "head", "seq", "mktemp", "rm", "touch", "dirname"} {
		if p, err := exec.LookPath(tool); err == nil {
			_ = os.Symlink(p, filepath.Join(bin, tool))
		}
	}
	if err := os.WriteFile(filepath.Join(bin, "iptables"), []byte(fakeIptables), 0o755); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "state")
	if len(rules) > 0 {
		if err := os.WriteFile(state, []byte(strings.Join(rules, "\n")+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	v4 := filepath.Join(dir, "rules.v4")
	if saved != "" {
		if err := os.WriteFile(v4, []byte(saved), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < runs; i++ {
		cmd := exec.Command(filepath.Join(bin, "bash"), script)
		cmd.Env = []string{"PATH=" + bin, "STATE=" + state, "POWERSVX_IPTABLES_RULES_V4=" + v4}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("run %d: %v\n%s", i, err, out)
		}
	}
	var got []string
	if b, err := os.ReadFile(state); err == nil {
		got = strings.Split(strings.TrimSpace(string(b)), "\n")
	}
	savedOut := ""
	if b, err := os.ReadFile(v4); err == nil {
		savedOut = string(b)
	}
	return got, savedOut
}

func same(a, b []string) bool {
	return strings.Join(a, "|") == strings.Join(b, "|")
}

func TestNotrackFreshNodeGetsOnlyTheNarrowRule(t *testing.T) {
	got, _ := runNotrack(t, nil, "", 1)
	if want := []string{newPre, outRule}; !same(got, want) {
		t.Fatalf("rules = %q, want %q", got, want)
	}
}

func TestNotrackMigratesTheBroadRuleAndKeepsOthers(t *testing.T) {
	got, _ := runNotrack(t, []string{other, oldPre, outRule}, "", 1)
	if want := []string{other, outRule, newPre}; !same(got, want) {
		t.Fatalf("rules = %q, want %q", got, want)
	}
}

func TestNotrackRemovesDuplicateBroadRules(t *testing.T) {
	got, _ := runNotrack(t, []string{oldPre, oldPre, outRule}, "", 1)
	if want := []string{outRule, newPre}; !same(got, want) {
		t.Fatalf("rules = %q, want %q", got, want)
	}
}

func TestNotrackIsIdempotent(t *testing.T) {
	once, _ := runNotrack(t, []string{oldPre, outRule}, "", 1)
	twice, _ := runNotrack(t, []string{oldPre, outRule}, "", 2)
	thrice, _ := runNotrack(t, nil, "", 3)
	if !same(once, twice) {
		t.Fatalf("second run changed the rules: %q then %q", once, twice)
	}
	if want := []string{newPre, outRule}; !same(thrice, want) {
		t.Fatalf("fresh node after three runs = %q, want %q", thrice, want)
	}
}

func TestNotrackMigratesTheSavedRuleset(t *testing.T) {
	saved := "*raw\n:PREROUTING ACCEPT [0:0]\n-A PREROUTING -p udp -m udp --dport 53 -j NOTRACK\n-A PREROUTING -p tcp -m tcp --dport 853 -j NOTRACK\n-A OUTPUT -p udp -m udp --sport 53 -j NOTRACK\nCOMMIT\n"
	_, got := runNotrack(t, nil, saved, 2)
	want := "*raw\n:PREROUTING ACCEPT [0:0]\n-A PREROUTING -p udp -m addrtype --dst-type LOCAL -m udp --dport 53 -j NOTRACK\n-A PREROUTING -p tcp -m tcp --dport 853 -j NOTRACK\n-A OUTPUT -p udp -m udp --sport 53 -j NOTRACK\nCOMMIT\n"
	if got != want {
		t.Fatalf("saved ruleset =\n%s\nwant\n%s", got, want)
	}
}

func TestCheckNotrackReportsTheBroadRule(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell")
	}
	for _, c := range []struct {
		rules []string
		code  int
		say   string
	}{
		{[]string{oldPre, outRule}, 1, "FAIL broad rule present"},
		{[]string{newPre, outRule}, 0, "OK   no broad"},
	} {
		dir := t.TempDir()
		bin := filepath.Join(dir, "bin")
		_ = os.Mkdir(bin, 0o755)
		for _, tool := range []string{"sh", "bash", "grep", "touch"} {
			if p, err := exec.LookPath(tool); err == nil {
				_ = os.Symlink(p, filepath.Join(bin, tool))
			}
		}
		_ = os.WriteFile(filepath.Join(bin, "iptables"), []byte(fakeIptables), 0o755)
		state := filepath.Join(dir, "state")
		_ = os.WriteFile(state, []byte(strings.Join(c.rules, "\n")+"\n"), 0o644)
		cmd := exec.Command(filepath.Join(bin, "bash"), "check-notrack.sh")
		cmd.Env = []string{"PATH=" + bin, "STATE=" + state}
		out, err := cmd.CombinedOutput()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
		if code != c.code || !strings.Contains(string(out), c.say) {
			t.Fatalf("rules %q: exit %d, output %q; want exit %d with %q", c.rules, code, out, c.code, c.say)
		}
	}
}
