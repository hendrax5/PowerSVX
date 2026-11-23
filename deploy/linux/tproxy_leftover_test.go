package linux_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// leftover copies tproxy-leftover.sh into a temp directory and runs it with a
// fake nft and ip first on the PATH. A nil fake means the tool is not installed.
func leftover(t *testing.T, nft, ip *string) (string, int) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell")
	}
	src, err := os.ReadFile("tproxy-leftover.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "tproxy-leftover.sh")
	if err := os.WriteFile(script, src, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	// Tools the script needs besides nft and ip, linked from the real system.
	for _, tool := range []string{"sh", "grep", "id"} {
		p, err := exec.LookPath(tool)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(p, filepath.Join(bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]*string{"nft": nft, "ip": ip} {
		if body == nil {
			continue
		}
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+*body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(filepath.Join(bin, "sh"), script)
	cmd.Env = []string{"PATH=" + bin, "POWERSVX_PRIV="}
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return string(out), code
}

func str(s string) *string { return &s }

// nftHasTable answers `nft list table inet powersvx_tproxy` like a node that has it.
const nftHasTable = `[ "$*" = "list table inet powersvx_tproxy" ] && { echo "table inet powersvx_tproxy {}"; exit 0; }; exit 1`

// ipLeftover prints what the old intercept left: a fwmark rule and the local route.
const ipLeftover = `case "$*" in
  *"rule show"*) echo "0:	from all lookup local"; echo "100:	from all fwmark 0x1 lookup 100" ;;
  *"route show table 100"*) echo "local default dev lo scope host" ;;
esac
exit 0`

// ipClean prints a normal host: no fwmark rule, nothing in table 100.
const ipClean = `case "$*" in
  *"rule show"*) echo "0:	from all lookup local"; echo "32766:	from all lookup main" ;;
esac
exit 0`

func TestLeftoverWarnsAboutTableAndRoute(t *testing.T) {
	out, code := leftover(t, str(nftHasTable), str(ipLeftover))
	if code != 0 {
		t.Fatalf("must never fail the update, exit %d: %s", code, out)
	}
	for _, want := range []string{"WARNING", "powersvx_tproxy", "fwmark", "table 100", "Nothing was removed", "docs/PRODUCTION.md"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q: %s", want, out)
		}
	}
}

func TestLeftoverWarnsAboutTableAlone(t *testing.T) {
	out, code := leftover(t, str(nftHasTable), str(ipClean))
	if code != 0 || !strings.Contains(out, "powersvx_tproxy") || strings.Contains(out, "fwmark rule") {
		t.Fatalf("exit %d: %s", code, out)
	}
}

func TestLeftoverWarnsAboutRouteAlone(t *testing.T) {
	out, code := leftover(t, str("exit 1"), str(ipLeftover))
	if code != 0 || !strings.Contains(out, "fwmark rule") || strings.Contains(out, "nftables table") {
		t.Fatalf("exit %d: %s", code, out)
	}
}

func TestLeftoverSilentWhenAbsent(t *testing.T) {
	out, code := leftover(t, str("exit 1"), str(ipClean))
	if code != 0 || out != "" {
		t.Fatalf("exit %d, want silence: %q", code, out)
	}
}

func TestLeftoverSurvivesMissingNft(t *testing.T) {
	out, code := leftover(t, nil, str(ipClean))
	if code != 0 || out != "" {
		t.Fatalf("no nft, clean host: exit %d, want silence: %q", code, out)
	}
	out, code = leftover(t, nil, str(ipLeftover))
	if code != 0 || !strings.Contains(out, "fwmark rule") {
		t.Fatalf("no nft, leftover route: exit %d: %s", code, out)
	}
}

func TestLeftoverSurvivesMissingNftAndIp(t *testing.T) {
	out, code := leftover(t, nil, nil)
	if code != 0 || out != "" {
		t.Fatalf("exit %d, want silence: %q", code, out)
	}
}

func TestLeftoverNeverRemovesAnything(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "mutated")
	nft := `case "$1" in list) exit 0 ;; *) echo "nft $*" >> ` + marker + `; exit 9 ;; esac`
	ip := `case "$*" in *"rule show"*|*"route show"*) echo "100:	from all fwmark 0x1 lookup 100" ;; *) echo "ip $*" >> ` + marker + `; exit 9 ;; esac`
	out, code := leftover(t, str(nft), str(ip))
	if code != 0 || !strings.Contains(out, "WARNING") {
		t.Fatalf("exit %d: %s", code, out)
	}
	if b, err := os.ReadFile(marker); err == nil {
		t.Fatalf("the script changed something: %s", b)
	}
}
