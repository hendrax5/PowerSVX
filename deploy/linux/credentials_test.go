package linux_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const (
	envPass = "POWERSVX_DNSDIST_WEB_PASSWORD"
	envKey  = "POWERSVX_DNSDIST_API_KEY"
	optIn   = "POWERSVX_ALLOW_DEFAULT_DNSDIST_CREDENTIALS"
)

// genWith runs the dnsdist generator with exactly the given credential variables: the
// harness opt-in and anything the host environment sets are cleared first.
func genWith(t *testing.T, vars ...string) (stdout string, conf string, err error) {
	t.Helper()
	root := node(t)
	out := filepath.Join(root, "dnsdist.conf")
	env := append([]string{envPass + "=", envKey + "=", optIn + "="}, vars...)
	env = append(env, "POWERSVX_HOST_CPUS=2", "POWERSVX_HOST_MEM_MB=2048", "POWERSVX_DNSDIST_IPV6=0")
	stdout, err = sh(t, root, env, "gen-dnsdist-conf.sh", out)
	b, _ := os.ReadFile(out)
	return stdout, string(b), err
}

func TestGeneratorRefusesBuiltInWebCredentials(t *testing.T) {
	cases := []struct {
		name       string
		vars       []string
		wantFail   bool
		wantLine   string // expected setWebserverConfig line when it succeeds
		wantInFail string
	}{
		{name: "nothing set", wantFail: true, wantInFail: "must both be set"},
		{name: "only the password", vars: []string{envPass + "=pw-only-1"}, wantFail: true, wantInFail: "must both be set"},
		{name: "only the key", vars: []string{envKey + "=key-only-1"}, wantFail: true, wantInFail: "must both be set"},
		{name: "opt-in other than 1 does not count", vars: []string{optIn + "=yes"}, wantFail: true, wantInFail: "must both be set"},
		{
			name:     "explicit values are used verbatim",
			vars:     []string{envPass + "=pw-Verbatim-9", envKey + "=key-Verbatim-9"},
			wantLine: `setWebserverConfig({password="pw-Verbatim-9", apiKey="key-Verbatim-9", acl="127.0.0.1"})`,
		},
		{
			name:     "opt-in uses the development values",
			vars:     []string{optIn + "=1"},
			wantLine: `setWebserverConfig({password="powersvx", apiKey="powersvx-api", acl="127.0.0.1"})`,
		},
		{
			name:     "opt-in does not override an explicit value",
			vars:     []string{optIn + "=1", envPass + "=pw-Explicit-3"},
			wantLine: `setWebserverConfig({password="pw-Explicit-3", apiKey="powersvx-api", acl="127.0.0.1"})`,
		},
		{name: "a double quote is refused", vars: []string{envPass + `=a"b`, envKey + "=key-ok-1"}, wantFail: true, wantInFail: "must not contain"},
		{name: "a backslash is refused", vars: []string{envPass + "=pw-ok-1", envKey + `=a\b`}, wantFail: true, wantInFail: "must not contain"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, conf, err := genWith(t, c.vars...)
			if c.wantFail {
				if err == nil {
					t.Fatalf("expected the generator to fail, output:\n%s", out)
				}
				mustContain(t, "error message", out, c.wantInFail)
				if conf != "" {
					t.Errorf("a configuration was written despite the failure")
				}
			} else {
				if err != nil {
					t.Fatalf("generator failed: %v\n%s", err, out)
				}
				mustContain(t, "dnsdist.conf", conf, c.wantLine+"\n")
			}
			// The values never appear in what the script prints (summary line, warnings, errors).
			for _, v := range c.vars {
				if k, val, ok := strings.Cut(v, "="); ok && k != optIn && val != "" && strings.Contains(out, val) {
					t.Errorf("output echoes the value of %s", k)
				}
			}
			for _, fixed := range []string{"powersvx-api", `"powersvx"`} {
				if strings.Contains(out, fixed) {
					t.Errorf("output prints a built-in default %q:\n%s", fixed, out)
				}
			}
		})
	}
}

func TestGeneratedConfigHeaderCarriesNoCredentials(t *testing.T) {
	_, conf, err := genWith(t, envPass+"=pw-Header-5", envKey+"=key-Header-5")
	if err != nil {
		t.Fatal(err)
	}
	head := strings.SplitN(conf, "\n\n", 2)[0]
	if strings.Contains(head, "pw-Header-5") || strings.Contains(head, "key-Header-5") {
		t.Errorf("the configuration header carries a credential:\n%s", head)
	}
}

// ensure runs deploy/linux/ensure-dnsdist-credentials.sh on a file in a scratch directory.
func ensure(t *testing.T, root, file string) string {
	t.Helper()
	out, err := sh(t, root, nil, "ensure-dnsdist-credentials.sh", file)
	if err != nil {
		t.Fatalf("ensure-dnsdist-credentials.sh: %v\n%s", err, out)
	}
	return out
}

func envValues(t *testing.T, file string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for _, l := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			m[k] = v
		}
	}
	return m
}

func checkRandom(t *testing.T, name, v string) {
	t.Helper()
	if len(v) < 32 || strings.Trim(v, "0123456789abcdef") != "" {
		t.Errorf("%s is not a long random hex value (len %d)", name, len(v))
	}
}

func checkMode600(t *testing.T, file string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	st, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("%s has mode %v, want 0600", file, st.Mode().Perm())
	}
}

func TestEnsureCreatesMissingCredentials(t *testing.T) {
	root := node(t)
	file := filepath.Join(root, ".env")
	// No trailing newline, and group-readable: the helper must cope and tighten the mode.
	if err := os.WriteFile(file, []byte("PG_PASSWORD=keepme\nAPI_TOKEN=keepme-too"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := ensure(t, root, file)
	got := envValues(t, file)
	checkRandom(t, envPass, got[envPass])
	checkRandom(t, envKey, got[envKey])
	if got["PG_PASSWORD"] != "keepme" || got["API_TOKEN"] != "keepme-too" {
		t.Errorf("existing entries changed: %v", got)
	}
	checkMode600(t, file)
	for _, v := range []string{got[envPass], got[envKey]} {
		if strings.Contains(out, v) {
			t.Errorf("the helper printed a value")
		}
	}
	mustContain(t, "output", out, "created "+envPass, "created "+envKey)
}

func TestEnsureCreatesTheFileWhenAbsent(t *testing.T) {
	root := node(t)
	file := filepath.Join(root, ".env")
	ensure(t, root, file)
	got := envValues(t, file)
	checkRandom(t, envPass, got[envPass])
	checkRandom(t, envKey, got[envKey])
	if got[envPass] == got[envKey] {
		t.Error("password and key are equal")
	}
	checkMode600(t, file)
}

func TestEnsureLeavesPresentValuesAlone(t *testing.T) {
	root := node(t)
	file := filepath.Join(root, ".env")
	want := envPass + "=already-here\n" + envKey + "=already-there\nOTHER=1\n"
	if err := os.WriteFile(file, []byte(want), 0o600); err != nil {
		t.Fatal(err)
	}
	out := ensure(t, root, file)
	b, _ := os.ReadFile(file)
	if string(b) != want {
		t.Errorf("file changed:\n%s", b)
	}
	if strings.Contains(out, "already-") || strings.Contains(out, "created") {
		t.Errorf("unexpected output: %s", out)
	}
}

func TestEnsureFillsOnlyWhatIsMissing(t *testing.T) {
	root := node(t)
	file := filepath.Join(root, ".env")
	// The password is kept; the key is present but empty, so it is replaced (not duplicated).
	if err := os.WriteFile(file, []byte(envPass+"=keep-this-one\n"+envKey+"=\nOTHER=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ensure(t, root, file)
	got := envValues(t, file)
	if got[envPass] != "keep-this-one" || got["OTHER"] != "1" {
		t.Errorf("existing entries changed: %v", got)
	}
	checkRandom(t, envKey, got[envKey])
	b, _ := os.ReadFile(file)
	if n := strings.Count(string(b), envKey+"="); n != 1 {
		t.Errorf("%s appears %d times", envKey, n)
	}
}

// What apply-update.sh does on a node whose .env lacks the values: create them, then generate
// the dnsdist configuration from the same file. Both sides must end up with the same values.
func TestEnsureThenGenerateAgree(t *testing.T) {
	root := node(t)
	file := filepath.Join(root, ".env")
	ensure(t, root, file)
	got := envValues(t, file)
	env := []string{envPass + "=" + got[envPass], envKey + "=" + got[envKey], optIn + "=", "POWERSVX_HOST_CPUS=2", "POWERSVX_HOST_MEM_MB=2048", "POWERSVX_DNSDIST_IPV6=0"}
	out, err := sh(t, root, env, "gen-dnsdist-conf.sh", filepath.Join(root, "dnsdist.conf"))
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	conf, _ := os.ReadFile(filepath.Join(root, "dnsdist.conf"))
	mustContain(t, "dnsdist.conf", string(conf), `password="`+got[envPass]+`", apiKey="`+got[envKey]+`"`)
}

// The safety from the PROXY protocol update stays: the credentials are created before the new
// configuration is generated, and the Control Plane is recreated before that configuration is
// moved into place and dnsdist is recreated.
func TestApplyUpdateOrdersCredentialsControlPlaneThenDnsdist(t *testing.T) {
	b, err := os.ReadFile("apply-update.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	at := func(needle string) int {
		i := strings.Index(s, needle)
		if i < 0 {
			t.Fatalf("apply-update.sh lacks %q", needle)
		}
		return i
	}
	ensureAt := at("ensure-dnsdist-credentials.sh")
	genAt := at(`gen-dnsdist-conf.sh" "$ROOT/configs/dnsdist/dnsdist.conf.new"`)
	cpAt := at("--force-recreate powersvx\n")
	mvAt := at(`mv -f "$ROOT/configs/dnsdist/dnsdist.conf.new"`)
	dnsdistAt := at("--force-recreate unbound dnsdist")
	if !(ensureAt < genAt && genAt < cpAt && cpAt < mvAt && mvAt < dnsdistAt) {
		t.Errorf("wrong order: ensure=%d generate=%d control-plane=%d move=%d dnsdist=%d", ensureAt, genAt, cpAt, mvAt, dnsdistAt)
	}
}
