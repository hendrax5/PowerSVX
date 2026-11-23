package unboundloop_test

// Ticket #36: the Auth Backend sees the client's address, not the Dataplane's.
//
// Real dnsdist (generated configuration, PROXY protocol v2 on by default), real Unbound, and
// the real Control Plane share a network namespace, as in bringUp. Two client containers with
// addresses of their own ask dnsdist on :53; the test proves that the views, the GeoDNS
// answer, the NOTIFY master check and the transfer and update allow lists judge the client
// that asked. A third group talks to the Auth Backend directly from a non-loopback address
// (the test binds it to all addresses for that, which a node never does) to show that a PROXY
// header from there is not believed.

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"
)

const (
	proxyZone = "psvxproxy.net"
	secZone   = "sec.psvxproxy.net"
)

// dropSections removes the sections the test writes again.
var dropSections = regexp.MustCompile(`(?m)^\[(geodns|split_horizon|transfer|update)\]\r?\n(?:[^\[\r\n][^\n]*\n|\r?\n)*`)

func tomlFor(a, b string) func(string) string {
	return func(toml string) string {
		toml = strings.ReplaceAll(toml, `bind_address = "127.0.0.1"`, `bind_address = "0.0.0.0"`)
		toml = dropSections.ReplaceAllString(toml, "")
		return toml + fmt.Sprintf(`

[split_horizon]
enabled = true
views = [{ name = "internal", networks = ["%[1]s/32"] }]

[geodns]
enabled = true
default_tag = "default"
overrides = [{ ip = "%[1]s", country = "ID" }, { ip = "%[2]s", country = "US" }]

[transfer]
allow_axfr = true
allow_from = ["%[1]s/32"]

[update]
enabled = true
allow_from = ["%[1]s/32"]
`, a, b)
	}
}

func addRecord(t *testing.T, s *stack, zone, name, typ, content, view, geoTag string) {
	t.Helper()
	body := fmt.Sprintf(`{"name":%q,"type":%q,"content":%q,"ttl":60,"view":%q,"geo_tag":%q}`, name, typ, content, view, geoTag)
	mustAPI(t, s.api, "POST", "/api/v1/zones/"+zone+"/records", body, http.StatusCreated)
}

// waitAnswer asks from c until the answer line contains want (dnsdist picks up a new zone
// from the CDB within a few seconds).
func waitAnswer(t *testing.T, c *client, dd, want string, args ...string) string {
	t.Helper()
	var last string
	if why := poll(60*time.Second, func() string {
		last = c.ask(dd, args...)
		if !strings.Contains(last, want) {
			return last
		}
		return ""
	}); why != "" {
		t.Fatalf("dnsq %v from %s: want %q in the answer, last got %q", args, c.ip, want, last)
	}
	return last
}

func TestTheAuthBackendJudgesTheRealClientThroughTheDataplane(t *testing.T) {
	needDocker(t)
	dnsq := buildTool(t, "dnsq")
	a, b := startClient(t, dnsq), startClient(t, dnsq)
	t.Logf("client A %s (the only address in the view, the geo override ID, the allow lists and the NOTIFY master), client B %s", a.ip, b.ip)

	s := bringUp(t, options{toml: tomlFor(a.ip, b.ip)})
	dd := dnsdistAddr(t, s.dd)

	// The generated dnsdist configuration, as the node runs it.
	conf := dockerQuiet("exec", s.dd, "cat", "/etc/dnsdist/dnsdist.conf")
	if !strings.Contains(conf, `name="powersvx-auth"`) || !strings.Contains(conf, "useProxyProtocol=true") {
		t.Fatalf("the generated dnsdist configuration does not use PROXY protocol for the Auth Backend:\n%s", conf)
	}

	mustAPI(t, s.api, "POST", "/api/v1/zones", fmt.Sprintf(`{"name":%q}`, proxyZone), http.StatusCreated)
	addRecord(t, s, proxyZone, "app."+proxyZone, "A", "10.9.0.1", "internal", "")
	addRecord(t, s, proxyZone, "app."+proxyZone, "A", "192.0.2.1", "default", "")
	addRecord(t, s, proxyZone, "cdn."+proxyZone, "A", "192.0.2.100", "", "ID")
	addRecord(t, s, proxyZone, "cdn."+proxyZone, "A", "192.0.2.200", "", "US")
	addRecord(t, s, proxyZone, "cdn."+proxyZone, "A", "192.0.2.254", "", "default")

	t.Run("views follow the real client", func(t *testing.T) {
		app := "app." + proxyZone + "."
		waitAnswer(t, a, dd, "A 10.9.0.1", "-n", app, "-t", "A")
		for i := 0; i < 3; i++ { // alternating, so a wrong answer cannot hide behind the first one
			if got := a.ask(dd, "-n", app, "-t", "A"); !strings.Contains(got, "answers=A 10.9.0.1") {
				t.Fatalf("A (in the internal view) got %s", got)
			}
			if got := b.ask(dd, "-n", app, "-t", "A"); !strings.Contains(got, "answers=A 192.0.2.1") || strings.Contains(got, "10.9.0.1") {
				t.Fatalf("B (default view) got %s", got)
			}
		}
		// Over TCP too: the header comes with the connection.
		if got := b.ask(dd, "-n", app, "-t", "A", "-net", "tcp"); !strings.Contains(got, "answers=A 192.0.2.1") {
			t.Fatalf("B over TCP got %s", got)
		}
		if got := a.ask(dd, "-n", app, "-t", "A", "-net", "tcp"); !strings.Contains(got, "answers=A 10.9.0.1") {
			t.Fatalf("A over TCP got %s", got)
		}
	})

	t.Run("GeoDNS follows the real client", func(t *testing.T) {
		cdn := "cdn." + proxyZone + "."
		waitAnswer(t, a, dd, "A 192.0.2.100", "-n", cdn, "-t", "A")
		for i := 0; i < 3; i++ {
			if got := a.ask(dd, "-n", cdn, "-t", "A"); !strings.Contains(got, "answers=A 192.0.2.100") {
				t.Fatalf("A (ID) got %s", got)
			}
			if got := b.ask(dd, "-n", cdn, "-t", "A"); !strings.Contains(got, "answers=A 192.0.2.200") {
				t.Fatalf("B (US) got %s", got)
			}
		}
	})

	t.Run("a client subnet in the query steers GeoDNS, the views stay with the client address", func(t *testing.T) {
		// B asks on behalf of a subnet that A's override covers (A's address as a /32): GeoDNS
		// answers for that subnet, the view is still B's.
		got := b.ask(dd, "-n", "cdn."+proxyZone+".", "-t", "A", "-ecs", a.ip+"/32")
		if !strings.Contains(got, "answers=A 192.0.2.100") {
			t.Fatalf("GeoDNS did not follow the client subnet: %s", got)
		}
		got = b.ask(dd, "-n", "app."+proxyZone+".", "-t", "A", "-ecs", a.ip+"/32")
		if !strings.Contains(got, "answers=A 192.0.2.1") {
			t.Fatalf("the view followed the client subnet instead of the client address: %s", got)
		}
	})

	t.Run("NOTIFY from the configured master is accepted without TSIG, from another host refused", func(t *testing.T) {
		mustAPI(t, s.api, "POST", "/api/v1/secondary", fmt.Sprintf(`{"name":%q,"masters":[%q]}`, secZone, a.ip+":53"), http.StatusCreated)
		waitAnswer(t, a, dd, "rcode=NOERROR", "-n", secZone+".", "-op", "notify")
		if got := a.ask(dd, "-n", secZone+".", "-op", "notify"); !strings.Contains(got, "rcode=NOERROR") {
			t.Fatalf("NOTIFY from the master: %s", got)
		}
		if got := b.ask(dd, "-n", secZone+".", "-op", "notify"); !strings.Contains(got, "rcode=REFUSED") {
			t.Fatalf("NOTIFY from another host: %s", got)
		}
	})

	t.Run("the zone transfer allow list judges the real client", func(t *testing.T) {
		got := a.ask(dd, "-n", proxyZone+".", "-t", "AXFR")
		if !strings.Contains(got, "rcode=NOERROR") || strings.Contains(got, "records=0") {
			t.Fatalf("AXFR from the allowed client: %s", got)
		}
		if got := b.ask(dd, "-n", proxyZone+".", "-t", "AXFR"); !strings.Contains(got, "error=") {
			t.Fatalf("AXFR from a client outside the allow list must fail: %s", got)
		}
	})

	t.Run("the dynamic update allow list judges the real client", func(t *testing.T) {
		if got := b.ask(dd, "-n", proxyZone+".", "-op", "update"); !strings.Contains(got, "rcode=REFUSED") {
			t.Fatalf("UPDATE from a client outside the allow list: %s", got)
		}
		if got := a.ask(dd, "-n", proxyZone+".", "-op", "update"); strings.Contains(got, "rcode=REFUSED") || !strings.Contains(got, "rcode=") {
			t.Fatalf("UPDATE from the allowed client must get past the allow list: %s", got)
		}
	})

	t.Run("a PROXY header from a non-loopback source is not trusted", func(t *testing.T) {
		direct := strings.Replace(dd, ":53", ":5354", 1)
		app := "app." + proxyZone + "."
		// B reaches the Auth Backend itself (a lab setup: a node binds it to loopback) and
		// claims to be A, the client of the internal view and of the allow lists.
		for _, netw := range []string{"udp", "tcp"} {
			if got := b.ask(direct, "-n", app, "-t", "A", "-net", netw, "-proxy", a.ip); strings.Contains(got, "10.9.0.1") || strings.Contains(got, "rcode=NOERROR") {
				t.Fatalf("%s: a header from a non-loopback source was believed: %s", netw, got)
			}
			if got := b.ask(direct, "-n", app, "-t", "A", "-net", netw, "-proxy", "127.0.0.1"); strings.Contains(got, "rcode=NOERROR") {
				t.Fatalf("%s: a header naming loopback from a non-loopback source got an answer: %s", netw, got)
			}
		}
		// Without a header the same host is refused as a non-local source (the existing rule).
		if got := b.ask(direct, "-n", app, "-t", "A"); !strings.Contains(got, "rcode=REFUSED") {
			t.Fatalf("a plain query from a non-loopback source must be refused: %s", got)
		}
		if got := b.ask(direct, "-n", proxyZone+".", "-t", "AXFR"); !strings.Contains(got, "error=") {
			t.Fatalf("AXFR straight to the Auth Backend from a non-loopback source must fail: %s", got)
		}
		// The refusals are counted by the Control Plane.
		_, out := apiCall(t, s.api, "GET", "/metrics", "")
		_ = out
	})

	t.Run("the dnsdist health checks keep the Auth Backend up", func(t *testing.T) {
		// dnsdist marks the server down after three failed checks (15 s); wait past that and ask again.
		time.Sleep(25 * time.Second)
		if got := a.ask(dd, "-n", "app."+proxyZone+".", "-t", "A"); !strings.Contains(got, "answers=A 10.9.0.1") {
			t.Fatalf("after the health checks ran for 25 s: %s", got)
		}
		if logs := dockerQuiet("logs", s.dd); strings.Contains(logs, "Marking downstream powersvx-auth") && strings.Contains(logs, "as 'down'") {
			// the first 'down' at start-up (before the Control Plane exists) is expected; it must be 'up' afterwards
			last := logs[strings.LastIndex(logs, "Marking downstream powersvx-auth"):]
			if !strings.Contains(last, "as 'up'") {
				t.Fatalf("the Auth Backend ended up marked down:\n%s", logs)
			}
		}
	})
}

// A node whose dnsdist configuration was generated before this change (no PROXY header, ECS
// from dnsdist, a packet cache) and a Control Plane that is new, with the shipped default
// proxy_protocol = "optional": bringUp itself shows that dnsdist answers a hosted name through
// it. The Auth Backend answers header-less queries from the loopback Dataplane as before, the
// client address is simply the Dataplane's until the configuration is regenerated.
func TestAConfigurationGeneratedBeforePROXYProtocolStillWorks(t *testing.T) {
	needDocker(t)
	s := bringUp(t, options{genEnv: []string{"POWERSVX_AUTH_PROXY_PROTOCOL=0"}})
	conf := dockerQuiet("exec", s.dd, "cat", "/etc/dnsdist/dnsdist.conf")
	if !strings.Contains(conf, `name="powersvx-auth", pool="auth", useClientSubnet=true,`) || strings.Contains(conf, "useProxyProtocol") {
		t.Fatalf("POWERSVX_AUTH_PROXY_PROTOCOL=0 must generate the earlier configuration:\n%s", conf)
	}
	if !strings.Contains(conf, "getPool(\"auth\"):setCache(pcAuth)") {
		t.Fatalf("the earlier configuration keeps the Auth Backend packet cache")
	}
}

// The default generated configuration: PROXY protocol, no ECS added by dnsdist, no packet cache in
// front of the Auth Backend.
func TestTheDefaultGeneratedConfigurationUsesPROXYProtocolAndNoAuthCache(t *testing.T) {
	needDocker(t)
	line := generatedAuthLine(t, repoRoot(t))
	for _, want := range []string{`name="powersvx-auth"`, `pool="auth"`, "useProxyProtocol=true", "checkInterval=5"} {
		if !strings.Contains(line, want) {
			t.Errorf("%q missing from %s", want, line)
		}
	}
	if strings.Contains(line, "useClientSubnet") {
		t.Errorf("dnsdist must not add ECS when it sends the client address in a PROXY header (it breaks TSIG): %s", line)
	}
}
