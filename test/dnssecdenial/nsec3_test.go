package dnssecdenial_test

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/dnssec"
)

const base32hex = "0123456789ABCDEFGHIJKLMNOPQRSTUV"

// A name under the zone, not in it, whose NSEC3 hash ends in c (the signer
// hashes with one additional iteration).
func nameWithHashEndingIn(t *testing.T, salt string, c byte) string {
	t.Helper()
	for i := 0; i < 20000; i++ {
		n := fmt.Sprintf("n%d.example.com.", i)
		if h := dns.HashName(n, dns.SHA1, 1, salt); h != "" && h[len(h)-1] == c {
			return n
		}
	}
	t.Fatalf("no name with a hash ending in %c", c)
	return ""
}

// For several random salts: a positive answer, NODATA, an empty non-terminal and,
// over UDP, one missing name per final character of the base32hex hash, and a
// few over TCP, all authenticated by delv.
func TestValidatorAuthenticatesNSEC3DenialForRandomSaltsAndEveryHashEnding(t *testing.T) {
	if os.Getenv("POWERSVX_DOCKER_TESTS") != "1" {
		t.Skip("set POWERSVX_DOCKER_TESTS=1 to run the validator test (needs Docker)")
	}
	for s := 0; s < 3; s++ {
		raw := make([]byte, 1+s*3)
		if _, err := rand.Read(raw); err != nil {
			t.Fatal(err)
		}
		salt := hex.EncodeToString(raw)
		t.Run("salt-"+salt, func(t *testing.T) {
			signer, srv := buildZone(t, dnssec.SignOptions{Algorithm: dns.ECDSAP256SHA256, NSEC3: true, Salt: salt})
			port := listen(t, srv)
			container := startValidator(t, trustAnchor(t, signer))

			check := func(t *testing.T, tcp bool, name, qtype string, want ...string) {
				t.Helper()
				out := delv(t, container, port, tcp, name, qtype)
				for _, w := range want {
					if !strings.Contains(strings.ToLower(out), strings.ToLower(w)) {
						t.Errorf("delv %s %s (tcp=%v, salt %s, hash %s): lacks %q\n%s", name, qtype, tcp, salt, dns.HashName(name, dns.SHA1, 1, salt), w, out)
					}
				}
				for _, bad := range []string{"unsigned answer", "insecurity proof failed", "resolution failed: SERVFAIL", "resolution failed: timed out", "broken trust chain", "no valid signature"} {
					if strings.Contains(out, bad) {
						t.Errorf("delv %s %s (tcp=%v, salt %s): contains %q\n%s", name, qtype, tcp, salt, bad, out)
					}
				}
			}
			for _, tcp := range []bool{false, true} {
				check(t, tcp, "www.example.com.", "A", "; fully validated", "192.0.2.10")
				check(t, tcp, "missing.example.com.", "A", "; negative response, fully validated", "nxdomain")
				check(t, tcp, "deep.er.www.example.com.", "A", "; negative response, fully validated", "nxdomain")
				check(t, tcp, "www.example.com.", "AAAA", "; negative response, fully validated", "nxrrset")
				check(t, tcp, "example.com.", "TXT", "; negative response, fully validated", "nxrrset")
				check(t, tcp, "z.example.com.", "A", "; negative response, fully validated", "nxrrset")
			}
			for _, c := range []byte(base32hex) {
				name := nameWithHashEndingIn(t, salt, c)
				check(t, false, name, "A", "; negative response, fully validated", "nxdomain")
			}
			check(t, true, nameWithHashEndingIn(t, salt, '9'), "A", "; negative response, fully validated", "nxdomain")
		})
	}
}
