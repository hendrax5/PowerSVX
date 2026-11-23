package linux_test

import (
	"strings"
	"testing"
)

// The Control Plane reloads Unbound through its control interface, so the generated
// configuration must keep it enabled on loopback, and must load the runtime files the
// Control Plane writes. The generated file also has to pass check-unbound-conf.sh.
func TestGeneratedUnboundConfKeepsTheControlInterfaceOnLoopback(t *testing.T) {
	unbound, _ := generate(t, "2", "2048")
	mustContain(t, "unbound.conf", unbound,
		"remote-control:",
		"control-enable: yes",
		"control-interface: 127.0.0.1",
		"control-port: 8953",
		"include: /opt/unbound/etc/unbound/rpz/runtime-server.conf",
		"include: /opt/unbound/etc/unbound/rpz/runtime-zones.conf",
	)
	if strings.Contains(unbound, "control-enable: no") {
		t.Error("the generated unbound.conf must never disable the control interface")
	}

	// With a fake docker standing in for unbound-checkconf, every static check passes.
	if r := runCheck(t, unbound, strp("# empty\n")); r.code != 0 {
		t.Fatalf("the generated configuration must pass check-unbound-conf.sh:\n%s", r.out)
	}
}
