package resolver

import (
	"testing"

	"github.com/powersvx/powersvx/internal/config"
)

func TestPickForwardersSkipsCooldown(t *testing.T) {
	r := New(config.ResolverConfig{Mode: "forward", Forwarders: []string{"1.1.1.1:53", "8.8.8.8:53"}})
	dead, live := "1.1.1.1:53", "8.8.8.8:53"
	for i := 0; i < fwdMaxFails; i++ {
		r.noteFwd(dead, false)
	}
	got := r.pickForwarders([]string{dead, live})
	if len(got) != 1 || got[0] != live {
		t.Fatalf("expected only live after cooldown, got %v", got)
	}
	r.noteFwd(dead, true)
	got = r.pickForwarders([]string{dead, live})
	if len(got) != 2 {
		t.Fatalf("success must revive, got %v", got)
	}
}

func TestPickForwardersAllDownTriesAll(t *testing.T) {
	r := New(config.ResolverConfig{Mode: "forward"})
	addrs := []string{"192.0.2.1:53", "192.0.2.2:53"}
	for _, a := range addrs {
		for i := 0; i < fwdMaxFails; i++ {
			r.noteFwd(a, false)
		}
	}
	got := r.pickForwarders(addrs)
	if len(got) != 2 {
		t.Fatalf("all down should still try all, got %v", got)
	}
}

func TestPickForwardersFewerFailsStayUp(t *testing.T) {
	r := New(config.ResolverConfig{Mode: "forward"})
	dead, live := "1.1.1.1:53", "8.8.8.8:53"
	r.noteFwd(dead, false)
	r.noteFwd(dead, false)
	got := r.pickForwarders([]string{dead, live})
	if len(got) != 2 {
		t.Fatalf("two fails < %d threshold, got %v", fwdMaxFails, got)
	}
}
