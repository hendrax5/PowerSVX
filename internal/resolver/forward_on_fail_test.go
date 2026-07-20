package resolver

import (
	"testing"

	"github.com/powersvx/powersvx/internal/config"
)

func TestSetModeAndForwardOnFail(t *testing.T) {
	r := New(config.ResolverConfig{Mode: "forward", ForwardOnFail: true})
	r.SetMode("recursive")
	r.SetForwardOnFail(false)
	if r.Mode != "recursive" || r.ForwardOnFail {
		t.Fatalf("mode=%s fail=%v", r.Mode, r.ForwardOnFail)
	}
	r.SetMode("FORWARD")
	if r.Mode != "forward" {
		t.Fatalf("mode=%s", r.Mode)
	}
}

func TestNewDefaultsForwardOnFail(t *testing.T) {
	r := New(config.ResolverConfig{Mode: "recursive", ForwardOnFail: true, Forwarders: []string{"1.1.1.1:53"}})
	if !r.ForwardOnFail || r.Mode != "recursive" {
		t.Fatalf("%+v", r)
	}
}
