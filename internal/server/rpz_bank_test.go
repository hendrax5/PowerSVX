package server

import (
	"testing"

	"github.com/powersvx/powersvx/internal/rpz"
)

func TestBankSafeRPZHit(t *testing.T) {
	redir := rpz.Hit{Action: rpz.ActionRedirect, Target: "139.255.196.196"}
	h := bankSafeRPZHit("brimo.id", redir)
	if h.Action != rpz.ActionNXDOMAIN {
		t.Fatalf("brimo.id: %+v", h)
	}
	h = bankSafeRPZHit("poker.example", redir)
	if h.Action != rpz.ActionRedirect || h.Target != "139.255.196.196" {
		t.Fatalf("generic: %+v", h)
	}
	h = bankSafeRPZHit("www.bca.co.id", redir)
	if h.Action != rpz.ActionPass {
		t.Fatalf("official: %+v", h)
	}
}
