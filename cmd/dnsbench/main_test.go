package main

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestBuildQueryModes(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	hit := buildQuery("hit", "example.com.", rng)
	if hit.Question[0].Name != "example.com." || hit.Question[0].Qtype != dns.TypeA {
		t.Fatalf("hit: %+v", hit.Question)
	}
	nx := buildQuery("nx", "example.com.", rng)
	if !strings.HasSuffix(nx.Question[0].Name, "example.com.") || !strings.HasPrefix(nx.Question[0].Name, "nx-") {
		t.Fatalf("nx qname=%s", nx.Question[0].Name)
	}
	miss := buildQuery("miss", "example.com.", rng)
	if !strings.HasPrefix(miss.Question[0].Name, "r") {
		t.Fatalf("miss qname=%s", miss.Question[0].Name)
	}
}
