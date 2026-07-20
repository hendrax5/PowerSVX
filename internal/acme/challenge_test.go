package acme

import "testing"

func TestChallengePresentLookup(t *testing.T) {
	s := NewChallengeStore()
	s.Present("example.com", "abc123")
	v, ok := s.LookupTXT("_acme-challenge.example.com.")
	if !ok || v != "abc123" {
		t.Fatalf("got %v %v", v, ok)
	}
	if s.TXTAnswer("_acme-challenge.example.com.") == nil {
		t.Fatal("expected TXT RR")
	}
	s.CleanUp("example.com")
	if _, ok := s.LookupTXT("_acme-challenge.example.com."); ok {
		t.Fatal("expected cleaned")
	}
}
