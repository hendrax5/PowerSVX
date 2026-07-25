package config

import (
	"testing"
	"time"
)

func TestNextDailyAt(t *testing.T) {
	loc := time.FixedZone("WIB", 7*3600)
	now := time.Date(2026, 7, 25, 22, 0, 0, 0, loc)
	next, err := NextDailyAt(now, "04:00")
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 7, 26, 4, 0, 0, 0, loc)
	if !next.Equal(want) {
		t.Fatalf("got %v want %v", next, want)
	}

	now2 := time.Date(2026, 7, 26, 3, 59, 0, 0, loc)
	next2, err := NextDailyAt(now2, "04:00")
	if err != nil {
		t.Fatal(err)
	}
	want2 := time.Date(2026, 7, 26, 4, 0, 0, 0, loc)
	if !next2.Equal(want2) {
		t.Fatalf("got %v want %v", next2, want2)
	}

	now3 := time.Date(2026, 7, 26, 4, 0, 0, 0, loc)
	next3, err := NextDailyAt(now3, "04:00")
	if err != nil {
		t.Fatal(err)
	}
	want3 := time.Date(2026, 7, 27, 4, 0, 0, 0, loc)
	if !next3.Equal(want3) {
		t.Fatalf("same instant must roll to next day: got %v want %v", next3, want3)
	}
}

func TestParseHHMM(t *testing.T) {
	h, m, ok, err := ParseHHMM("4:05")
	if err != nil || !ok || h != 4 || m != 5 {
		t.Fatalf("got %d:%d ok=%v err=%v", h, m, ok, err)
	}
	_, _, ok, err = ParseHHMM("")
	if err != nil || ok {
		t.Fatal("empty should be ok=false")
	}
	if _, _, _, err := ParseHHMM("25:00"); err == nil {
		t.Fatal("expected error")
	}
}
