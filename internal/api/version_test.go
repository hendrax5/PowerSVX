package api

import "testing"

func TestBuildID(t *testing.T) {
	origV, origG := Version, GitCommit
	t.Cleanup(func() {
		Version, GitCommit = origV, origG
	})
	Version = "1.6.0"
	GitCommit = "unknown"
	if BuildID() != "1.6.0" {
		t.Fatalf("got %s", BuildID())
	}
	GitCommit = "abc1234"
	if BuildID() != "1.6.0+abc1234" {
		t.Fatalf("got %s", BuildID())
	}
}

func TestShortGit(t *testing.T) {
	if shortGit("e4629e4f901943965534d69351882b98c0fd4020") != "e4629e4" {
		t.Fatal(shortGit("e4629e4f901943965534d69351882b98c0fd4020"))
	}
}
