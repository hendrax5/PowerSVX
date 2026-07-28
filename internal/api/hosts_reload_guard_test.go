package api

import (
	"testing"
	"time"
)

func TestHostsFullReloadDaytime(t *testing.T) {
	cases := []struct {
		hour int
		want bool
	}{
		{0, false},
		{4, false},
		{5, false},
		{6, true},
		{12, true},
		{21, true},
		{22, false},
		{23, false},
	}
	for _, tc := range cases {
		now := time.Date(2026, 7, 25, tc.hour, 30, 0, 0, time.Local)
		if got := hostsFullReloadDaytime(now); got != tc.want {
			t.Fatalf("hour %d: got %v want %v", tc.hour, got, tc.want)
		}
	}
}
