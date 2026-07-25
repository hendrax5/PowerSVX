package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseHHMM parses "HH:MM" or "H:MM" (24h). Empty string returns ok=false.
func ParseHHMM(s string) (hour, min int, ok bool, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, false, nil
	}
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return 0, 0, false, fmt.Errorf("update_at must be HH:MM, got %q", s)
	}
	h, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	m, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil {
		return 0, 0, false, fmt.Errorf("update_at must be HH:MM, got %q", s)
	}
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, false, fmt.Errorf("update_at out of range: %q", s)
	}
	return h, m, true, nil
}

// NextDailyAt returns the next local wall-clock occurrence of HH:MM at or after now.
// If that time today has already passed, returns tomorrow at HH:MM.
func NextDailyAt(now time.Time, hhmm string) (time.Time, error) {
	h, m, ok, err := ParseHHMM(hhmm)
	if err != nil {
		return time.Time{}, err
	}
	if !ok {
		return time.Time{}, fmt.Errorf("update_at empty")
	}
	loc := now.Location()
	next := time.Date(now.Year(), now.Month(), now.Day(), h, m, 0, 0, loc)
	if !next.After(now) {
		next = next.Add(24 * time.Hour)
	}
	return next, nil
}
