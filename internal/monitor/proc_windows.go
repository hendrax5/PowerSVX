//go:build !linux

package monitor

import (
	"time"
)

// Non-Linux: CPU% stays at last/zero; RSS falls back to heap in resourceSnapshot.
func readProcessUsageOS() (cpu time.Duration, rss uint64, ok bool) {
	return 0, 0, false
}
