//go:build linux

package monitor

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"time"
)

func readProcessUsageOS() (cpu time.Duration, rss uint64, ok bool) {
	// /proc/self/stat: utime(14) stime(15) in clock ticks
	b, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0, 0, false
	}
	fields := strings.Fields(string(b))
	// comm can contain spaces inside (); find after )
	s := string(b)
	idx := strings.LastIndex(s, ")")
	if idx < 0 || idx+2 >= len(s) {
		return 0, 0, false
	}
	fields = strings.Fields(s[idx+2:])
	// After ')': state is [0], utime is [11], stime is [12] (1-based fields 14/15 of full stat)
	if len(fields) < 13 {
		return 0, 0, false
	}
	utime, err1 := strconv.ParseUint(fields[11], 10, 64)
	stime, err2 := strconv.ParseUint(fields[12], 10, 64)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	clk := clockTicks()
	cpu = time.Duration(float64(utime+stime) / clk * float64(time.Second))

	f, err := os.Open("/proc/self/status")
	if err != nil {
		return cpu, 0, true
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "VmRSS:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				kb, err := strconv.ParseUint(parts[1], 10, 64)
				if err == nil {
					rss = kb * 1024
				}
			}
			break
		}
	}
	return cpu, rss, true
}

func clockTicks() float64 {
	// Linux default USER_HZ is 100; reading from getconf is overkill.
	return 100
}
