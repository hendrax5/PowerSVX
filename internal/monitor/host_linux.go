//go:build linux

package monitor

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func enrichHostResources(r *Resources) {
	if r == nil {
		return
	}
	if total, avail, ok := readMeminfoMB(); ok {
		r.HostMemTotalMB = total
		r.HostMemAvailableMB = avail
		if total > 0 {
			used := total - avail
			if used < 0 {
				used = 0
			}
			r.HostMemUsedPct = used * 100 / total
		}
	}
	if total, used, pct, ok := readDiskGB("/"); ok {
		r.DiskTotalGB = total
		r.DiskUsedGB = used
		r.DiskUsedPct = pct
	}
	if load, ok := readLoad1(); ok {
		r.Load1 = load
	}
}

func readMeminfoMB() (total, avail float64, ok bool) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	var totKB, availKB float64
	var haveT, haveA bool
	for sc.Scan() {
		line := sc.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		v, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			totKB, haveT = v, true
		case "MemAvailable:":
			availKB, haveA = v, true
		}
		if haveT && haveA {
			break
		}
	}
	if !haveT {
		return 0, 0, false
	}
	if !haveA {
		availKB = totKB
	}
	return totKB / 1024, availKB / 1024, true
}

func readDiskGB(path string) (total, used, pct float64, ok bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, 0, false
	}
	bsize := float64(st.Bsize)
	tot := float64(st.Blocks) * bsize
	free := float64(st.Bavail) * bsize
	u := tot - free
	if tot <= 0 {
		return 0, 0, 0, false
	}
	return tot / (1024 * 1024 * 1024), u / (1024 * 1024 * 1024), u * 100 / tot, true
}

func readLoad1() (float64, bool) {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, false
	}
	fields := strings.Fields(string(b))
	if len(fields) < 1 {
		return 0, false
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, false
	}
	return v, true
}
