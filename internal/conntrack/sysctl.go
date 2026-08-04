package conntrack

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultProcMax     = "/proc/sys/net/netfilter/nf_conntrack_max"
	defaultProcCount   = "/proc/sys/net/netfilter/nf_conntrack_count"
	defaultSysHashsize = "/sys/module/nf_conntrack/parameters/hashsize"
	sysctlDropIn       = "/etc/sysctl.d/99-powersvx-conntrack.conf"
	modprobeDrop       = "/etc/modprobe.d/powersvx-conntrack.conf"

	MinMax     uint64 = 65_536
	MaxMax     uint64 = 16_777_216 // 16M hard cap (RAM safety)
	DefaultMax uint64 = 2_097_152  // 2M — typical BGP DNS host
)

func sysDir() string {
	return strings.TrimSpace(os.Getenv("POWERSVX_CONNTRACK_SYS_DIR"))
}

func pathMax() string {
	if d := sysDir(); d != "" {
		return filepath.Join(d, "nf_conntrack_max")
	}
	return defaultProcMax
}

func pathCount() string {
	if d := sysDir(); d != "" {
		return filepath.Join(d, "nf_conntrack_count")
	}
	return defaultProcCount
}

func pathHash() string {
	if d := sysDir(); d != "" {
		return filepath.Join(d, "hashsize")
	}
	return defaultSysHashsize
}

// Config is the desired conntrack tuning.
type Config struct {
	Managed  bool   // apply on save / startup
	Max      uint64 // nf_conntrack_max
	Hashsize uint64 // 0 = auto (max/4)
	Persist  bool   // try writing /etc/sysctl.d + modprobe.d
}

// Status is live kernel state.
type Status struct {
	Supported      bool    `json:"supported"`
	Available      bool    `json:"available"` // nf_conntrack loaded / proc present
	Count          uint64  `json:"count"`
	Max            uint64  `json:"max"`
	Hashsize       uint64  `json:"hashsize"`
	UsagePct       float64 `json:"usage_pct"`
	Writable       bool    `json:"writable"`
	HashWritable   bool    `json:"hash_writable"`
	PersistOK      bool    `json:"persist_ok"`
	PersistPath    string  `json:"persist_path,omitempty"`
	ModprobePath   string  `json:"modprobe_path,omitempty"`
	Warning        string  `json:"warning,omitempty"`
	LastError      string  `json:"last_error,omitempty"`
	LastApplyUnix  int64   `json:"last_apply_unix,omitempty"`
	RecommendedMax uint64  `json:"recommended_max"`
}

var (
	mu            sync.Mutex
	lastApplyUnix int64
	lastErr       string
)

// Supported is true on Linux.
func Supported() bool {
	return runtime.GOOS == "linux"
}

func readUint(path string) (uint64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return 0, fmt.Errorf("empty %s", path)
	}
	return strconv.ParseUint(s, 10, 64)
}

func writeUint(path string, v uint64) error {
	return os.WriteFile(path, []byte(strconv.FormatUint(v, 10)+"\n"), 0o644)
}

func fileWritable(path string) bool {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		// try create parent for drop-ins
		return false
	}
	_ = f.Close()
	return true
}

func pathCreatable(dir string) bool {
	info, err := os.Stat(dir)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// Normalize fills defaults and clamps.
func Normalize(cfg Config) (Config, error) {
	if cfg.Max == 0 {
		cfg.Max = DefaultMax
	}
	if cfg.Max < MinMax {
		return cfg, fmt.Errorf("conntrack_max must be >= %d", MinMax)
	}
	if cfg.Max > MaxMax {
		return cfg, fmt.Errorf("conntrack_max must be <= %d", MaxMax)
	}
	if cfg.Hashsize == 0 {
		cfg.Hashsize = cfg.Max / 4
		if cfg.Hashsize < 16384 {
			cfg.Hashsize = 16384
		}
	}
	if cfg.Hashsize > cfg.Max {
		return cfg, fmt.Errorf("conntrack_hashsize must be <= conntrack_max")
	}
	return cfg, nil
}

// GetStatus reads live kernel values.
func GetStatus(desired Config) Status {
	st := Status{
		Supported:      Supported(),
		RecommendedMax: DefaultMax,
		PersistPath:    sysctlDropIn,
		ModprobePath:   modprobeDrop,
	}
	mu.Lock()
	st.LastApplyUnix = lastApplyUnix
	st.LastError = lastErr
	mu.Unlock()

	if !st.Supported {
		st.Warning = "conntrack tuning only on Linux"
		return st
	}

	max, errMax := readUint(pathMax())
	count, errCount := readUint(pathCount())
	hash, errHash := readUint(pathHash())
	if errMax != nil && errCount != nil {
		st.Available = false
		st.Warning = "nf_conntrack not loaded (missing nf_conntrack_* sysctl paths)"
		return st
	}
	st.Available = true
	if errMax == nil {
		st.Max = max
	}
	if errCount == nil {
		st.Count = count
	}
	if errHash == nil {
		st.Hashsize = hash
	}
	if st.Max > 0 {
		st.UsagePct = float64(st.Count) * 100 / float64(st.Max)
	}
	st.Writable = fileWritable(pathMax())
	st.HashWritable = fileWritable(pathHash())
	if _, err := os.Stat(sysctlDropIn); err == nil {
		st.PersistOK = true
	} else if pathCreatable("/etc/sysctl.d") {
		// creatable later
		st.PersistOK = false
	}

	if st.UsagePct >= 90 {
		st.Warning = "Conntrack nearly full — raise max/hashsize or drop idle flows."
	} else if st.UsagePct >= 75 {
		st.Warning = "Conntrack usage high (>75%). Consider raising limits before table fills."
	} else if desired.Managed && st.Max > 0 && desired.Max > 0 && st.Max < desired.Max {
		st.Warning = "Desired max not applied yet — Save & apply, or check privileges / host sysctl bind-mount."
	} else if st.Hashsize > 0 && st.Max > 0 && st.Hashsize*8 < st.Max {
		st.Warning = "Hashsize is low vs max (aim ~max/4). Collisions hurt under load."
	} else if !st.Writable {
		st.Warning = "Cannot write sysctl (need host bind-mount POWERSVX_CONNTRACK_SYS_DIR or privileged)."
	}
	return st
}

// Apply sets live kernel values and optionally persists drop-in files.
func Apply(cfg Config) error {
	mu.Lock()
	defer mu.Unlock()
	if !Supported() {
		return fmt.Errorf("conntrack tuning only supported on linux")
	}
	cfg, err := Normalize(cfg)
	if err != nil {
		lastErr = err.Error()
		return err
	}
	if !cfg.Managed {
		lastErr = ""
		lastApplyUnix = time.Now().Unix()
		return nil
	}
	if _, err := os.Stat(pathMax()); err != nil {
		lastErr = "nf_conntrack not available"
		return fmt.Errorf("nf_conntrack not available: %w", err)
	}
	if err := writeUint(pathMax(), cfg.Max); err != nil {
		lastErr = err.Error()
		return fmt.Errorf("set nf_conntrack_max: %w", err)
	}
	if err := writeUint(pathHash(), cfg.Hashsize); err != nil {
		// Hashsize may be immutable after heavy use — keep max applied, surface warning.
		lastErr = "max applied; hashsize failed: " + err.Error()
		lastApplyUnix = time.Now().Unix()
		if cfg.Persist {
			_ = writePersistFiles(cfg) // best-effort
		}
		return fmt.Errorf("set hashsize: %w (nf_conntrack_max=%d applied)", err, cfg.Max)
	}
	if cfg.Persist {
		if err := writePersistFiles(cfg); err != nil {
			lastErr = "live ok; persist failed: " + err.Error()
			lastApplyUnix = time.Now().Unix()
			return fmt.Errorf("persist: %w (live values applied)", err)
		}
	}
	lastErr = ""
	lastApplyUnix = time.Now().Unix()
	return nil
}

func writePersistFiles(cfg Config) error {
	cfg, err := Normalize(cfg)
	if err != nil {
		return err
	}
	sysctlBody := fmt.Sprintf(
		"# Managed by PowerSVX — nf_conntrack tuning\n"+
			"net.netfilter.nf_conntrack_max = %d\n",
		cfg.Max,
	)
	if err := os.MkdirAll(filepath.Dir(sysctlDropIn), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(sysctlDropIn, []byte(sysctlBody), 0o644); err != nil {
		return fmt.Errorf("sysctl.d: %w", err)
	}
	modBody := fmt.Sprintf(
		"# Managed by PowerSVX — nf_conntrack hashsize at module load\n"+
			"options nf_conntrack hashsize=%d\n",
		cfg.Hashsize,
	)
	if err := os.MkdirAll(filepath.Dir(modprobeDrop), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(modprobeDrop, []byte(modBody), 0o644); err != nil {
		return fmt.Errorf("modprobe.d: %w", err)
	}
	return nil
}

// SuggestHashsize returns max/4 clamped.
func SuggestHashsize(max uint64) uint64 {
	if max == 0 {
		max = DefaultMax
	}
	h := max / 4
	if h < 16384 {
		h = 16384
	}
	return h
}
