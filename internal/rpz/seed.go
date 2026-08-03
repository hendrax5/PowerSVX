package rpz

import (
	"bufio"
	"os"
	"strings"

	"github.com/powersvx/powersvx/internal/config"
)

// HotSeedPath is the default relative filename under --data-dir.
const HotSeedPath = "rpz-hot-seed.txt"

// WriteHotSeed writes one FQDN per line (for restart warm-up).
func WriteHotSeed(path string, names []string) error {
	if path == "" {
		return nil
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, n := range names {
		n = config.NormalizeName(n)
		if n == "" || n == "." {
			continue
		}
		if _, err := w.WriteString(n + "\n"); err != nil {
			return err
		}
	}
	return w.Flush()
}

// ReadHotSeed loads previously persisted hot-seed names.
func ReadHotSeed(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, config.NormalizeName(line))
	}
	return out, sc.Err()
}
