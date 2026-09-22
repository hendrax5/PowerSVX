package blockcdb

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// MinUsefulCDBBytes: smaller files are treated as empty stubs (EnsureEmpty).
	MinUsefulCDBBytes = 1 << 20 // 1 MiB
	MetaFile          = "blocklist.meta.json"
	SeedManifestFile  = "seed-manifest.json"
)

// CDBFileSize returns domains.cdb size or 0 if missing.
func CDBFileSize(dataDir string) int64 {
	st, err := os.Stat(filepath.Join(Dir(dataDir), CDBFile))
	if err != nil {
		return 0
	}
	return st.Size()
}

// NeedsSeed reports whether the local CDB is missing or only an empty stub.
func NeedsSeed(dataDir string) bool {
	return CDBFileSize(dataDir) < MinUsefulCDBBytes
}

// SeedManifest describes a published blocklist-seed.tgz (from JMG → GitHub).
type SeedManifest struct {
	Policy    string    `json:"policy"`
	Zone      string    `json:"zone"`
	Serial    uint32    `json:"serial"`
	Entries   int       `json:"entries"`
	CreatedAt time.Time `json:"created_at"`
	Source    string    `json:"source,omitempty"`
}

// SyncNamesGuarded writes domains.txt + CDB but refuses to replace a useful CDB with empty.
func SyncNamesGuarded(dataDir string, names []string) (txtN, cdbN int, err error) {
	prev := existingMetaEntries(dataDir)
	if len(names) == 0 && prev > 0 {
		return 0, prev, fmt.Errorf("refusing to wipe blocklist CDB (%d entries) with empty set", prev)
	}
	return SyncNames(dataDir, names)
}

func existingMetaEntries(dataDir string) int {
	b, err := os.ReadFile(filepath.Join(Dir(dataDir), MetaFile))
	if err != nil {
		return 0
	}
	var n int
	for _, part := range strings.Split(string(b), ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, `"cdb":`) {
			_, _ = fmt.Sscanf(part, `"cdb":%d`, &n)
			return n
		}
	}
	return 0
}

// WriteSeedTarGz packs blocklist files (+ optional axfr-state.json) into w as .tgz.
func WriteSeedTarGz(dataDir string, manifest SeedManifest, axfrStatePath string, w io.Writer) error {
	dir := Dir(dataDir)
	gw := gzip.NewWriter(w)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	manBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := writeTarBytes(tw, SeedManifestFile, manBytes); err != nil {
		return err
	}
	for _, name := range []string{CDBFile, DomainsFile, MetaFile} {
		path := filepath.Join(dir, name)
		if err := writeTarFile(tw, name, path); err != nil {
			if os.IsNotExist(err) && name == DomainsFile {
				continue
			}
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	if axfrStatePath != "" {
		if err := writeTarFile(tw, "rpz-axfr-state.json", axfrStatePath); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func writeTarBytes(tw *tar.Writer, name string, b []byte) error {
	hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(b)), ModTime: time.Now()}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(b)
	return err
}

func writeTarFile(tw *tar.Writer, name, path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	hdr, err := tar.FileInfoHeader(st, "")
	if err != nil {
		return err
	}
	hdr.Name = name
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}

// InstallSeedTarGz extracts a seed archive into dataDir/blocklist (+ rpz-axfr-state.json).
func InstallSeedTarGz(dataDir string, r io.Reader) (SeedManifest, error) {
	var man SeedManifest
	gr, err := gzip.NewReader(r)
	if err != nil {
		return man, fmt.Errorf("gzip: %w", err)
	}
	defer gr.Close()
	tr := tar.NewReader(gr)

	dir := Dir(dataDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return man, err
	}
	tmpDir, err := os.MkdirTemp(dir, "seed-extract-*")
	if err != nil {
		return man, err
	}
	defer os.RemoveAll(tmpDir)

	var axfrState []byte
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return man, err
		}
		base := filepath.Base(hdr.Name)
		switch base {
		case SeedManifestFile:
			b, err := io.ReadAll(tr)
			if err != nil {
				return man, err
			}
			_ = json.Unmarshal(b, &man)
			_ = os.WriteFile(filepath.Join(tmpDir, base), b, 0o644)
		case CDBFile, DomainsFile, MetaFile:
			dst := filepath.Join(tmpDir, base)
			f, err := os.Create(dst)
			if err != nil {
				return man, err
			}
			if _, err := io.Copy(f, tr); err != nil {
				_ = f.Close()
				return man, err
			}
			_ = f.Close()
		case "rpz-axfr-state.json":
			axfrState, err = io.ReadAll(tr)
			if err != nil {
				return man, err
			}
		default:
			_, _ = io.Copy(io.Discard, tr)
		}
	}

	cdbTmp := filepath.Join(tmpDir, CDBFile)
	st, err := os.Stat(cdbTmp)
	if err != nil || st.Size() < int64(headerSize) {
		return man, fmt.Errorf("seed archive missing domains.cdb")
	}
	for _, name := range []string{CDBFile, DomainsFile, MetaFile, SeedManifestFile} {
		src := filepath.Join(tmpDir, name)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		dst := filepath.Join(dir, name)
		if err := os.Rename(src, dst); err != nil {
			// cross-device fallback
			if err := copyFile(src, dst); err != nil {
				return man, err
			}
		}
	}
	if len(axfrState) > 0 {
		path := filepath.Join(dataDir, "rpz-axfr-state.json")
		if dataDir == "" {
			path = filepath.Join(".", "data", "rpz-axfr-state.json")
		}
		_ = os.MkdirAll(filepath.Dir(path), 0o755)
		_ = os.WriteFile(path, axfrState, 0o644)
	}
	return man, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

// BootstrapFromURL downloads a seed .tgz (GitHub Release) and installs it when CDB is empty.
func BootstrapFromURL(dataDir, url string, timeout time.Duration) (SeedManifest, error) {
	var man SeedManifest
	if url == "" {
		return man, fmt.Errorf("seed url empty")
	}
	if !NeedsSeed(dataDir) {
		return man, fmt.Errorf("cdb already present")
	}
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return man, err
	}
	if tok := strings.TrimSpace(os.Getenv("POWERSVX_FILTER_SEED_TOKEN")); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	req.Header.Set("User-Agent", "PowerSVX-filter-seed/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return man, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return man, fmt.Errorf("seed HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return InstallSeedTarGz(dataDir, resp.Body)
}
