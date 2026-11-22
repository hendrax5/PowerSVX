package authoritative

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/powersvx/powersvx/internal/config"
)

// ExportMarker is written inside the zones directory once the one-time export
// from the database has completed.
const ExportMarker = ".exported"

// ZoneSource is where the one-time export reads the legacy zones from.
type ZoneSource interface {
	LoadZones(ctx context.Context) (map[string][]Record, error)
	LoadZoneMeta(ctx context.Context) (map[string]ZoneMeta, error)
}

// ExportFromSource writes every zone of src to one file each under dir, once.
// It does nothing when dir already holds zone files or the marker. The files
// are staged in a sibling directory and moved into place with one rename, with
// the marker inside, so a failure or crash never leaves a partial zones
// directory that a later start would mistake for a finished export. The
// source is only read.
func ExportFromSource(ctx context.Context, src ZoneSource, dir string) (exported int, ran bool, err error) {
	if hasZoneState(dir) {
		return 0, false, nil
	}
	zones, err := src.LoadZones(ctx)
	if err != nil {
		return 0, false, fmt.Errorf("load zones: %w", err)
	}
	metas, err := src.LoadZoneMeta(ctx)
	if err != nil {
		return 0, false, fmt.Errorf("load zone metadata: %w", err)
	}

	staging := dir + ".export-tmp"
	if err := os.RemoveAll(staging); err != nil {
		return 0, false, err
	}
	if err := os.MkdirAll(staging, 0o755); err != nil {
		return 0, false, err
	}
	done := false
	defer func() {
		if !done {
			_ = os.RemoveAll(staging)
		}
	}()

	names := make([]string, 0, len(zones))
	for name := range zones {
		names = append(names, name)
	}
	sort.Strings(names)
	seen := make(map[string]string, len(names))
	for _, name := range names {
		norm := normalizeZone(name)
		file := ZoneFileName(norm)
		if prev, dup := seen[file]; dup {
			return 0, false, fmt.Errorf("zones %q and %q map to the same file", prev, name)
		}
		seen[file] = name
		meta, ok := metas[name]
		if !ok {
			meta = DefaultZoneMeta()
		}
		if meta.Type == "" {
			meta.Type = "native"
		}
		recs := make([]Record, len(zones[name]))
		copy(recs, zones[name])
		data, err := encodeZoneFile(norm, meta, recs)
		if err != nil {
			return 0, false, fmt.Errorf("zone %s: %w", name, err)
		}
		if err := writeFileAtomic(filepath.Join(staging, file), data); err != nil {
			return 0, false, fmt.Errorf("zone %s: %w", name, err)
		}
	}
	marker, _ := json.Marshal(map[string]any{
		"version": ZoneFileVersion, "exported_at": time.Now().UTC().Format(time.RFC3339), "zones": len(names),
	})
	if err := writeFileAtomic(filepath.Join(staging, ExportMarker), marker); err != nil {
		return 0, false, err
	}

	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return 0, false, err
	}
	// An empty zones directory may already exist; a non-empty one is left alone.
	if err := os.Remove(dir); err != nil && !os.IsNotExist(err) {
		return 0, false, fmt.Errorf("zones directory is not empty: %w", err)
	}
	if err := os.Rename(staging, dir); err != nil {
		return 0, false, err
	}
	done = true
	return len(names), true, nil
}

func normalizeZone(name string) string {
	return config.NormalizeName(name)
}

func hasZoneState(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if n == ExportMarker || (strings.HasSuffix(n, ".json") && !strings.HasPrefix(n, ".")) {
			return true
		}
	}
	return false
}
