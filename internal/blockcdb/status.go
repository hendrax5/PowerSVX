package blockcdb

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	// SyncStatusFile records the outcome of the last Filter rebuild. It is separate from
	// blocklist.meta.json, which seed archives carry to other nodes and which older readers
	// parse by hand.
	SyncStatusFile = "filter-sync-status.json"
	// RebuildPendingFile exists while the cached feeds may be newer than domains.cdb.
	RebuildPendingFile = "rebuild-pending"
	tmpSuffix          = ".tmp"
)

// Sync statuses recorded in SyncStatus.Status.
const (
	SyncRunning     = "running"
	SyncOK          = "ok"
	SyncFailed      = "failed"
	SyncInterrupted = "interrupted"
)

// SyncStatus is the last Filter rebuild result, persisted so it survives restarts.
type SyncStatus struct {
	Status     string    `json:"status"`
	Reason     string    `json:"reason,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	DurationMS int64     `json:"duration_ms"`
	// Entries is the number of names in the CDB that is serving after this run.
	Entries int    `json:"entries"`
	Error   string `json:"error,omitempty"`
}

// ReadSyncStatus returns the persisted last rebuild result; ok is false when none exists.
func ReadSyncStatus(dataDir string) (SyncStatus, bool) {
	var st SyncStatus
	b, err := os.ReadFile(filepath.Join(Dir(dataDir), SyncStatusFile))
	if err != nil || json.Unmarshal(b, &st) != nil || st.Status == "" {
		return SyncStatus{}, false
	}
	return st, true
}

// WriteSyncStatus persists st atomically.
func WriteSyncStatus(dataDir string, st SyncStatus) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	dir := Dir(dataDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, SyncStatusFile), append(b, '\n'))
}

// MarkRebuildPending records that cached feeds are about to change, so a rebuild cut short
// is redone on the next sync even when the upstream serial has not moved.
func MarkRebuildPending(dataDir string) error {
	dir := Dir(dataDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, RebuildPendingFile), []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o644)
}

// RebuildPending reports whether a previous run changed the feeds without finishing the CDB.
func RebuildPending(dataDir string) bool {
	_, err := os.Stat(filepath.Join(Dir(dataDir), RebuildPendingFile))
	return err == nil
}

// ClearRebuildPending removes the pending marker after a CDB was built from the feeds.
func ClearRebuildPending(dataDir string) {
	_ = os.Remove(filepath.Join(Dir(dataDir), RebuildPendingFile))
}

func writeFileAtomic(path string, data []byte) error {
	tmp := path + tmpSuffix
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// StaleTmp describes one removed leftover temporary file.
type StaleTmp struct {
	Path  string `json:"path"`
	Bytes int64  `json:"bytes"`
}

// CleanStaleTmp removes leftover "*.tmp" regular files in the Filter directory and its
// feeds/ cache. Call it only when no writer is running (at Control Plane start): every such
// file then belongs to a process that died mid-write. Live .cdb, .txt, .lua and .json files
// and anything that is not a regular file ending in ".tmp" are never touched.
func CleanStaleTmp(dataDir string) []StaleTmp { return cleanTmp(dataDir, nil) }

// CleanRebuildTmp is the narrow variant run at the start of each rebuild: it removes only
// the temporary files the rebuild itself writes (domains.txt.tmp, domains.cdb.tmp, domains.names.tmp and feed
// cache temp files), leaving temp files of unrelated writers that may be in flight.
func CleanRebuildTmp(dataDir string) []StaleTmp {
	return cleanTmp(dataDir, func(rel string) bool {
		switch rel {
		case DomainsFile + tmpSuffix, CDBFile + tmpSuffix, NamesScratchFile:
			return true
		}
		return strings.HasPrefix(rel, "feeds/") && strings.HasSuffix(rel, ".txt"+tmpSuffix)
	})
}

func cleanTmp(dataDir string, only func(rel string) bool) []StaleTmp {
	dir := Dir(dataDir)
	var removed []StaleTmp
	for _, sub := range []string{"", "feeds"} {
		entries, err := os.ReadDir(filepath.Join(dir, sub))
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if !e.Type().IsRegular() || !strings.HasSuffix(name, tmpSuffix) {
				continue
			}
			rel := name
			if sub != "" {
				rel = sub + "/" + name
			}
			if only != nil && !only(rel) {
				continue
			}
			full := filepath.Join(dir, sub, name)
			var size int64
			if info, err := e.Info(); err == nil {
				size = info.Size()
			}
			if os.Remove(full) == nil {
				removed = append(removed, StaleTmp{Path: full, Bytes: size})
			}
		}
	}
	sort.Slice(removed, func(i, j int) bool { return removed[i].Path < removed[j].Path })
	return removed
}

// TotalBytes sums the sizes of removed files.
func TotalBytes(files []StaleTmp) (n int64) {
	for _, f := range files {
		n += f.Bytes
	}
	return n
}
