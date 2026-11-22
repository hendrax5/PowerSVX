package api

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/powersvx/powersvx/internal/blockcdb"
	"github.com/powersvx/powersvx/internal/config"
)

// unboundRPZEntryCount is the number of names in the active block CDB.
func (a *API) unboundRPZEntryCount() int64 {
	return a.unboundRPZEntries.Load()
}

// refreshUnboundEntryCount reloads the CDB entry count from the CDB metadata file
// (startup / health).
func (a *API) refreshUnboundEntryCount() {
	var n int64
	if config.DNSDistDataplane() {
		meta := filepath.Join(blockcdb.Dir(a.dataDir), "blocklist.meta.json")
		if b, err := os.ReadFile(meta); err == nil {
			var m struct {
				CDB int `json:"cdb"`
			}
			if json.Unmarshal(b, &m) == nil && m.CDB > 0 {
				n = int64(m.CDB)
			}
		}
	}
	a.unboundRPZEntries.Store(n)
}

// RefreshUnboundEntryCount exposes the CDB entry count for health after start.
func (a *API) RefreshUnboundEntryCount() { a.refreshUnboundEntryCount() }
