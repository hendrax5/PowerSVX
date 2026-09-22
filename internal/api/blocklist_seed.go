package api

import (
	"net/http"
	"time"

	"github.com/powersvx/powersvx/internal/blockcdb"
	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/rpz"
)

// handleBlocklistSeed serves GET /api/v1/blocklist/seed — authenticated download of
// domains.cdb + domains.txt + axfr state for publishing to GitHub Releases.
func (a *API) handleBlocklistSeed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if blockcdb.NeedsSeed(a.dataDir) {
		http.Error(w, "local CDB not ready for seed export", http.StatusServiceUnavailable)
		return
	}
	entries := existingCDBCount(a.dataDir)
	var serial uint32
	zone := config.DefaultKomdigiZone
	policy := config.DefaultKomdigiPolicyName
	if st := rpz.LoadAxfrState(rpz.AxfrStatePath(a.dataDir)); st != nil {
		if fs, ok := st.Get(policy); ok {
			serial = fs.Serial
			if fs.Zone != "" {
				zone = fs.Zone
			}
		}
	}
	man := blockcdb.SeedManifest{
		Policy:    policy,
		Zone:      zone,
		Serial:    serial,
		Entries:   entries,
		CreatedAt: time.Now().UTC(),
		Source:    "powersvx-export",
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="blocklist-seed.tgz"`)
	w.Header().Set("X-PowerSVX-Seed-Serial", itoaU32(serial))
	w.Header().Set("X-PowerSVX-Seed-Entries", itoaInt(entries))
	if err := blockcdb.WriteSeedTarGz(a.dataDir, man, rpz.AxfrStatePath(a.dataDir), w); err != nil {
		a.log.Warn("blocklist seed export failed", "err", err)
		http.Error(w, "seed export failed", http.StatusInternalServerError)
		return
	}
}

func itoaU32(n uint32) string {
	return itoaInt(int(n))
}

func itoaInt(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
