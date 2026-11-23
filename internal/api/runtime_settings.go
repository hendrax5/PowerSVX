package api

import "github.com/powersvx/powersvx/internal/config"

func (a *API) loadRuntimeSettings() config.RuntimeSettings {
	rs, err := config.LoadRuntimeSettings(config.RuntimeSettingsPath(a.dataDir))
	if err != nil {
		return config.RuntimeSettings{}
	}
	return rs
}

// withPreservedConntrack copies the conntrack fields from disk so other settings saves do not wipe them.
func (a *API) withPreservedConntrack(rs config.RuntimeSettings) config.RuntimeSettings {
	cur := a.loadRuntimeSettings()
	rs.ConntrackManaged = cur.ConntrackManaged
	rs.ConntrackMax = cur.ConntrackMax
	rs.ConntrackHashsize = cur.ConntrackHashsize
	rs.ConntrackPersist = cur.ConntrackPersist
	return rs
}
