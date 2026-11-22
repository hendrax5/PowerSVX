package api

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/powersvx/powersvx/internal/config"
	"github.com/powersvx/powersvx/internal/unboundrpz"
)

// unboundReloadRetryDelays spaces the retries after a failed reload. Unbound often
// starts after the Control Plane does, so the first attempt can fail on a healthy node.
var unboundReloadRetryDelays = []time.Duration{5 * time.Second, 15 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute, 5 * time.Minute}

// unboundSyncState is what the last runtime sync did, for the health output.
type unboundSyncState struct {
	mu         sync.Mutex
	synced     bool
	skipped    []unboundrpz.SkippedForwarder
	writeErr   string
	reloadErr  string
	reloadedAt time.Time
	gen        int // bumped on every sync so a stale retry stops
}

func hostDeployment() bool { return os.Getenv("POWERSVX_HOST_DEPLOYMENT") == "1" }

func (s *unboundSyncState) record(report unboundrpz.RuntimeReport, writeErr, reloadErr error) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.synced = true
	s.gen++
	s.skipped = append([]unboundrpz.SkippedForwarder(nil), report.SkippedForwarders...)
	s.writeErr, s.reloadErr = "", ""
	if writeErr != nil {
		s.writeErr = writeErr.Error()
	}
	if reloadErr != nil {
		s.reloadErr = reloadErr.Error()
	} else if writeErr == nil {
		s.reloadedAt = time.Now()
	}
	return s.gen
}

// retried records the outcome of a background retry unless a newer sync has run.
func (s *unboundSyncState) retried(gen int, err error) (current bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gen != gen {
		return false
	}
	if err != nil {
		s.reloadErr = err.Error()
		return true
	}
	s.reloadErr = ""
	s.reloadedAt = time.Now()
	return true
}

// health returns the check for the health output, or nil before the first sync.
// status is "pass", or "degraded" when a forwarder was skipped, the write failed
// or the reload failed.
func (s *unboundSyncState) health() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.synced {
		return nil
	}
	out := map[string]any{"status": "pass"}
	if !s.reloadedAt.IsZero() {
		out["last_reload"] = s.reloadedAt.UTC().Format(time.RFC3339)
	}
	if len(s.skipped) > 0 {
		out["status"] = "degraded"
		out["skipped_forwarders"] = append([]unboundrpz.SkippedForwarder(nil), s.skipped...)
		out["note"] = "forwarders that point back into the Dataplane were not written to Unbound; unbound recurses by itself for them. Remove them from the resolver settings."
	}
	if s.writeErr != "" {
		out["status"] = "degraded"
		out["write_error"] = s.writeErr
	}
	if s.reloadErr != "" {
		out["status"] = "degraded"
		out["reload_error"] = s.reloadErr
	}
	return out
}

// retryReload keeps trying to reload Unbound after a failed reload, until one works,
// a newer sync takes over or the delays run out. The failure stays in the health output.
func (a *API) retryReload(gen int) {
	for _, d := range unboundReloadRetryDelays {
		time.Sleep(d)
		err := unboundrpz.TryReload()
		if !a.unboundSync.retried(gen, err) {
			return
		}
		if err == nil {
			a.log.Info("unbound reloaded after an earlier failure")
			return
		}
		a.log.Error("unbound reload still failing", "err", err)
	}
}

// loopForwarderError names the first forwarder that would make Unbound forward to itself.
// The console and API refuse such a value instead of saving it.
func loopForwarderError(fwd []string, fz []config.ForwardZoneConfig) error {
	port := unboundrpz.BackendPort()
	check := func(where string, list []string) error {
		for _, f := range list {
			if loop, why := unboundrpz.ForwarderLoop(f, port); loop {
				return fmt.Errorf("%sforwarder %q points at %s, so Unbound would forward to itself and every lookup would fail; leave the forwarders empty and set the resolver mode to recursive: Unbound recurses by itself", where, f, why)
			}
		}
		return nil
	}
	if err := check("", fwd); err != nil {
		return err
	}
	for _, z := range fz {
		if err := check("zone "+z.Zone+": ", z.Forwarders); err != nil {
			return err
		}
	}
	return nil
}

// dropLoopForwarders removes the forwarders that would make Unbound forward to itself and
// says how many it removed. It is for values nobody just typed (the TOML defaults or earlier
// saved settings): saving them again must not write the loop back to the settings file.
func dropLoopForwarders(fwd []string, fz []config.ForwardZoneConfig) ([]string, []config.ForwardZoneConfig, int) {
	port := unboundrpz.BackendPort()
	dropped := 0
	var keptFwd []string
	for _, f := range fwd {
		if loop, _ := unboundrpz.ForwarderLoop(f, port); loop {
			dropped++
			continue
		}
		keptFwd = append(keptFwd, f)
	}
	var keptZones []config.ForwardZoneConfig
	for _, z := range fz {
		var zf []string
		for _, f := range z.Forwarders {
			if loop, _ := unboundrpz.ForwarderLoop(f, port); loop {
				dropped++
				continue
			}
			zf = append(zf, f)
		}
		if len(zf) == 0 && len(z.Forwarders) > 0 {
			continue // the zone only had looping forwarders
		}
		z.Forwarders = zf
		keptZones = append(keptZones, z)
	}
	return keptFwd, keptZones, dropped
}

// NormalizeSavedResolver is run once at start on the saved runtime settings. Earlier
// versions let the console save the shipped default `forward` mode with Unbound's own
// address as the forwarder, and that value survives every change of the TOML. It removes
// such forwarders, switches a forward mode that is left with none to recursive, rewrites the
// file, and logs what it did. The writer still skips a looping forwarder at render time,
// whatever the source; this makes the settings file honest as well.
func NormalizeSavedResolver(path string, rs config.RuntimeSettings, log *slog.Logger) config.RuntimeSettings {
	fwd, fz, dropped := dropLoopForwarders(rs.Forwarders, rs.ForwardZones)
	if dropped == 0 {
		return rs
	}
	hadGlobal := len(rs.Forwarders) > 0
	rs.Forwarders, rs.ForwardZones = fwd, fz
	if rs.Forwarders == nil {
		rs.Forwarders = []string{}
	}
	if hadGlobal && len(fwd) == 0 && rs.ResolverMode != nil && strings.EqualFold(*rs.ResolverMode, "forward") {
		mode := "recursive"
		rs.ResolverMode = &mode
	}
	if err := config.SaveRuntimeSettings(path, rs); err != nil {
		log.Error("saved resolver settings point at Unbound itself and could not be rewritten", "path", path, "err", err)
		return rs
	}
	log.Warn("saved resolver settings pointed Unbound at itself; removed those forwarders and rewrote the file",
		"path", path, "removed", dropped, "resolver_mode", rs.ResolverMode)
	return rs
}
