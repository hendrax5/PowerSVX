package api

import (
	"os"
	"sync"
	"time"

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
