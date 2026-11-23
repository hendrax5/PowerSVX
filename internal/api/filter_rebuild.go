package api

import (
	"context"
	"errors"
	"runtime/debug"
	"time"

	"github.com/powersvx/powersvx/internal/blockcdb"
	"github.com/powersvx/powersvx/internal/rpz"
)

// syncContext is the context every Filter rebuild runs under; it is cancelled at shutdown.
func (a *API) syncContext() context.Context {
	a.syncMu.Lock()
	defer a.syncMu.Unlock()
	if a.syncCtx == nil {
		a.syncCtx, a.syncCancel = context.WithCancel(context.Background())
	}
	return a.syncCtx
}

// StopFilterSync cancels a running Filter rebuild and waits for it to remove its temporary
// files and record "interrupted", or for ctx to end. New rebuilds are refused afterwards.
func (a *API) StopFilterSync(ctx context.Context) {
	a.syncContext()
	a.syncMu.Lock()
	a.syncCancel()
	a.syncMu.Unlock()
	done := make(chan struct{})
	go func() { a.syncWG.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		a.log.Warn("filter rebuild did not stop before the shutdown deadline; its temporary file is removed at next start")
	}
}

// CleanFilterTmp runs once at start, before the first sync: the Control Plane is a single
// process, so every leftover *.tmp in the Filter directory belongs to a process that died
// mid-write. A rebuild still marked running was cut off the same way.
func (a *API) CleanFilterTmp() {
	if prev, ok := blockcdb.ReadSyncStatus(a.dataDir); ok && prev.Status == blockcdb.SyncRunning {
		prev.Status = blockcdb.SyncInterrupted
		prev.Error = "the Control Plane stopped while the rebuild was running"
		prev.FinishedAt = time.Now().UTC()
		prev.Entries = existingCDBCount(a.dataDir)
		_ = blockcdb.WriteSyncStatus(a.dataDir, prev)
		a.log.Warn("previous filter rebuild was cut off by a stop; last good CDB kept serving",
			"started_at", prev.StartedAt, "entries", prev.Entries)
	}
	a.logRemovedTmp(blockcdb.CleanStaleTmp(a.dataDir), "startup")
}

func (a *API) logRemovedTmp(removed []blockcdb.StaleTmp, when string) {
	if len(removed) == 0 {
		return
	}
	for _, r := range removed {
		a.log.Warn("removed stale temporary file", "path", r.Path, "bytes", r.Bytes, "when", when)
	}
	a.log.Info("stale temporary files removed", "files", len(removed), "freed_bytes", blockcdb.TotalBytes(removed), "when", when)
}

// startDNSDistCDBRefresh pulls AXFR/IXFR (or hosts) and builds domains.cdb for dnsdist.
// The live CDB is replaced only by a complete one; a failed or cancelled run leaves it as is.
func (a *API) startDNSDistCDBRefresh(sync bool, reason string) error {
	ctx := a.syncContext()
	if ctx.Err() != nil {
		return errRPZ("shutting down")
	}
	eng := a.srv.RPZ()
	if eng != nil && !eng.TryBeginLoad() {
		return errRPZ("rpz sync already in progress")
	}
	policies := a.rpzPolicyConfigs(a.cfg.RPZ.Policies)
	run := func() {
		n, err := a.runFilterRebuild(ctx, policies, reason)
		if eng != nil {
			eng.EndLoad(err)
		}
		if n > 0 {
			a.unboundRPZEntries.Store(int64(n))
		}
		if err != nil {
			return
		}
		_, _ = blockcdb.WriteBanksWhitelist(a.dataDir)
		a.tryReloadDNSDist()
	}
	if sync {
		run()
		return nil
	}
	a.syncWG.Add(1)
	go func() {
		defer a.syncWG.Done()
		run()
	}()
	return nil
}

// runFilterRebuild runs one rebuild with logging, stale-temp cleanup and a persisted result.
func (a *API) runFilterRebuild(ctx context.Context, policies []rpz.PolicyConfig, reason string) (int, error) {
	started := time.Now().UTC()
	a.log.Info("filter rebuild started", "reason", reason)
	a.logRemovedTmp(blockcdb.CleanRebuildTmp(a.dataDir), "rebuild start")
	status := blockcdb.SyncStatus{Status: blockcdb.SyncRunning, Reason: reason, StartedAt: started, Entries: existingCDBCount(a.dataDir)}
	_ = blockcdb.WriteSyncStatus(a.dataDir, status)

	n, err := a.pullAndWriteBlockCDB(ctx, policies)
	// A rebuild is the one place the process holds tens of MB beyond its idle footprint: hand the
	// pages back now rather than whenever the runtime scavenger gets to them.
	debug.FreeOSMemory()

	finished := time.Now().UTC()
	status.FinishedAt = finished
	status.DurationMS = finished.Sub(started).Milliseconds()
	serving := existingCDBCount(a.dataDir)
	status.Entries = serving
	attrs := []any{"reason", reason, "duration", finished.Sub(started).Round(time.Millisecond).String(), "entries", serving, "cdb_bytes", blockcdb.CDBFileSize(a.dataDir)}
	switch {
	case err == nil:
		status.Status = blockcdb.SyncOK
		a.log.Info("filter rebuild finished", attrs...)
	case ctx.Err() != nil && errors.Is(err, context.Canceled):
		status.Status = blockcdb.SyncInterrupted
		status.Error = "stopped before the rebuild finished (shutdown)"
		a.log.Warn("filter rebuild interrupted; last good CDB still serving", append(attrs, "err", err)...)
	default:
		status.Status = blockcdb.SyncFailed
		status.Error = err.Error()
		a.log.Warn("filter rebuild failed; last good CDB still serving", append(attrs, "err", err)...)
	}
	if werr := blockcdb.WriteSyncStatus(a.dataDir, status); werr != nil {
		a.log.Warn("could not record the filter rebuild result", "err", werr)
	}
	return n, err
}

// filterSyncPayload is the last rebuild result for the API; nil when none was recorded yet.
func (a *API) filterSyncPayload() any {
	st, ok := blockcdb.ReadSyncStatus(a.dataDir)
	if !ok {
		return nil
	}
	return st
}
