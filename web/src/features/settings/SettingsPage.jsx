import { useEffect, useRef, useState } from 'react'
import { api } from '../../api'
import { useAuth } from '../../auth'
import Settings from '../../Settings'
import { ErrorBox } from '../../ui'

function AxfrSyncPanel({ isAdmin }) {
  const DEFAULT_SOURCES = ['182.23.79.202:53', '139.255.196.202:53']
  const [data, setData] = useState(null)
  const [draftTargets, setDraftTargets] = useState([])
  const [newTarget, setNewTarget] = useState('')
  const [editAddr, setEditAddr] = useState(null)
  const [err, setErr] = useState('')
  const [ok, setOk] = useState('')
  const [busy, setBusy] = useState(false)

  const applySnapshot = (d) => {
    setData(d)
    setDraftTargets([...(d.targets || [])])
  }

  const load = () =>
    api
      .axfrSync()
      .then(applySnapshot)
      .catch((e) => setErr(e.message))

  useEffect(() => {
    load()
  }, [])

  useEffect(() => {
    if (!data?.progress?.running) return undefined
    const t = setInterval(() => {
      api.axfrSync().then(applySnapshot).catch(() => {})
    }, 1500)
    return () => clearInterval(t)
  }, [data?.progress?.running])

  const targetsDirty =
    JSON.stringify([...(draftTargets || [])].sort()) !==
    JSON.stringify([...(data?.targets || [])].sort())

  const toggle = async () => {
    if (!data) return
    setBusy(true)
    setErr('')
    setOk('')
    try {
      const next = await api.setAxfrSync({ enabled: !data.enabled })
      applySnapshot(next)
      setOk(next.enabled ? 'Outbound master sync enabled' : 'Outbound master sync disabled')
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  const saveTargets = async () => {
    setBusy(true)
    setErr('')
    setOk('')
    try {
      const next = await api.setAxfrSync({ targets: draftTargets })
      applySnapshot(next)
      setEditAddr(null)
      setNewTarget('')
      setOk('Sources saved')
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  const resetDefaults = () => {
    setDraftTargets([...DEFAULT_SOURCES])
    setEditAddr(null)
    setNewTarget('')
    setOk('')
    setErr('')
  }

  const startEditTarget = (addr) => {
    setErr('')
    setOk('')
    setEditAddr(addr)
    setNewTarget(addr)
  }

  const cancelEditTarget = () => {
    setEditAddr(null)
    setNewTarget('')
    setErr('')
  }

  const addOrUpdateTarget = () => {
    const raw = newTarget.trim()
    if (!raw) return
    const normalized = raw.includes(':') ? raw : `${raw}:53`
    if (editAddr != null) {
      if (
        draftTargets.some((t) => (t === normalized || t === raw) && t !== editAddr)
      ) {
        setErr('Source already listed')
        return
      }
      setDraftTargets(draftTargets.map((t) => (t === editAddr ? normalized : t)))
      setEditAddr(null)
      setNewTarget('')
      setErr('')
      setOk('Source updated in list — Save sources to apply')
      return
    }
    if (draftTargets.includes(normalized) || draftTargets.includes(raw)) {
      setErr('Source already listed')
      return
    }
    setDraftTargets([...draftTargets, normalized])
    setNewTarget('')
    setErr('')
  }

  const removeTarget = (addr) => {
    setDraftTargets(draftTargets.filter((t) => t !== addr))
    if (editAddr === addr) {
      setEditAddr(null)
      setNewTarget('')
    }
  }

  const syncNow = async () => {
    setBusy(true)
    setErr('')
    setOk('')
    try {
      const next = await api.runAxfrSync()
      applySnapshot(next)
      setOk('NOTIFY started for your authoritative zones')
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  const statusTone = (st) => {
    if (st === 'soa_ok' || st === 'axfr_ok' || st === 'notify_ok') return 'text-[var(--ok)]'
    if (st === 'fail' || st === 'notify_fail' || st === 'soa_mismatch') return 'text-[var(--danger)]'
    return 'text-[var(--muted)]'
  }

  if (!data) {
    if (err) return <ErrorBox msg={err} />
    return (
      <div className="space-y-4" role="status" aria-busy="true" aria-label="Loading AXFR sync">
        <div className="h-24 rounded-[var(--radius-lg)] bg-[var(--bg-panel)] animate-pulse" />
        <div className="grid grid-cols-1 lg:grid-cols-[1.35fr_1fr] gap-4">
          <div className="h-48 rounded-[var(--radius-lg)] bg-[var(--bg-panel)] animate-pulse" />
          <div className="h-48 rounded-[var(--radius-lg)] bg-[var(--bg-panel)] animate-pulse reveal-delay-1" />
        </div>
        <div className="h-40 rounded-[var(--radius-lg)] bg-[var(--bg-panel)] animate-pulse reveal-delay-2" />
      </div>
    )
  }

  const p = data.progress || {}
  const pct = p.total > 0 ? Math.min(100, Math.round((100 * (p.done || 0)) / p.total)) : 0
  const zoneCount = (data.zones || []).length

  return (
    <div className="space-y-5 max-w-[var(--content-max)]" aria-labelledby="tools-axfr-heading">
      <header className="reveal">
        <p className="text-[11px] uppercase tracking-[0.14em] text-[var(--muted)] mb-2">Zone transfer</p>
        <h2 id="tools-axfr-heading" className="text-2xl md:text-3xl font-semibold tracking-tight leading-none">
          AXFR
        </h2>
        <p className="text-sm text-[var(--muted)] mt-3 max-w-[60ch] leading-relaxed">
          Two different jobs. The top panel is PowerSVX as <span className="text-[var(--text)]">master</span>{' '}
          (others pull <em>your</em> zones). The bottom panel is PowerSVX as{' '}
          <span className="text-[var(--text)]">slave</span> (you pull the Komdigi blocklist into RPZ).
        </p>
      </header>

      {err ? <ErrorBox msg={err} /> : null}
      {ok ? (
        <div
          className="border border-[var(--accent)]/40 bg-[var(--accent-soft)] text-[var(--accent)] text-sm px-3 py-2 reveal"
          role="status"
        >
          {ok}
        </div>
      ) : null}

      <div className="grid grid-cols-1 lg:grid-cols-[1.25fr_1fr] gap-4 items-start">
        <section className="panel overflow-hidden reveal reveal-delay-1" aria-labelledby="axfr-sources-heading">
          <div className="px-4 py-3 border-b border-[var(--border)] flex flex-wrap items-start justify-between gap-3">
            <div>
              <p className="text-[10px] uppercase tracking-[0.12em] text-[var(--muted)] mb-1">Role: master</p>
              <h3 id="axfr-sources-heading" className="text-sm font-medium">
                Outbound — secondaries pull from PowerSVX
              </h3>
              <p className="text-xs text-[var(--muted)] mt-1 leading-relaxed max-w-[46ch]">
                Allow these IPs to AXFR <strong className="font-medium text-[var(--text)]">your</strong>{' '}
                authoritative zones and receive NOTIFY. This is <em>not</em> how you download the TrustPositif
                blocklist — use Filter feeds below for that.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <span
                className={`inline-flex items-center gap-2 text-xs mono px-2.5 py-1.5 rounded-[var(--radius)] border ${
                  data.enabled
                    ? 'border-[var(--ok)]/40 text-[var(--ok)] bg-[color-mix(in_srgb,var(--ok)_12%,transparent)]'
                    : 'border-[var(--border)] text-[var(--muted)]'
                }`}
              >
                <span className={`axfr-pulse-dot ${data.enabled ? 'is-on' : ''}`} aria-hidden />
                {data.enabled ? 'On' : 'Off'}
              </span>
              <button
                type="button"
                disabled={busy || !isAdmin}
                onClick={toggle}
                className={`btn text-xs min-h-[36px] disabled:opacity-50 ${data.enabled ? 'btn-secondary' : 'btn-primary'}`}
              >
                {data.enabled ? 'Disable' : 'Enable'}
              </button>
              <button
                type="button"
                disabled={busy || !isAdmin || !data.enabled || p.running}
                onClick={syncNow}
                className="btn btn-secondary text-xs min-h-[36px] disabled:opacity-50"
              >
                {p.running ? 'Syncing…' : 'NOTIFY now'}
              </button>
            </div>
          </div>
          <div className="px-4 py-2 border-b border-[var(--border)] flex flex-wrap justify-between gap-2">
            <p className="text-xs text-[var(--muted)]">Secondary IPs (host or host:port)</p>
            <button
              type="button"
              disabled={!isAdmin || busy}
              onClick={resetDefaults}
              className="btn btn-ghost text-xs min-h-[32px] px-2 disabled:opacity-50"
            >
              Fill Komdigi secondary IPs
            </button>
          </div>
          <ul className="divide-y divide-[var(--border)]">
            {draftTargets.length === 0 ? (
              <li className="px-4 py-8 text-sm text-[var(--muted)]">
                No secondaries. Add IPs that should pull zones from this server, or fill Komdigi secondary IPs.
              </li>
            ) : (
              draftTargets.map((addr, i) => (
                <li
                  key={addr}
                  className={`flex items-center gap-3 px-4 py-2.5 axfr-row ${
                    editAddr === addr ? 'bg-[var(--accent-soft)]' : ''
                  }`}
                  style={{ '--index': i }}
                >
                  <span className="mono text-sm flex-1 break-all">{addr}</span>
                  <div className="flex gap-1 shrink-0">
                    <button
                      type="button"
                      disabled={!isAdmin || busy}
                      onClick={() => startEditTarget(addr)}
                      className="btn btn-ghost text-xs disabled:opacity-40"
                    >
                      Edit
                    </button>
                    <button
                      type="button"
                      disabled={!isAdmin || busy}
                      onClick={() => removeTarget(addr)}
                      className="btn btn-ghost text-xs text-[var(--danger)] disabled:opacity-40"
                    >
                      Remove
                    </button>
                  </div>
                </li>
              ))
            )}
          </ul>
          <div className="px-4 py-3 border-t border-[var(--border)] flex flex-col sm:flex-row gap-2">
            <label className="flex-1 space-y-1.5">
              <span className="sr-only">{editAddr != null ? 'Edit source' : 'Add source'}</span>
              <input
                value={newTarget}
                onChange={(e) => setNewTarget(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault()
                    addOrUpdateTarget()
                  }
                }}
                disabled={!isAdmin || busy}
                placeholder="182.23.79.202 or host:53"
                className="w-full mono text-sm input"
              />
            </label>
            <div className="flex gap-2">
              <button
                type="button"
                disabled={!isAdmin || busy || !newTarget.trim()}
                onClick={addOrUpdateTarget}
                className="btn btn-secondary min-h-[44px] disabled:opacity-50"
              >
                {editAddr != null ? 'Save' : 'Add'}
              </button>
              {editAddr != null ? (
                <button
                  type="button"
                  disabled={!isAdmin || busy}
                  onClick={cancelEditTarget}
                  className="btn btn-ghost min-h-[44px] disabled:opacity-50"
                >
                  Cancel
                </button>
              ) : null}
              <button
                type="button"
                disabled={!isAdmin || busy || !targetsDirty}
                onClick={saveTargets}
                className="btn btn-primary min-h-[44px] disabled:opacity-50"
              >
                Save sources
              </button>
            </div>
          </div>
        </section>

        <section className="panel overflow-hidden reveal reveal-delay-2" aria-labelledby="axfr-progress-heading">
          <div className="px-4 py-3 border-b border-[var(--border)]">
            <h3 id="axfr-progress-heading" className="text-sm font-medium">
              Sync progress
            </h3>
            <p className="text-xs text-[var(--muted)] mt-1">NOTIFY then remote SOA check per zone.</p>
          </div>
          <div className="px-4 py-5 space-y-4">
            <div className="flex items-baseline justify-between gap-3">
              <span className="text-3xl font-semibold tracking-tight mono tabular-nums">{pct}%</span>
              <span className="text-xs text-[var(--muted)] text-right">
                {p.done || 0}/{p.total || 0} zones
                {zoneCount ? ` · ${zoneCount} tracked` : ''}
              </span>
            </div>
            <div className="h-2 bg-[var(--bg)] border border-[var(--border)] rounded-[var(--radius-sm)] overflow-hidden">
              <div
                className={`h-full bg-[var(--accent)] transition-[width] duration-500 ease-[cubic-bezier(0.16,1,0.3,1)] ${
                  p.running ? 'axfr-bar-shimmer' : ''
                }`}
                style={{ width: `${p.running || p.total ? pct : 0}%` }}
              />
            </div>
            <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs">
              <div>
                <dt className="text-[var(--muted)]">Phase</dt>
                <dd className="mono mt-0.5">{p.phase || (p.running ? '…' : 'idle')}</dd>
              </div>
              <div>
                <dt className="text-[var(--muted)]">Current</dt>
                <dd className="mono mt-0.5 truncate">{p.current_zone || '—'}</dd>
              </div>
              <div className="col-span-2">
                <dt className="text-[var(--muted)]">Last finished</dt>
                <dd className="mono mt-0.5">{p.finished_at || '—'}</dd>
              </div>
            </dl>
            {p.last_error ? <p className="text-xs text-[var(--danger)]">{p.last_error}</p> : null}
          </div>
        </section>
      </div>

      <section className="panel overflow-hidden reveal reveal-delay-3" aria-labelledby="axfr-zones-heading">
        <div className="px-4 py-3 border-b border-[var(--border)] flex items-baseline justify-between gap-3">
          <div>
            <h3 id="axfr-zones-heading" className="text-sm font-medium">
              Zone status
            </h3>
            <p className="text-xs text-[var(--muted)] mt-1">Per-source notify / SOA / pull state.</p>
          </div>
        </div>
        {(data.zones || []).length === 0 ? (
          <div className="px-4 py-10 text-left">
            <p className="text-base font-semibold tracking-tight">No authoritative zones</p>
            <p className="text-sm text-[var(--muted)] mt-2 max-w-md leading-relaxed">
              Create a zone first, then enable AXFR sync and run Sync now.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-[var(--muted)] border-b border-[var(--border)]">
                  <th className="px-4 py-2 font-medium">Zone</th>
                  <th className="px-4 py-2 font-medium">Serial</th>
                  <th className="px-4 py-2 font-medium">Source</th>
                  <th className="px-4 py-2 font-medium">Status</th>
                  <th className="px-4 py-2 font-medium">Detail</th>
                </tr>
              </thead>
              <tbody>
                {(data.zones || []).flatMap((z) =>
                  (z.targets || []).map((t, i) => (
                    <tr key={`${z.zone}-${t.addr}`} className="border-b border-[var(--border)]/70 axfr-row">
                      <td className="px-4 py-2 mono">{i === 0 ? z.zone : ''}</td>
                      <td className="px-4 py-2 mono">{i === 0 ? z.serial : ''}</td>
                      <td className="px-4 py-2 mono text-xs">{t.addr}</td>
                      <td className={`px-4 py-2 mono text-xs ${statusTone(t.status)}`}>{t.status}</td>
                      <td className="px-4 py-2 text-xs text-[var(--muted)]">
                        {t.error ||
                          (t.remote_serial ? `remote ${t.remote_serial}` : '') ||
                          (t.axfr_pull_at ? `pull ${t.axfr_pull_at}` : '') ||
                          (t.notify_at ? `notify ${t.notify_at}` : '—')}
                      </td>
                    </tr>
                  )),
                )}
              </tbody>
            </table>
          </div>
        )}
        {data.note ? (
          <p className="px-4 py-3 text-[11px] text-[var(--muted)] border-t border-[var(--border)] leading-relaxed">
            {data.note}
          </p>
        ) : null}
      </section>

      <AxfrFilterFeedsPanel isAdmin={isAdmin} />
    </div>
  )
}

const DEFAULT_AXFR_FILTER_MASTERS = ['182.23.79.202:53', '139.255.196.202:53']

function AxfrFilterFeedsPanel({ isAdmin }) {
  const defaultRedirectTarget = '139.255.196.196'
  const [hostsPolicies, setHostsPolicies] = useState([])
  const [policies, setPolicies] = useState([])
  const [savedAxfr, setSavedAxfr] = useState([])
  const [hostsIntervalSec, setHostsIntervalSec] = useState(3600)
  const [axfrIntervalSec, setAxfrIntervalSec] = useState(86400)
  const [status, setStatus] = useState(null)
  const [name, setName] = useState('')
  const [zone, setZone] = useState('')
  const [mastersText, setMastersText] = useState(DEFAULT_AXFR_FILTER_MASTERS.join('\n'))
  const [action, setAction] = useState('nxdomain')
  const [target, setTarget] = useState('')
  const [editName, setEditName] = useState(null)
  const [err, setErr] = useState('')
  const [ok, setOk] = useState('')
  const [busy, setBusy] = useState(false)
  const [awaitingSync, setAwaitingSync] = useState(false)

  const applyRPZ = (r) => {
    setStatus(r)
    const all = clonePolicies(r?.policies)
    const axfr = all.filter((p) => p.format === 'axfr')
    setHostsPolicies(all.filter((p) => (p.format || 'hosts') !== 'axfr'))
    setPolicies(axfr)
    setSavedAxfr(axfr)
    setHostsIntervalSec(Number(r?.update_interval) || 0)
    setAxfrIntervalSec(
      r?.axfr_update_interval === undefined || r?.axfr_update_interval === null
        ? 86400
        : Number(r.axfr_update_interval),
    )
  }

  const finishSyncBanner = (r) => {
    setAwaitingSync(false)
    if (r?.error) {
      setOk('')
      setErr(`Sync failed: ${r.error}`)
      return
    }
    setErr('')
    const feeds = r?.axfr_feeds || {}
    const axfrPols = (r?.policies || []).filter((p) => p.format === 'axfr')
    const parts = axfrPols.map((p) => {
      const st = feeds[p.name]
      if (!st) return `${p.name}: no status`
      if (st.ok === false) return `${p.name}: FAILED ${st.last_error || ''}`.trim()
      return `${p.name}: OK serial ${st.serial} (${st.last_mode || 'synced'})`
    })
    setOk(
      `Sync OK · ${Number(r?.entries ?? 0).toLocaleString()} RPZ entries` +
        (parts.length ? ` · ${parts.join(' · ')}` : ' · no AXFR feeds'),
    )
  }

  const load = () =>
    api
      .rpz()
      .then(applyRPZ)
      .catch((e) => setErr(e.message))

  useEffect(() => {
    load()
  }, [])

  useEffect(() => {
    if (action === 'redirect' && !target) setTarget(defaultRedirectTarget)
    if (action === 'cname' && target === defaultRedirectTarget) setTarget('')
  }, [action, target])

  useEffect(() => {
    if (!status?.loading && !awaitingSync) return undefined
    const t = setInterval(() => {
      api
        .rpz()
        .then((r) => {
          applyRPZ(r)
          if (!r.loading) finishSyncBanner(r)
        })
        .catch((e) => {
          setAwaitingSync(false)
          setErr(e.message)
        })
    }, 2000)
    return () => clearInterval(t)
  }, [status?.loading, awaitingSync])

  const parseMasters = (text) =>
    text
      .split(/[\n,]+/)
      .map((s) => s.trim())
      .filter(Boolean)
      .map((s) => (s.includes(':') ? s : `${s}:53`))

  const resetForm = () => {
    setName('')
    setZone('')
    setMastersText(DEFAULT_AXFR_FILTER_MASTERS.join('\n'))
    setAction('nxdomain')
    setTarget('')
    setEditName(null)
  }

  const startEdit = (p) => {
    setErr('')
    setOk('')
    setEditName(p.name)
    setName(p.name || '')
    setZone(p.zone || p.source || '')
    setMastersText((p.masters && p.masters.length ? p.masters : DEFAULT_AXFR_FILTER_MASTERS).join('\n'))
    setAction(p.action || 'nxdomain')
    setTarget(p.target || '')
  }

  const cancelEdit = () => {
    setErr('')
    setOk('')
    resetForm()
  }

  const addOrUpdate = () => {
    setErr('')
    setOk('')
    const n = name.trim()
    const z = zone.trim()
    const masters = parseMasters(mastersText)
    const t = target.trim()
    if (!n || !z) {
      setErr('Name and zone are required')
      return
    }
    const zNorm = z.replace(/\.$/, '').toLowerCase()
    if (zNorm === 'trustkominfo' || zNorm === 'trustpositif') {
      setErr(
        `Zone "${z}" looks wrong for Komdigi. Use trustpositifkominfo (see their sample dig AXFR).`,
      )
      return
    }
    if (!masters.length) {
      setErr('At least one master (host or host:port) is required')
      return
    }
    if (action === 'redirect' && !t) {
      setErr(`Redirect needs a landing IP (e.g. ${defaultRedirectTarget})`)
      return
    }
    if (action === 'cname' && !t) {
      setErr('CNAME needs a landing hostname (e.g. block.local)')
      return
    }
    const nextPolicy = {
      name: n,
      source: z,
      zone: z,
      masters,
      format: 'axfr',
      action,
      target: action === 'redirect' || action === 'cname' ? t : '',
      enabled: true,
    }
    if (editName != null) {
      if (policies.some((p) => p.name === n && p.name !== editName)) {
        setErr(`Feed "${n}" already exists`)
        return
      }
      setPolicies((list) =>
        list.map((p) => (p.name === editName ? { ...nextPolicy, enabled: p.enabled !== false } : p)),
      )
      setOk(`Updated "${n}" in draft — click Save & sync filters to apply`)
      resetForm()
      return
    }
    if (policies.some((p) => p.name === n) || hostsPolicies.some((p) => p.name === n)) {
      setErr(`Policy "${n}" already exists`)
      return
    }
    setPolicies((p) => [...p, nextPolicy])
    setOk(`Added "${n}" to draft — click Save & sync filters to pull AXFR`)
    resetForm()
  }

  const remove = (n) => {
    setErr('')
    setOk(`Removed "${n}" from draft — click Save & sync filters to apply`)
    setPolicies((p) => p.filter((x) => x.name !== n))
    if (editName === n) resetForm()
  }

  const toggleEnabled = (n) => {
    setErr('')
    setPolicies((list) =>
      list.map((p) => {
        if (p.name !== n) return p
        const on = p.enabled !== false
        return { ...p, enabled: !on }
      }),
    )
    setOk(`Toggled "${n}" — click Save & sync filters to apply`)
  }

  const saveSync = async () => {
    setBusy(true)
    setErr('')
    setOk('')
    try {
      const hostsSec = Math.max(0, Number(hostsIntervalSec) || 0)
      const axfrSec = Math.max(0, Number(axfrIntervalSec) || 0)
      const r = await api.updateRPZ([...hostsPolicies, ...policies], false, hostsSec, axfrSec, true)
      applyRPZ(r)
      if (r.sync_skipped) {
        setAwaitingSync(true)
        setOk(
          `Saved AXFR policy. Sync already running — wait until it finishes, then click Re-sync (${r.sync_skip_reason || 'busy'}).`,
        )
      } else if (r.loading) {
        setAwaitingSync(true)
        setOk('Saved — AXFR/IXFR syncing from masters… (first pull can take several minutes)')
      } else {
        finishSyncBanner(r)
      }
    } catch (ex) {
      setErr(`Save failed: ${ex.message}`)
    } finally {
      setBusy(false)
    }
  }

  const resync = async () => {
    setBusy(true)
    setErr('')
    setOk('')
    try {
      const r = await api.reloadRPZ(true)
      applyRPZ(r)
      setAwaitingSync(true)
      setOk('Re-sync started… SOA check then IXFR/AXFR')
    } catch (ex) {
      setErr(`Re-sync failed: ${ex.message}`)
    } finally {
      setBusy(false)
    }
  }

  const loading = !!status?.loading || awaitingSync
  const dirty = JSON.stringify(policies) !== JSON.stringify(savedAxfr)
  const axfrFeeds = status?.axfr_feeds || {}
  const axfrEvents = Array.isArray(status?.axfr_events) ? status.axfr_events : []
  const feedStates = policies.map((p) => ({ policy: p, st: axfrFeeds[p.name] || null }))
  const anyFailed =
    !!status?.error || feedStates.some((f) => f.st && (f.st.ok === false || f.st.last_mode === 'failed'))
  const anySynced = feedStates.some((f) => f.st && f.st.serial)
  const syncState = loading
    ? { label: 'Syncing…', tone: 'warn' }
    : anyFailed
      ? { label: 'Failed', tone: 'danger' }
      : anySynced
        ? { label: 'Synced', tone: 'ok' }
        : policies.length
          ? { label: 'Not synced yet', tone: 'warn' }
          : { label: 'Idle', tone: 'muted' }
  const toneClass =
    syncState.tone === 'ok'
      ? 'border-emerald-500/40 text-emerald-700 bg-emerald-500/10'
      : syncState.tone === 'danger'
        ? 'border-[var(--danger)]/40 text-[var(--danger)] bg-[var(--danger)]/10'
        : syncState.tone === 'warn'
          ? 'border-amber-500/40 text-amber-800 bg-amber-500/10'
          : 'border-[var(--border)] text-[var(--muted)] bg-[var(--bg)]'

  const modeLabel = (mode) => {
    switch (mode) {
      case 'full_axfr':
        return 'Full AXFR'
      case 'ixfr':
        return 'IXFR'
      case 'skipped':
        return 'Skipped (serial unchanged)'
      case 'failed':
        return 'Failed'
      default:
        return mode || '—'
    }
  }

  return (
    <section className="panel overflow-hidden reveal reveal-delay-3" aria-labelledby="axfr-filter-heading">
      <div className="px-4 py-3 border-b border-[var(--border)] flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-[10px] uppercase tracking-[0.12em] text-[var(--muted)] mb-1">Role: slave</p>
          <h3 id="axfr-filter-heading" className="text-sm font-medium">
            Filter feeds — pull blocklist (PowerSVX as slave)
          </h3>
          <p className="text-xs text-[var(--muted)] mt-1 leading-relaxed max-w-[56ch]">
            Default: AXFR zone <span className="mono text-[var(--text)]">trustpositifkominfo</span> (enabled).
            First install can bootstrap CDB from the GitHub seed release; later updates use IXFR. Disable a feed
            without deleting it.
          </p>
          <div className="mt-2 flex flex-wrap items-center gap-2 text-xs">
            <span className={`inline-flex items-center px-2 py-0.5 border mono ${toneClass}`}>{syncState.label}</span>
            {dirty ? (
              <span className="inline-flex items-center px-2 py-0.5 border border-amber-500/40 text-amber-800 bg-amber-500/10">
                Unsaved draft
              </span>
            ) : null}
            <span className="text-[var(--muted)]">
              {status ? `${Number(status.entries ?? 0).toLocaleString()} RPZ entries total` : '…'}
              {status?.last_loaded ? ` · engine ${status.last_loaded}` : ''}
            </span>
          </div>
        </div>
        <div className="flex gap-2">
          <button
            type="button"
            disabled={!isAdmin || busy || loading}
            onClick={resync}
            className="btn btn-secondary text-xs min-h-[36px] disabled:opacity-50"
          >
            Re-sync
          </button>
          <button
            type="button"
            disabled={!isAdmin || busy || loading}
            onClick={saveSync}
            className="btn btn-primary text-xs min-h-[36px] disabled:opacity-50"
          >
            {busy ? 'Saving…' : loading ? 'Syncing…' : 'Save & sync filters'}
          </button>
        </div>
      </div>

      <div className="px-4 py-3 space-y-3">
        <div
          className={`border text-sm px-3 py-2 ${
            syncState.tone === 'ok'
              ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-800'
              : syncState.tone === 'danger'
                ? 'border-[var(--danger)]/40 bg-[var(--danger)]/10 text-[var(--danger)]'
                : syncState.tone === 'warn'
                  ? 'border-amber-500/40 bg-amber-500/10 text-amber-900'
                  : 'border-[var(--border)] text-[var(--muted)]'
          }`}
          role="status"
        >
          {loading ? (
            <p>Sync in progress — large zones can take several minutes. Status updates every few seconds.</p>
          ) : anyFailed ? (
            <p>
              Filter sync failed
              {status?.error ? `: ${status.error}` : err ? `: ${err}` : '.'}{' '}
              {Number(status?.entries ?? 0) > 0
                ? `DNS still resolves; serving last CDB (${Number(status.entries).toLocaleString()} entries).`
                : 'Check feed rows and the log below.'}
            </p>
          ) : anySynced ? (
            <p>
              Last sync OK
              {feedStates
                .filter((f) => f.st?.updated_at)
                .map((f) => ` · ${f.policy.name} serial ${f.st.serial} (${modeLabel(f.st.last_mode)}) at ${f.st.updated_at}`)
                .join('') || '.'}
            </p>
          ) : policies.length ? (
            <p>Feeds configured but not synced yet — click Save & sync filters or Re-sync.</p>
          ) : (
            <p>No filter feeds configured.</p>
          )}
        </div>

        {err || (status?.error && !(Number(status?.entries ?? 0) > 0)) ? (
          <ErrorBox msg={err || `Engine error: ${status.error}`} />
        ) : null}
        {status?.error && Number(status?.entries ?? 0) > 0 && !err ? (
          <div className="border border-amber-500/40 bg-amber-500/10 text-amber-900 text-sm px-3 py-2">
            Sync warning: {status.error} — serving last-good filter CDB ({Number(status.entries).toLocaleString()}{' '}
            entries). Resolve path stays up.
          </div>
        ) : null}
        {ok ? (
          <div className="border border-[var(--accent)]/40 bg-[var(--accent-soft)] text-[var(--accent)] text-sm px-3 py-2">
            {ok}
          </div>
        ) : null}

        <label className="text-xs text-[var(--muted)] space-y-1 block max-w-xs">
          AXFR auto-refresh interval (seconds, 0 = off · default 86400 = 24h)
          <input
            type="number"
            min={0}
            step={3600}
            className="w-full bg-[var(--bg)] border border-[var(--border)] px-2 py-1.5 text-sm mono text-[var(--text)]"
            value={axfrIntervalSec}
            onChange={(e) => setAxfrIntervalSec(e.target.value)}
            disabled={!isAdmin || busy}
          />
        </label>

        <ul className="space-y-2 text-sm">
          {policies.length ? (
            policies.map((p) => {
              const st = axfrFeeds[p.name]
              const rowTone = !st
                ? 'text-[var(--muted)]'
                : st.ok === false || st.last_mode === 'failed'
                  ? 'text-[var(--danger)]'
                  : 'text-emerald-700'
              return (
                <li
                  key={p.name}
                  className={`flex flex-wrap items-start justify-between gap-2 border-b border-[var(--border)]/60 pb-2 ${
                    editName === p.name ? 'bg-[var(--accent-soft)] -mx-2 px-2 rounded-[var(--radius)]' : ''
                  }`}
                >
                  <div className="min-w-0">
                    <div className="font-medium flex flex-wrap items-center gap-2">
                      <span>{p.name}</span>
                      <span
                        className={`text-[10px] uppercase tracking-wide mono ${
                          p.enabled === false ? 'text-[var(--muted)]' : 'text-emerald-700'
                        }`}
                      >
                        {p.enabled === false ? 'disabled' : 'enabled'}
                      </span>
                      <span className={`text-[10px] uppercase tracking-wide mono ${rowTone}`}>
                        {st ? modeLabel(st.last_mode) : 'never synced'}
                      </span>
                    </div>
                    <div className="mono text-xs text-[var(--muted)] break-all">zone {p.zone || p.source}</div>
                    <div className="mono text-xs text-[var(--muted)] break-all">
                      masters {(p.masters || []).join(', ') || '—'}
                    </div>
                    <div className="text-xs text-[var(--muted)] mt-0.5">
                      axfr · {p.action || 'nxdomain'}
                      {p.target ? ` → ${p.target}` : ''}
                    </div>
                    {st ? (
                      <div className={`text-xs mt-1 mono ${rowTone}`}>
                        serial {st.serial ?? 0}
                        {st.last_master ? ` · via ${st.last_master}` : ''}
                        {st.updated_at ? ` · ${st.updated_at}` : ''}
                        {st.last_error ? ` · ${st.last_error}` : ''}
                      </div>
                    ) : (
                      <div className="text-xs mt-1 text-[var(--muted)]">No sync status yet</div>
                    )}
                  </div>
                  <div className="flex gap-1 shrink-0">
                    <button
                      type="button"
                      disabled={!isAdmin || busy || loading}
                      onClick={() => toggleEnabled(p.name)}
                      className="btn btn-ghost text-xs disabled:opacity-40"
                    >
                      {p.enabled === false ? 'Enable' : 'Disable'}
                    </button>
                    <button
                      type="button"
                      disabled={!isAdmin || busy || loading}
                      onClick={() => startEdit(p)}
                      className="btn btn-ghost text-xs disabled:opacity-40"
                    >
                      Edit
                    </button>
                    <button
                      type="button"
                      disabled={!isAdmin || busy || loading}
                      onClick={() => remove(p.name)}
                      className="btn btn-ghost text-xs text-[var(--danger)] disabled:opacity-40"
                    >
                      Remove
                    </button>
                  </div>
                </li>
              )
            })
          ) : (
            <li className="text-sm text-[var(--muted)]">No slave filter feeds yet — add one below, then Save & sync.</li>
          )}
        </ul>

        <div className="border border-[var(--border)] rounded-[var(--radius)] overflow-hidden">
          <div className="px-3 py-2 border-b border-[var(--border)] text-xs font-medium flex justify-between gap-2">
            <span>Sync log</span>
            <span className="text-[var(--muted)] font-normal">latest {Math.min(axfrEvents.length, 20)} events</span>
          </div>
          {axfrEvents.length ? (
            <ul className="max-h-48 overflow-y-auto divide-y divide-[var(--border)]/60 text-xs mono">
              {[...axfrEvents].reverse().slice(0, 20).map((ev, i) => (
                <li
                  key={`${ev.time}-${i}`}
                  className={`px-3 py-1.5 ${
                    ev.level === 'error' ? 'text-[var(--danger)]' : 'text-[var(--muted)]'
                  }`}
                >
                  <span className="text-[var(--text)]/70">{ev.time || '—'}</span>
                  {ev.feed ? ` · ${ev.feed}` : ''}
                  {' · '}
                  {ev.message}
                </li>
              ))}
            </ul>
          ) : (
            <p className="px-3 py-4 text-xs text-[var(--muted)]">
              No sync events yet. After the next Re-sync / Save & sync, results appear here.
            </p>
          )}
        </div>

        <div className="grid gap-2 sm:grid-cols-2">
          <label className="text-xs text-[var(--muted)] space-y-1">
            Name
            <input
              className="w-full bg-[var(--bg)] border border-[var(--border)] px-2 py-1.5 text-sm text-[var(--text)]"
              value={name}
              onChange={(e) => setName(e.target.value)}
              disabled={!isAdmin || busy}
              placeholder="trustpositif-axfr"
            />
          </label>
          <label className="text-xs text-[var(--muted)] space-y-1">
            Zone
            <input
              className="w-full bg-[var(--bg)] border border-[var(--border)] px-2 py-1.5 text-sm mono text-[var(--text)]"
              value={zone}
              onChange={(e) => setZone(e.target.value)}
              disabled={!isAdmin || busy}
              placeholder="trustpositifkominfo"
            />
          </label>
          <label className="text-xs text-[var(--muted)] space-y-1 sm:col-span-2">
            Komdigi masters (one per line)
            <textarea
              className="w-full bg-[var(--bg)] border border-[var(--border)] px-2 py-1.5 text-sm mono text-[var(--text)] min-h-[4.5rem]"
              value={mastersText}
              onChange={(e) => setMastersText(e.target.value)}
              disabled={!isAdmin || busy}
              placeholder={DEFAULT_AXFR_FILTER_MASTERS.join('\n')}
            />
          </label>
          <label className="text-xs text-[var(--muted)] space-y-1">
            Action
            <select
              className="w-full bg-[var(--bg)] border border-[var(--border)] px-2 py-1.5 text-sm text-[var(--text)]"
              value={action}
              onChange={(e) => setAction(e.target.value)}
              disabled={!isAdmin || busy}
            >
              <option value="nxdomain">nxdomain</option>
              <option value="nodata">nodata</option>
              <option value="pass">pass</option>
              <option value="redirect">redirect (sinkhole IP)</option>
              <option value="cname">cname (landing host)</option>
            </select>
            {action === 'redirect' ? (
              <p className="text-[11px] text-[var(--muted)] leading-relaxed">
                Sinkhole IP breaks many Indonesian banking apps (they treat it as DNS hijack). The
                website still loads. PowerSVX answers NXDOMAIN instead of the landing IP for
                bank-branded names; gambling/porn redirect is unchanged.
              </p>
            ) : null}
          </label>
          {action === 'redirect' || action === 'cname' ? (
            <label className="text-xs text-[var(--muted)] space-y-1">
              {action === 'redirect' ? 'Landing IP' : 'Landing hostname'}
              <input
                className="w-full bg-[var(--bg)] border border-[var(--border)] px-2 py-1.5 text-sm mono text-[var(--text)]"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                disabled={!isAdmin || busy}
                placeholder={action === 'redirect' ? defaultRedirectTarget : 'block.corp.local'}
              />
            </label>
          ) : (
            <div />
          )}
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            disabled={!isAdmin || busy || loading}
            onClick={addOrUpdate}
            className="btn btn-secondary disabled:opacity-50"
          >
            {editName != null ? 'Save changes' : 'Add feed to list'}
          </button>
          {editName != null ? (
            <button
              type="button"
              disabled={!isAdmin || busy || loading}
              onClick={cancelEdit}
              className="btn btn-ghost disabled:opacity-50"
            >
              Cancel
            </button>
          ) : null}
        </div>
      </div>
    </section>
  )
}

function RPZPanel({ initial, onChange }) {
  const defaultRedirectTarget = '139.255.196.196'
  const defaultName = 'trustpositif'
  const defaultSource = 'https://trustpositif.komdigi.go.id/assets/db/domains_isp'
  const [policies, setPolicies] = useState(() => hostsOnlyPolicies(initial?.policies))
  const [axfrPolicies, setAxfrPolicies] = useState(() => axfrOnlyPolicies(initial?.policies))
  const [intervalSec, setIntervalSec] = useState(() => Number(initial?.update_interval) || 0)
  const [updateAt, setUpdateAt] = useState(() => initial?.update_at || '')
  const [axfrIntervalSec, setAxfrIntervalSec] = useState(() =>
    initial?.axfr_update_interval === undefined || initial?.axfr_update_interval === null
      ? 86400
      : Number(initial.axfr_update_interval),
  )
  const [status, setStatus] = useState(initial)
  const [name, setName] = useState(defaultName)
  const [source, setSource] = useState(defaultSource)
  const [action, setAction] = useState('nxdomain')
  const [target, setTarget] = useState('')
  const [editName, setEditName] = useState(null)
  const [err, setErr] = useState('')
  const [ok, setOk] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    setPolicies(hostsOnlyPolicies(initial?.policies))
    setAxfrPolicies(axfrOnlyPolicies(initial?.policies))
    setIntervalSec(Number(initial?.update_interval) || 0)
    setUpdateAt(initial?.update_at || '')
    setAxfrIntervalSec(
      initial?.axfr_update_interval === undefined || initial?.axfr_update_interval === null
        ? 86400
        : Number(initial.axfr_update_interval),
    )
    setStatus(initial)
  }, [initial])

  useEffect(() => {
    if (action === 'redirect' && !target) setTarget(defaultRedirectTarget)
    if (action === 'cname' && target === defaultRedirectTarget) setTarget('')
  }, [action, target])

  useEffect(() => {
    if (!status?.loading) return undefined
    const t = setInterval(() => {
      api
        .rpz()
        .then((r) => {
          setStatus(r)
          setPolicies(hostsOnlyPolicies(r.policies))
          setAxfrPolicies(axfrOnlyPolicies(r.policies))
          onChange?.(r)
          if (!r.loading) {
            setOk(r.error ? '' : `Synced · ${r.entries} entries`)
            if (r.error) setErr(r.error)
          }
        })
        .catch((e) => setErr(e.message))
    }, 2000)
    return () => clearInterval(t)
  }, [status?.loading, onChange])

  const resetForm = () => {
    setName(defaultName)
    setSource(defaultSource)
    setAction('nxdomain')
    setTarget('')
    setEditName(null)
  }

  const startEdit = (p) => {
    setErr('')
    setOk('')
    setEditName(p.name)
    setName(p.name || '')
    setSource(p.source || '')
    setAction(p.action || 'nxdomain')
    setTarget(p.target || '')
  }

  const cancelEdit = () => {
    setErr('')
    setOk('')
    resetForm()
  }

  const addOrUpdate = () => {
    setErr('')
    setOk('')
    const n = name.trim()
    const s = source.trim()
    const t = target.trim()
    if (!n || !s) {
      setErr('Name and source (URL or file path) are required')
      return
    }
    if (action === 'redirect' && !t) {
      setErr(`Redirect needs a landing IP (e.g. ${defaultRedirectTarget})`)
      return
    }
    if (action === 'cname' && !t) {
      setErr('CNAME needs a landing hostname (e.g. block.local)')
      return
    }
    const nextPolicy = {
      name: n,
      source: s,
      format: 'hosts',
      action,
      target: action === 'redirect' || action === 'cname' ? t : '',
    }
    if (editName != null) {
      if (
        policies.some((p) => p.name === n && p.name !== editName) ||
        axfrPolicies.some((p) => p.name === n)
      ) {
        setErr(`Policy "${n}" already exists`)
        return
      }
      setPolicies((list) => list.map((p) => (p.name === editName ? nextPolicy : p)))
      setOk(`Updated "${n}" in list — Save & sync to apply`)
      resetForm()
      return
    }
    if (policies.some((p) => p.name === n) || axfrPolicies.some((p) => p.name === n)) {
      setErr(`Policy "${n}" already exists`)
      return
    }
    setPolicies((p) => [...p, nextPolicy])
  }

  const remove = (n) => {
    setErr('')
    setOk('')
    setPolicies((p) => p.filter((x) => x.name !== n))
    if (editName === n) resetForm()
  }

  const saveSync = async () => {
    setBusy(true)
    setErr('')
    setOk('')
    try {
      const sec = Math.max(0, Number(intervalSec) || 0)
      const axfrSec = Math.max(0, Number(axfrIntervalSec) || 0)
      const at = String(updateAt || '').trim()
      const r = await api.updateRPZ([...policies, ...axfrPolicies], false, sec, axfrSec, false, at, true)
      setStatus(r)
      setPolicies(hostsOnlyPolicies(r.policies))
      setAxfrPolicies(axfrOnlyPolicies(r.policies))
      setIntervalSec(Number(r.update_interval) || 0)
      setUpdateAt(r.update_at || '')
      setAxfrIntervalSec(
        r.axfr_update_interval === undefined || r.axfr_update_interval === null
          ? 86400
          : Number(r.axfr_update_interval),
      )
      onChange?.(r)
      setOk(r.loading ? 'Saved — syncing feeds in background…' : `Saved · ${r.entries} entries`)
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  const resync = async () => {
    setBusy(true)
    setErr('')
    setOk('')
    try {
      const r = await api.reloadRPZ(false, true)
      setStatus(r)
      onChange?.(r)
      setOk('Re-sync started…')
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  const loading = !!status?.loading

  return (
    <section className="panel p-4 space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-medium">RPZ feeds</h2>
          <p className="text-xs text-[var(--muted)] mt-1">
            HTTP URL or local file · hosts format · actions: nxdomain, nodata, pass, redirect (IP), cname.
            Slave AXFR filter feeds are managed under Tools → AXFR.
          </p>
          <p className="text-sm mt-2">
            {status?.enabled ? 'Enabled' : 'Disabled'} · {status?.entries ?? 0} entries
            {loading ? ' · syncing…' : null}
            {status?.from_disk ? ' · from disk' : null}
            {status?.last_loaded ? (
              <span className="text-[var(--muted)]"> · last {status.last_loaded}</span>
            ) : null}
          </p>
        </div>
        <div className="flex gap-2">
          <button
            type="button"
            disabled={busy || loading}
            onClick={resync}
            className="btn btn-secondary"
          >
            Re-sync
          </button>
          <button
            type="button"
            disabled={busy || loading}
            onClick={saveSync}
            className="btn btn-primary"
          >
            {busy ? 'Saving…' : 'Save & sync'}
          </button>
        </div>
      </div>

      {err ? <ErrorBox msg={err} /> : null}
      {ok ? (
        <div className="border border-[var(--accent)]/40 bg-[var(--accent-soft)] text-[var(--accent)] text-sm px-3 py-2">
          {ok}
        </div>
      ) : null}
      {loading ? (
        <div className="border border-[var(--warn)]/40 bg-[var(--warn)]/10 text-[var(--warn)] text-sm px-3 py-2">
          Large feeds (e.g. TrustPositif ~9M domains) can take several minutes. Snapshot is written to
          data/rpz-store for faster restarts.
        </div>
      ) : null}

      <div className="grid gap-3 sm:grid-cols-2 max-w-lg">
        <label className="text-xs text-[var(--muted)] space-y-1 block">
          Hosts interval (seconds, 0 = off · 86400 = 24h)
          <input
            type="number"
            min={0}
            step={60}
            className="w-full bg-[var(--bg)] border border-[var(--border)] px-2 py-1.5 text-sm mono text-[var(--text)]"
            value={intervalSec}
            onChange={(e) => setIntervalSec(e.target.value)}
          />
        </label>
        <label className="text-xs text-[var(--muted)] space-y-1 block">
          Daily at (local HH:MM, empty = interval from start)
          <input
            type="time"
            className="w-full bg-[var(--bg)] border border-[var(--border)] px-2 py-1.5 text-sm mono text-[var(--text)]"
            value={updateAt || ''}
            onChange={(e) => setUpdateAt(e.target.value)}
          />
        </label>
      </div>
      <p className="text-xs text-[var(--muted)]">
        With a daily time set, hosts reload runs at that clock each day (process TZ, e.g. Asia/Jakarta).
        AXFR filter interval is under Tools → AXFR (default 24h · IXFR after first pull).
      </p>

      <ul className="space-y-2 text-sm">
        {policies.length ? (
          policies.map((p) => (
            <li
              key={p.name}
              className={`flex flex-wrap items-start justify-between gap-2 border-b border-[var(--border)]/60 pb-2 ${
                editName === p.name ? 'bg-[var(--accent-soft)] -mx-2 px-2 rounded-[var(--radius)]' : ''
              }`}
            >
              <div className="min-w-0">
                <div className="font-medium">{p.name}</div>
                <div className="mono text-xs text-[var(--muted)] break-all">{p.source}</div>
                <div className="text-xs text-[var(--muted)] mt-0.5">
                  {p.format || 'hosts'} · {p.action || 'nxdomain'}
                  {p.target ? ` → ${p.target}` : ''}
                </div>
              </div>
              <div className="flex gap-1 shrink-0">
                <button
                  type="button"
                  disabled={busy || loading}
                  onClick={() => startEdit(p)}
                  className="btn btn-ghost text-xs disabled:opacity-40"
                >
                  Edit
                </button>
                <button
                  type="button"
                  disabled={busy || loading}
                  onClick={() => remove(p.name)}
                  className="btn btn-ghost text-xs text-[var(--danger)] disabled:opacity-40"
                >
                  Remove
                </button>
              </div>
            </li>
          ))
        ) : (
          <li className="text-sm text-[var(--muted)]">No feeds yet — add one below.</li>
        )}
      </ul>

      <div className="grid gap-2 sm:grid-cols-2">
        <label className="text-xs text-[var(--muted)] space-y-1">
          Name
          <input
            className="w-full bg-[var(--bg)] border border-[var(--border)] px-2 py-1.5 text-sm text-[var(--text)]"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="trustpositif"
          />
        </label>
        <label className="text-xs text-[var(--muted)] space-y-1">
          Action
          <select
            className="w-full bg-[var(--bg)] border border-[var(--border)] px-2 py-1.5 text-sm text-[var(--text)]"
            value={action}
            onChange={(e) => setAction(e.target.value)}
          >
            <option value="nxdomain">nxdomain</option>
            <option value="nodata">nodata</option>
            <option value="pass">pass</option>
            <option value="redirect">redirect (sinkhole IP)</option>
            <option value="cname">cname (landing host)</option>
          </select>
          {action === 'redirect' ? (
            <p className="text-[11px] text-[var(--muted)] leading-relaxed">
              Sinkhole IP breaks many Indonesian banking apps (they treat it as DNS hijack). The
              website still loads. PowerSVX answers NXDOMAIN instead of the landing IP for
              bank-branded names; gambling/porn redirect is unchanged.
            </p>
          ) : null}
        </label>
        {action === 'redirect' || action === 'cname' ? (
          <label className="text-xs text-[var(--muted)] space-y-1 sm:col-span-2">
            {action === 'redirect' ? 'Landing IP' : 'Landing hostname'}
            <input
              className="w-full bg-[var(--bg)] border border-[var(--border)] px-2 py-1.5 text-sm mono text-[var(--text)]"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder={action === 'redirect' ? defaultRedirectTarget : 'block.corp.local'}
            />
          </label>
        ) : null}
        <label className="text-xs text-[var(--muted)] space-y-1 sm:col-span-2">
          Source (HTTPS URL or file path)
          <input
            className="w-full bg-[var(--bg)] border border-[var(--border)] px-2 py-1.5 text-sm mono text-[var(--text)]"
            value={source}
            onChange={(e) => setSource(e.target.value)}
            placeholder="https://…"
          />
        </label>
      </div>
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          disabled={busy || loading}
          onClick={addOrUpdate}
          className="btn btn-secondary"
        >
          {editName != null ? 'Save changes' : 'Add feed to list'}
        </button>
        {editName != null ? (
          <button type="button" disabled={busy || loading} onClick={cancelEdit} className="btn btn-ghost">
            Cancel
          </button>
        ) : null}
      </div>
    </section>
  )
}

function clonePolicies(list) {
  return (list || []).map((p) => ({
    name: p.name || '',
    source: p.source || '',
    format: p.format || 'hosts',
    action: p.action || 'nxdomain',
    target: p.target || '',
    zone: p.zone || '',
    masters: Array.isArray(p.masters) ? [...p.masters] : [],
  }))
}

function hostsOnlyPolicies(list) {
  return clonePolicies(list).filter((p) => (p.format || 'hosts') !== 'axfr')
}

function axfrOnlyPolicies(list) {
  return clonePolicies(list).filter((p) => p.format === 'axfr')
}

function UsersPanel() {
  const { isAdmin, me } = useAuth()
  const [users, setUsers] = useState([])
  const [name, setName] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState('operator')
  const [editing, setEditing] = useState(false)
  const [err, setErr] = useState('')
  const [ok, setOk] = useState('')
  const [busy, setBusy] = useState(false)

  const load = () =>
    api
      .listUsers()
      .then((d) => setUsers(d.users || []))
      .catch((e) => setErr(e.message))

  useEffect(() => {
    if (!isAdmin || me?.auth_type !== 'local') return undefined
    load()
    return undefined
  }, [isAdmin, me?.auth_type])

  if (!isAdmin || me?.auth_type !== 'local') return null

  const resetForm = () => {
    setName('')
    setPassword('')
    setRole('operator')
    setEditing(false)
  }

  const startEdit = (u) => {
    setName(u.name)
    setPassword('')
    setRole(u.role || 'operator')
    setEditing(true)
    setOk('')
    setErr('')
  }

  const save = async (e) => {
    e.preventDefault()
    setBusy(true)
    setErr('')
    setOk('')
    try {
      await api.upsertUser({ name, password, role })
      setOk(editing ? `Updated ${name}` : `Created ${name}`)
      resetForm()
      await load()
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  const remove = async (n) => {
    setErr('')
    try {
      await api.deleteUser(n)
      if (editing && name === n) resetForm()
      await load()
    } catch (ex) {
      setErr(ex.message)
    }
  }

  return (
    <section className="panel p-4 space-y-3">
      <h2 className="text-sm font-medium">Local users</h2>
      <p className="text-xs text-[var(--muted)]">
        Click Edit to change role or password (leave password blank to keep). API tokens stay in TOML.
      </p>
      {err ? <ErrorBox msg={err} /> : null}
      {ok ? (
        <div className="border border-[var(--accent)]/40 bg-[var(--accent-soft)] text-[var(--accent)] text-sm px-3 py-2">
          {ok}
        </div>
      ) : null}
      <ul className="text-sm divide-y divide-[var(--border)]">
        {users.map((u) => (
          <li key={u.name} className="flex justify-between gap-2 py-2 items-center">
            <span className="mono">
              {u.name} <span className="text-[var(--muted)]">· {u.role}</span>
            </span>
            <span className="flex gap-2 shrink-0">
              <button
                type="button"
                className="text-xs text-[var(--accent)] hover:underline"
                onClick={() => startEdit(u)}
              >
                Edit
              </button>
              <button
                type="button"
                className="text-xs text-[var(--muted)] hover:text-[var(--warn)]"
                onClick={() => remove(u.name)}
              >
                Delete
              </button>
            </span>
          </li>
        ))}
      </ul>
      <form onSubmit={save} className="grid grid-cols-1 md:grid-cols-3 gap-2">
        <input
          className="bg-[var(--bg)] border border-[var(--border)] px-2 py-1.5 text-sm"
          placeholder="username"
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
          disabled={editing}
        />
        <input
          type="password"
          className="bg-[var(--bg)] border border-[var(--border)] px-2 py-1.5 text-sm"
          placeholder={editing ? 'new password (optional)' : 'password'}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required={!editing}
        />
        <select
          className="bg-[var(--bg)] border border-[var(--border)] px-2 py-1.5 text-sm"
          value={role}
          onChange={(e) => setRole(e.target.value)}
        >
          <option value="admin">admin</option>
          <option value="operator">operator</option>
          <option value="readonly">readonly</option>
        </select>
        <div className="md:col-span-3 flex flex-wrap gap-2">
          <button
            type="submit"
            disabled={busy}
            className="btn btn-primary"
          >
            {busy ? 'Saving…' : editing ? 'Update user' : 'Add user'}
          </button>
          {editing ? (
            <button type="button" onClick={resetForm} className="border border-[var(--border)] px-4 py-2 text-sm">
              Cancel edit
            </button>
          ) : null}
        </div>
      </form>
    </section>
  )
}

function BackupPanel() {
  const { isAdmin } = useAuth()
  const [err, setErr] = useState('')
  const [ok, setOk] = useState('')
  const [busy, setBusy] = useState(false)
  const fileRef = useRef(null)

  const download = async () => {
    setBusy(true)
    setErr('')
    setOk('')
    try {
      const data = await api.backup()
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `powersvx-backup-${new Date().toISOString().slice(0, 10)}.json`
      a.click()
      URL.revokeObjectURL(url)
      setOk('Backup downloaded')
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  const restore = async (e) => {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file) return
    setBusy(true)
    setErr('')
    setOk('')
    try {
      const text = await file.text()
      const body = JSON.parse(text)
      await api.restoreBackup(body)
      setOk('Backup restored — reload zones if needed')
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="panel p-4 space-y-3">
      <h2 className="text-sm font-medium">Zone backup</h2>
      <p className="text-xs text-[var(--muted)]">
        Export authoritative zones as JSON, or restore from a previous backup. See docs/PRODUCTION.md.
      </p>
      {err ? <ErrorBox msg={err} /> : null}
      {ok ? (
        <div className="border border-[var(--accent)]/40 bg-[var(--accent-soft)] text-[var(--accent)] text-sm px-3 py-2">
          {ok}
        </div>
      ) : null}
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          disabled={busy}
          onClick={download}
          className="btn btn-primary"
        >
          Download backup
        </button>
        <button
          type="button"
          disabled={busy || !isAdmin}
          onClick={() => fileRef.current?.click()}
          className="btn btn-secondary"
        >
          Restore from file
        </button>
        <input ref={fileRef} type="file" accept="application/json,.json" className="hidden" onChange={restore} />
      </div>
      {!isAdmin ? <p className="text-xs text-[var(--muted)]">Restore requires admin</p> : null}
    </section>
  )
}

function ACMEPanel() {
  const [st, setSt] = useState(null)
  const [err, setErr] = useState('')
  const [ok, setOk] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    api.acme().then(setSt).catch((e) => setErr(e.message))
  }, [])

  const obtain = async () => {
    setBusy(true)
    setErr('')
    setOk('')
    try {
      const s = await api.acmeObtain()
      setSt(s)
      setOk('Certificate obtained — point [server.tls] at certs/acme and restart if needed')
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  if (!st) return null
  return (
    <section className="panel p-4 space-y-3">
      <h2 className="text-sm font-medium">ACME DNS-01</h2>
      <p className="text-xs text-[var(--muted)]">
        Issues TLS certs via Let&apos;s Encrypt DNS-01 using this server&apos;s TXT answers.
        Domain must resolve publicly to this PowerSVX.
      </p>
      <dl className="text-sm space-y-1 mono">
        <div className="flex justify-between"><dt className="text-[var(--muted)]">enabled</dt><dd>{String(st.enabled)}</dd></div>
        <div className="flex justify-between"><dt className="text-[var(--muted)]">staging</dt><dd>{String(st.staging)}</dd></div>
        <div className="flex justify-between"><dt className="text-[var(--muted)]">cert</dt><dd>{st.cert_present ? 'present' : 'missing'}</dd></div>
      </dl>
      {err ? <ErrorBox msg={err} /> : null}
      {ok ? (
        <div className="border border-[var(--accent)]/40 bg-[var(--accent-soft)] text-[var(--accent)] text-sm px-3 py-2">
          {ok}
        </div>
      ) : null}
      <button
        type="button"
        disabled={busy || !st.enabled}
        onClick={obtain}
        className="btn btn-primary"
      >
        {busy ? 'Obtaining…' : 'Obtain certificate'}
      </button>
    </section>
  )
}



export default function SettingsPage() {
  return (
    <Settings
      tools={{
        axfr: AxfrSyncPanel,
        acme: ACMEPanel,
        backup: BackupPanel,
        users: UsersPanel,
        rpz: RPZPanel,
      }}
    />
  )
}
