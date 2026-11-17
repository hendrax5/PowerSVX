import { useEffect, useRef, useState } from 'react'
import {
  ArrowsClockwise,
  Broadcast,
  Certificate,
  Check,
  CheckCircle,
  Clock,
  CloudArrowDown,
  CloudArrowUp,
  Copy,
  Database,
  DownloadSimple,
  FileText,
  GlobeSimple,
  Key,
  LockSimple,
  PencilSimple,
  Plus,
  ShieldCheck,
  SlidersHorizontal,
  Trash,
  User,
  UserGear,
  Users,
  WarningCircle,
} from '@phosphor-icons/react'
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
    <div className="space-y-6 max-w-[var(--content-max)]" aria-labelledby="tools-axfr-heading">
      <header className="reveal flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-4 border-b border-[var(--border)]">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="p-1.5 rounded-lg bg-[var(--accent-soft)] text-[var(--accent)]">
              <Broadcast size={20} weight="bold" />
            </span>
            <span className="text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">DNS Zone Transfer</span>
          </div>
          <h2 id="tools-axfr-heading" className="text-2xl font-bold tracking-tight text-[var(--text)]">
            AXFR &amp; IXFR Synchronization
          </h2>
          <p className="text-xs text-[var(--muted)] mt-1.5 max-w-[65ch] leading-relaxed">
            Manage dual-mode zone replication: <span className="font-semibold text-[var(--text)]">Master (Outbound)</span> transfers your local authoritative zones to secondary servers, while <span className="font-semibold text-[var(--text)]">Slave (Inbound)</span> synchronizes the national Komdigi blocklist into RPZ.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-[var(--muted)] bg-[var(--bg-elevated)] border border-[var(--border)] px-3 py-1.5 rounded-[var(--radius)]">
            {zoneCount} {zoneCount === 1 ? 'Authoritative Zone' : 'Authoritative Zones'}
          </span>
        </div>
      </header>

      {err ? <ErrorBox msg={err} /> : null}
      {ok ? (
        <div
          className="border border-[var(--ok)]/40 bg-[var(--ok-soft)] text-[var(--ok)] text-xs font-medium px-4 py-3 rounded-[var(--radius)] flex items-center gap-2 reveal"
          role="status"
        >
          <CheckCircle size={16} weight="bold" />
          <span>{ok}</span>
        </div>
      ) : null}

      <div className="grid grid-cols-1 lg:grid-cols-[1.3fr_1fr] gap-5 items-start">
        {/* Outbound Master Settings */}
        <section className="panel overflow-hidden reveal reveal-delay-1" aria-labelledby="axfr-sources-heading">
          <div className="p-4 border-b border-[var(--border)] bg-[var(--bg-elevated)] flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2.5">
              <span className="w-2.5 h-2.5 rounded-full bg-[var(--accent)]" />
              <div>
                <span className="text-[10px] font-semibold uppercase tracking-wider text-[var(--accent)]">Role: Master</span>
                <h3 id="axfr-sources-heading" className="text-sm font-semibold text-[var(--text)]">
                  Outbound Zone Transfers
                </h3>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <span
                className={`inline-flex items-center gap-1.5 text-xs font-mono px-2.5 py-1 rounded-[var(--radius)] border ${
                  data.enabled
                    ? 'border-[var(--ok)]/40 text-[var(--ok)] bg-[var(--ok-soft)]'
                    : 'border-[var(--border)] text-[var(--muted)] bg-[var(--bg)]'
                }`}
              >
                <span className={`axfr-pulse-dot ${data.enabled ? 'is-on' : ''}`} aria-hidden />
                {data.enabled ? 'ACTIVE' : 'DISABLED'}
              </span>
              <button
                type="button"
                disabled={busy || !isAdmin}
                onClick={toggle}
                className={`btn text-xs min-h-[32px] px-3 py-1 font-medium disabled:opacity-50 ${data.enabled ? 'btn-secondary' : 'btn-primary'}`}
              >
                {data.enabled ? 'Disable' : 'Enable'}
              </button>
              <button
                type="button"
                disabled={busy || !isAdmin || !data.enabled || p.running}
                onClick={syncNow}
                className="btn btn-secondary text-xs min-h-[32px] px-3 py-1 font-medium flex items-center gap-1.5 disabled:opacity-50"
              >
                <Broadcast size={14} />
                <span>{p.running ? 'NOTIFYing…' : 'Send NOTIFY'}</span>
              </button>
            </div>
          </div>

          <div className="p-3.5 border-b border-[var(--border)] text-xs text-[var(--muted)] leading-relaxed bg-[var(--bg-panel)]">
            Authorized secondary nameservers allowed to pull zones via AXFR and receive automated NOTIFY triggers upon serial bump.
          </div>

          <div className="p-3 border-b border-[var(--border)] flex flex-wrap items-center justify-between gap-2 bg-[var(--bg)]/40">
            <span className="text-xs font-medium text-[var(--muted)]">Authorized Secondary Peers</span>
            <button
              type="button"
              disabled={!isAdmin || busy}
              onClick={resetDefaults}
              className="btn btn-ghost text-xs min-h-[28px] px-2 text-[var(--accent)] hover:underline flex items-center gap-1 disabled:opacity-50"
            >
              <ArrowsClockwise size={13} />
              <span>Fill Komdigi Secondary IPs</span>
            </button>
          </div>

          <ul className="divide-y divide-[var(--border)]">
            {draftTargets.length === 0 ? (
              <li className="p-6 text-center text-xs text-[var(--muted)]">
                No secondary IPs configured. Add IP addresses below or use the Komdigi default preset.
              </li>
            ) : (
              draftTargets.map((addr, i) => (
                <li
                  key={addr}
                  className={`flex items-center justify-between gap-3 px-4 py-2.5 axfr-row ${
                    editAddr === addr ? 'bg-[var(--accent-soft)]' : 'hover:bg-[var(--bg-elevated)]/50'
                  }`}
                  style={{ '--index': i }}
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="w-1.5 h-1.5 rounded-full bg-[var(--muted)]" />
                    <span className="mono text-xs font-medium text-[var(--text)] truncate">{addr}</span>
                  </div>
                  <div className="flex gap-1 shrink-0">
                    <button
                      type="button"
                      disabled={!isAdmin || busy}
                      onClick={() => startEditTarget(addr)}
                      className="btn btn-ghost text-xs min-h-[28px] px-2 text-[var(--muted)] hover:text-[var(--text)] disabled:opacity-40"
                    >
                      <PencilSimple size={13} />
                      <span className="sr-only">Edit</span>
                    </button>
                    <button
                      type="button"
                      disabled={!isAdmin || busy}
                      onClick={() => removeTarget(addr)}
                      className="btn btn-ghost text-xs min-h-[28px] px-2 text-[var(--danger)] hover:bg-[var(--danger)]/10 disabled:opacity-40"
                    >
                      <Trash size={13} />
                      <span className="sr-only">Remove</span>
                    </button>
                  </div>
                </li>
              ))
            )}
          </ul>

          <div className="p-3 border-t border-[var(--border)] bg-[var(--bg-elevated)]/60 flex flex-col sm:flex-row gap-2">
            <div className="relative flex-1">
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
                placeholder="e.g. 182.23.79.202 or 10.0.0.5:53"
                className="w-full mono text-xs input min-h-[36px]"
              />
            </div>
            <div className="flex gap-2 shrink-0">
              <button
                type="button"
                disabled={!isAdmin || busy || !newTarget.trim()}
                onClick={addOrUpdateTarget}
                className="btn btn-secondary text-xs min-h-[36px] px-3 disabled:opacity-50 flex items-center gap-1.5"
              >
                <Plus size={14} weight="bold" />
                <span>{editAddr != null ? 'Update' : 'Add'}</span>
              </button>
              {editAddr != null ? (
                <button
                  type="button"
                  disabled={!isAdmin || busy}
                  onClick={cancelEditTarget}
                  className="btn btn-ghost text-xs min-h-[36px] px-2.5 disabled:opacity-50"
                >
                  Cancel
                </button>
              ) : null}
              <button
                type="button"
                disabled={!isAdmin || busy || !targetsDirty}
                onClick={saveTargets}
                className="btn btn-primary text-xs min-h-[36px] px-4 font-semibold disabled:opacity-50"
              >
                Save Sources
              </button>
            </div>
          </div>
        </section>

        {/* Sync Progress & Telemetry */}
        <section className="panel overflow-hidden reveal reveal-delay-2" aria-labelledby="axfr-progress-heading">
          <div className="p-4 border-b border-[var(--border)] bg-[var(--bg-elevated)] flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="p-1 rounded bg-[var(--bg)] border border-[var(--border)] text-[var(--muted)]">
                <SlidersHorizontal size={16} />
              </span>
              <div>
                <span className="text-[10px] font-semibold uppercase tracking-wider text-[var(--muted)]">Outbound Queue</span>
                <h3 id="axfr-progress-heading" className="text-sm font-semibold text-[var(--text)]">
                  Replication Status
                </h3>
              </div>
            </div>
            <span className="text-xs font-mono font-bold text-[var(--text)]">{pct}%</span>
          </div>

          <div className="p-5 space-y-4">
            <div>
              <div className="flex items-center justify-between text-xs mb-1.5">
                <span className="text-[var(--muted)] font-medium">Replication Cycle</span>
                <span className="font-mono text-xs text-[var(--text)]">
                  {p.done || 0} / {p.total || 0} zones {zoneCount ? `(${zoneCount} tracked)` : ''}
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
            </div>

            <div className="grid grid-cols-2 gap-3 pt-2 border-t border-[var(--border)]">
              <div className="p-2.5 rounded-[var(--radius)] bg-[var(--bg)] border border-[var(--border)]">
                <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold block">Phase</span>
                <span className="font-mono text-xs font-semibold text-[var(--text)] mt-0.5 block truncate">
                  {p.phase || (p.running ? 'Running…' : 'Idle')}
                </span>
              </div>
              <div className="p-2.5 rounded-[var(--radius)] bg-[var(--bg)] border border-[var(--border)]">
                <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold block">Current Zone</span>
                <span className="font-mono text-xs font-semibold text-[var(--text)] mt-0.5 block truncate">
                  {p.current_zone || '—'}
                </span>
              </div>
              <div className="col-span-2 p-2.5 rounded-[var(--radius)] bg-[var(--bg)] border border-[var(--border)]">
                <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold block">Last Completed</span>
                <span className="font-mono text-xs text-[var(--muted)] mt-0.5 block truncate">
                  {p.finished_at || 'Never run or completed'}
                </span>
              </div>
            </div>

            {p.last_error ? (
              <div className="p-2.5 rounded-[var(--radius)] bg-[var(--danger)]/10 border border-[var(--danger)]/30 text-[var(--danger)] text-xs flex items-center gap-1.5">
                <WarningCircle size={14} weight="bold" />
                <span>{p.last_error}</span>
              </div>
            ) : null}
          </div>
        </section>
      </div>

      {/* Authoritative Zones Status Table */}
      <section className="panel overflow-hidden reveal reveal-delay-3" aria-labelledby="axfr-zones-heading">
        <div className="p-4 border-b border-[var(--border)] bg-[var(--bg-elevated)] flex flex-wrap items-center justify-between gap-3">
          <div>
            <span className="text-[10px] font-semibold uppercase tracking-wider text-[var(--muted)]">Status Directory</span>
            <h3 id="axfr-zones-heading" className="text-sm font-semibold text-[var(--text)]">
              Authoritative Zones State
            </h3>
          </div>
          <span className="text-xs text-[var(--muted)]">Per-source NOTIFY / SOA / transfer state</span>
        </div>

        {(data.zones || []).length === 0 ? (
          <div className="p-8 text-center">
            <p className="text-sm font-semibold text-[var(--text)]">No authoritative zones configured</p>
            <p className="text-xs text-[var(--muted)] mt-1.5 max-w-sm mx-auto leading-relaxed">
              Create an authoritative DNS zone in DNS Management first, then configure secondary transfer peers.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-[11px] font-semibold text-[var(--muted)] border-b border-[var(--border)] bg-[var(--bg)]/50">
                  <th className="px-4 py-2.5">Zone Name</th>
                  <th className="px-4 py-2.5">SOA Serial</th>
                  <th className="px-4 py-2.5">Secondary Peer</th>
                  <th className="px-4 py-2.5">Transfer Status</th>
                  <th className="px-4 py-2.5">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border)]">
                {(data.zones || []).flatMap((z) =>
                  (z.targets || []).map((t, i) => (
                    <tr key={`${z.zone}-${t.addr}`} className="hover:bg-[var(--bg-elevated)]/40 axfr-row">
                      <td className="px-4 py-2.5 font-mono font-medium text-[var(--text)]">{i === 0 ? z.zone : ''}</td>
                      <td className="px-4 py-2.5 font-mono text-[var(--muted)]">{i === 0 ? z.serial : ''}</td>
                      <td className="px-4 py-2.5 font-mono text-[var(--text)]">{t.addr}</td>
                      <td className="px-4 py-2.5">
                        <span className={`inline-flex items-center gap-1 font-mono font-semibold uppercase text-[10px] ${statusTone(t.status)}`}>
                          <span className="w-1.5 h-1.5 rounded-full bg-current" />
                          {t.status}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 font-mono text-[11px] text-[var(--muted)]">
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
          <div className="p-3 bg-[var(--bg)]/50 border-t border-[var(--border)] text-[11px] text-[var(--muted)] leading-relaxed">
            {data.note}
          </div>
        ) : null}
      </section>

      {/* Slave Filter Feeds (Kominfo Inbound RPZ sync) */}
      <AxfrFilterFeedsPanel isAdmin={isAdmin} />

      {/* Slave Authoritative Zones (RFC 1995 IXFR / AXFR / TSIG / SOA) */}
      <SecondaryZonesPanel isAdmin={isAdmin} />
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
  const [tsigKey, setTsigKey] = useState('')
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
    setTsigKey('')
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
    setTsigKey(p.tsig_key || '')
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
      tsig_key: tsigKey.trim() || undefined,
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
      {/* Header Banner */}
      <div className="p-4 border-b border-[var(--border)] bg-[var(--bg-elevated)] flex flex-wrap items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="p-1 rounded bg-[var(--accent-soft)] text-[var(--accent)]">
              <ShieldCheck size={18} weight="bold" />
            </span>
            <span className="text-[10px] font-semibold uppercase tracking-wider text-[var(--accent)]">
              Role: Slave · National Filtering Dataplane
            </span>
          </div>
          <h3 id="axfr-filter-heading" className="text-base font-bold text-[var(--text)] tracking-tight">
            Kominfo &amp; TrustPositif Filter Feeds
          </h3>
          <p className="text-xs text-[var(--muted)] leading-relaxed max-w-[62ch]">
            Pulls authoritative blocklists (<span className="mono text-[var(--text)] font-medium">trustpositifkominfo</span>) directly into PowerSVX zero-copy CDB engine. First start bootstraps from seed data; continuous updates use incremental IXFR.
          </p>
          <div className="pt-1 flex flex-wrap items-center gap-2 text-xs">
            <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-[var(--radius)] text-xs font-mono font-medium border ${toneClass}`}>
              <span className="w-1.5 h-1.5 rounded-full bg-current" />
              {syncState.label}
            </span>
            {dirty ? (
              <span className="inline-flex items-center px-2 py-0.5 rounded-[var(--radius)] text-[11px] font-semibold uppercase tracking-wide border border-amber-500/40 text-amber-800 bg-amber-500/10">
                Unsaved Changes
              </span>
            ) : null}
            <span className="text-xs font-mono font-semibold text-[var(--text)]">
              {status ? `${Number(status.entries ?? 0).toLocaleString()} RPZ rules active in CDB` : 'Loading rules…'}
            </span>
            {status?.last_loaded ? (
              <span className="text-xs text-[var(--muted)]">· engine {status.last_loaded}</span>
            ) : null}
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            disabled={!isAdmin || busy || loading}
            onClick={resync}
            className="btn btn-secondary text-xs min-h-[36px] px-3 font-medium flex items-center gap-1.5 disabled:opacity-50"
          >
            <ArrowsClockwise size={14} className={loading ? 'animate-spin' : ''} />
            <span>Re-sync</span>
          </button>
          <button
            type="button"
            disabled={!isAdmin || busy || loading}
            onClick={saveSync}
            className="btn btn-primary text-xs min-h-[36px] px-4 font-semibold disabled:opacity-50"
          >
            {busy ? 'Saving…' : loading ? 'Syncing…' : 'Save & Sync Filters'}
          </button>
        </div>
      </div>

      <div className="p-4 space-y-4">
        {/* Sync Status Callout */}
        <div
          className={`border rounded-[var(--radius)] text-xs p-3.5 flex items-start gap-2.5 ${
            syncState.tone === 'ok'
              ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-900'
              : syncState.tone === 'danger'
                ? 'border-[var(--danger)]/30 bg-[var(--danger)]/10 text-[var(--danger)]'
                : syncState.tone === 'warn'
                  ? 'border-amber-500/30 bg-amber-500/10 text-amber-900'
                  : 'border-[var(--border)] text-[var(--muted)] bg-[var(--bg)]'
          }`}
          role="status"
        >
          {syncState.tone === 'ok' ? (
            <CheckCircle size={18} weight="bold" className="shrink-0 text-emerald-700 mt-0.5" />
          ) : syncState.tone === 'danger' ? (
            <WarningCircle size={18} weight="bold" className="shrink-0 text-[var(--danger)] mt-0.5" />
          ) : (
            <ArrowsClockwise size={18} weight="bold" className="shrink-0 text-amber-800 mt-0.5" />
          )}
          <div className="leading-relaxed">
            {loading ? (
              <p className="font-medium">Sync in progress — downloading and compiling zones to CDB. Real-time updates occur every few seconds.</p>
            ) : anyFailed ? (
              <p>
                <strong className="font-semibold">Filter sync failed:</strong>{' '}
                {status?.error || err || 'Check logs below.'}{' '}
                {Number(status?.entries ?? 0) > 0
                  ? `DNS resolve path remains active with last good CDB snapshot (${Number(status.entries).toLocaleString()} entries).`
                  : 'Verify upstream Komdigi master IPs connectivity.'}
              </p>
            ) : anySynced ? (
              <p>
                <strong className="font-semibold">Last sync verified:</strong>{' '}
                {feedStates
                  .filter((f) => f.st?.updated_at)
                  .map((f) => `${f.policy.name} (Serial ${f.st.serial}, ${modeLabel(f.st.last_mode)}) at ${f.st.updated_at}`)
                  .join(' · ') || 'CDB engine synced and healthy.'}
              </p>
            ) : policies.length ? (
              <p>Feeds configured in draft. Click <strong>Save &amp; Sync Filters</strong> to pull authoritative zone transfer.</p>
            ) : (
              <p>No filter feeds configured.</p>
            )}
          </div>
        </div>

        {err || (status?.error && !(Number(status?.entries ?? 0) > 0)) ? (
          <ErrorBox msg={err || `Engine error: ${status.error}`} />
        ) : null}
        {status?.error && Number(status?.entries ?? 0) > 0 && !err ? (
          <div className="border border-amber-500/40 bg-amber-500/10 text-amber-900 text-xs px-3.5 py-2.5 rounded-[var(--radius)]">
            Warning: {status.error} — serving last-good filter CDB ({Number(status.entries).toLocaleString()}{' '}
            entries). Resolving operations unaffected.
          </div>
        ) : null}
        {ok ? (
          <div className="border border-[var(--ok)]/40 bg-[var(--ok-soft)] text-[var(--ok)] text-xs px-3.5 py-2.5 rounded-[var(--radius)] font-medium">
            {ok}
          </div>
        ) : null}

        {/* Schedule & Auto-refresh Config Card */}
        <div className="p-3.5 rounded-[var(--radius)] bg-[var(--bg-panel)] border border-[var(--border)] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <label htmlFor="axfr-interval-input" className="text-xs font-semibold text-[var(--text)] block">
              AXFR Auto-Refresh Interval
            </label>
            <p className="text-[11px] text-[var(--muted)] mt-0.5">
              Frequency for SOA checks and incremental IXFR sync. 0 disables automatic sync (default: 86400s = 24h).
            </p>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <input
              id="axfr-interval-input"
              type="number"
              min={0}
              step={3600}
              className="w-32 bg-[var(--bg)] border border-[var(--border)] px-3 py-1.5 text-xs mono text-[var(--text)] rounded-[var(--radius)]"
              value={axfrIntervalSec}
              onChange={(e) => setAxfrIntervalSec(e.target.value)}
              disabled={!isAdmin || busy}
            />
            <span className="text-xs text-[var(--muted)]">seconds</span>
          </div>
        </div>

        {/* Feeds List Cards */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-[var(--muted)]">
              Active Inbound Feeds ({policies.length})
            </h4>
          </div>

          <div className="space-y-2.5">
            {policies.length ? (
              policies.map((p) => {
                const st = axfrFeeds[p.name]
                const rowTone = !st
                  ? 'text-[var(--muted)]'
                  : st.ok === false || st.last_mode === 'failed'
                    ? 'text-[var(--danger)]'
                    : 'text-emerald-700'
                return (
                  <div
                    key={p.name}
                    className={`p-3.5 rounded-[var(--radius)] border border-[var(--border)] bg-[var(--bg-elevated)] flex flex-col md:flex-row md:items-center justify-between gap-3 transition-colors ${
                      editName === p.name ? 'border-[var(--accent)] ring-1 ring-[var(--accent)]' : ''
                    }`}
                  >
                    <div className="space-y-1.5 min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-semibold text-xs text-[var(--text)]">{p.name}</span>
                        <span
                          className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                            p.enabled === false
                              ? 'border-[var(--border)] text-[var(--muted)] bg-[var(--bg)]'
                              : 'border-emerald-500/30 text-emerald-700 bg-emerald-500/10'
                          }`}
                        >
                          {p.enabled === false ? 'DISABLED' : 'ENABLED'}
                        </span>
                        <span className={`text-[10px] font-mono font-medium px-2 py-0.5 rounded border border-[var(--border)] bg-[var(--bg)] ${rowTone}`}>
                          {st ? modeLabel(st.last_mode) : 'NEVER SYNCED'}
                        </span>
                        <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-[var(--accent-soft)] text-[var(--accent)] border border-[var(--accent)]/30">
                          {p.action || 'nxdomain'} {p.target ? `→ ${p.target}` : ''}
                        </span>
                      </div>
                      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-[var(--muted)] mono">
                        <span>Zone: <strong className="text-[var(--text)]">{p.zone || p.source}</strong></span>
                        <span>Masters: <strong className="text-[var(--text)]">{(p.masters || []).join(', ') || '—'}</strong></span>
                        {p.tsig_key ? (
                          <span className="inline-flex items-center gap-1 text-[11px] text-[var(--accent)]">
                            <Key size={11} weight="bold" />
                            <span>TSIG: {p.tsig_key}</span>
                          </span>
                        ) : null}
                      </div>
                      {st ? (
                        <div className={`text-[11px] mono ${rowTone}`}>
                          Serial: {st.serial ?? 0}
                          {st.last_master ? ` · via ${st.last_master}` : ''}
                          {st.updated_at ? ` · ${st.updated_at}` : ''}
                          {st.last_error ? ` · ${st.last_error}` : ''}
                        </div>
                      ) : (
                        <div className="text-[11px] text-[var(--muted)]">Pending first sync</div>
                      )}
                    </div>

                    <div className="flex items-center gap-2 shrink-0 pt-2 md:pt-0 border-t md:border-t-0 border-[var(--border)]">
                      <button
                        type="button"
                        disabled={!isAdmin || busy || loading}
                        onClick={() => toggleEnabled(p.name)}
                        className="btn btn-secondary text-xs min-h-[30px] px-2.5 disabled:opacity-40"
                      >
                        {p.enabled === false ? 'Enable' : 'Disable'}
                      </button>
                      <button
                        type="button"
                        disabled={!isAdmin || busy || loading}
                        onClick={() => startEdit(p)}
                        className="btn btn-ghost text-xs min-h-[30px] px-2.5 text-[var(--muted)] hover:text-[var(--text)] disabled:opacity-40"
                      >
                        <PencilSimple size={13} className="mr-1 inline" />
                        <span>Edit</span>
                      </button>
                      <button
                        type="button"
                        disabled={!isAdmin || busy || loading}
                        onClick={() => remove(p.name)}
                        className="btn btn-ghost text-xs min-h-[30px] px-2.5 text-[var(--danger)] hover:bg-[var(--danger)]/10 disabled:opacity-40"
                      >
                        <Trash size={13} className="mr-1 inline" />
                        <span>Remove</span>
                      </button>
                    </div>
                  </div>
                )
              })
            ) : (
              <div className="p-6 text-center text-xs text-[var(--muted)] border border-dashed border-[var(--border)] rounded-[var(--radius)]">
                No slave filter feeds configured. Add the official Kominfo AXFR feed below.
              </div>
            )}
          </div>
        </div>

        {/* Sync Telemetry Log */}
        <div className="border border-[var(--border)] rounded-[var(--radius)] overflow-hidden bg-[var(--bg)]">
          <div className="px-3.5 py-2.5 border-b border-[var(--border)] bg-[var(--bg-elevated)] text-xs font-semibold flex items-center justify-between gap-2">
            <span className="flex items-center gap-1.5 text-[var(--text)]">
              <Database size={14} />
              <span>Dataplane Transfer Log</span>
            </span>
            <span className="text-[11px] text-[var(--muted)] font-mono font-normal">
              Latest {Math.min(axfrEvents.length, 20)} events
            </span>
          </div>
          {axfrEvents.length ? (
            <ul className="max-h-44 overflow-y-auto divide-y divide-[var(--border)]/40 text-xs mono p-1">
              {[...axfrEvents].reverse().slice(0, 20).map((ev, i) => (
                <li
                  key={`${ev.time}-${i}`}
                  className={`px-3 py-1.5 flex items-start gap-2 ${
                    ev.level === 'error' ? 'text-[var(--danger)]' : 'text-[var(--muted)]'
                  }`}
                >
                  <span className="text-[var(--text)]/60 shrink-0 font-medium">{ev.time || '—'}</span>
                  {ev.feed ? <span className="text-[var(--accent)] font-semibold shrink-0">[{ev.feed}]</span> : null}
                  <span className="break-all">{ev.message}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="px-4 py-6 text-center text-xs text-[var(--muted)]">
              No recent sync events logged. Trigger a Re-sync or Save &amp; Sync to inspect live transfer details.
            </p>
          )}
        </div>

        {/* Add/Edit Feed Form */}
        <div className="p-4 rounded-[var(--radius)] border border-[var(--border)] bg-[var(--bg-panel)] space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-[var(--border)]">
            <h4 className="text-xs font-bold text-[var(--text)] uppercase tracking-wider">
              {editName != null ? `Edit Feed: ${editName}` : 'Add Inbound Filter Feed'}
            </h4>
            {editName != null ? (
              <span className="text-[11px] text-[var(--warn)] font-medium">Drafting changes</span>
            ) : null}
          </div>

          <div className="grid gap-3 sm:grid-cols-2">
            <label className="text-xs font-medium text-[var(--muted)] space-y-1 block">
              <span>Feed Identifier</span>
              <input
                className="w-full input text-xs font-mono"
                value={name}
                onChange={(e) => setName(e.target.value)}
                disabled={!isAdmin || busy}
                placeholder="e.g. trustpositif-axfr"
              />
            </label>
            <label className="text-xs font-medium text-[var(--muted)] space-y-1 block">
              <span>Authoritative Zone Name</span>
              <input
                className="w-full input text-xs font-mono"
                value={zone}
                onChange={(e) => setZone(e.target.value)}
                disabled={!isAdmin || busy}
                placeholder="trustpositifkominfo"
              />
            </label>
            <label className="text-xs font-medium text-[var(--muted)] space-y-1 block sm:col-span-2">
              <span>Master DNS Servers (one per line, host:port)</span>
              <textarea
                className="w-full input text-xs font-mono min-h-[4rem]"
                value={mastersText}
                onChange={(e) => setMastersText(e.target.value)}
                disabled={!isAdmin || busy}
                placeholder={DEFAULT_AXFR_FILTER_MASTERS.join('\n')}
              />
            </label>
            <label className="text-xs font-medium text-[var(--muted)] space-y-1 block">
              <span>TSIG Key Name (optional RFC 2845 auth)</span>
              <input
                list="rpz-tsig-keys-list"
                className="w-full input text-xs font-mono"
                value={tsigKey}
                onChange={(e) => setTsigKey(e.target.value)}
                disabled={!isAdmin || busy}
                placeholder="Leave blank if master allows IP ACL"
              />
              <datalist id="rpz-tsig-keys-list">
                {(status?.tsig_keys || []).map((k) => (
                  <option key={k} value={k} />
                ))}
              </datalist>
            </label>
            <label className="text-xs font-medium text-[var(--muted)] space-y-1 block">
              <span>Filter Policy Action</span>
              <select
                className="w-full input text-xs"
                value={action}
                onChange={(e) => setAction(e.target.value)}
                disabled={!isAdmin || busy}
              >
                <option value="nxdomain">NXDOMAIN (Recommended · Zero banking disruption)</option>
                <option value="nodata">NODATA</option>
                <option value="pass">PASS (Bypass rule)</option>
                <option value="redirect">REDIRECT (Sinkhole IP)</option>
                <option value="cname">CNAME (Landing hostname)</option>
              </select>
              {action === 'redirect' ? (
                <p className="text-[11px] text-[var(--warn)] leading-relaxed pt-1">
                  Sinkhole redirection may trigger security warnings in Indonesian mobile banking apps. PowerSVX automatically maintains NXDOMAIN protection for sensitive financial services.
                </p>
              ) : null}
            </label>
            {action === 'redirect' || action === 'cname' ? (
              <label className="text-xs font-medium text-[var(--muted)] space-y-1 block sm:col-span-2">
                <span>{action === 'redirect' ? 'Sinkhole Landing IP' : 'Landing Hostname'}</span>
                <input
                  className="w-full input text-xs font-mono"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  disabled={!isAdmin || busy}
                  placeholder={action === 'redirect' ? defaultRedirectTarget : 'block.local'}
                />
              </label>
            ) : null}
          </div>

          <div className="pt-2 flex items-center gap-2">
            <button
              type="button"
              disabled={!isAdmin || busy || loading}
              onClick={addOrUpdate}
              className="btn btn-secondary text-xs min-h-[34px] px-4 font-medium disabled:opacity-50"
            >
              {editName != null ? 'Update Feed' : 'Add Feed to Draft'}
            </button>
            {editName != null ? (
              <button
                type="button"
                disabled={!isAdmin || busy || loading}
                onClick={cancelEdit}
                className="btn btn-ghost text-xs min-h-[34px] px-3 disabled:opacity-50"
              >
                Cancel
              </button>
            ) : null}
          </div>
        </div>
      </div>
    </section>
  )
}

function SecondaryZonesPanel({ isAdmin }) {
  const [zones, setZones] = useState([])
  const [tsigKeys, setTsigKeys] = useState([])
  const [name, setName] = useState('')
  const [mastersText, setMastersText] = useState('')
  const [tsigKey, setTsigKey] = useState('')
  const [refreshSec, setRefreshSec] = useState(0)
  const [editZone, setEditZone] = useState(null)
  const [syncingZone, setSyncingZone] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [ok, setOk] = useState('')

  const applyPayload = (r) => {
    setZones(r?.zones || [])
    setTsigKeys(r?.tsig_keys || [])
  }

  const load = () =>
    api
      .secondary()
      .then(applyPayload)
      .catch((e) => setErr(e.message))

  useEffect(() => {
    load()
  }, [])

  const parseMasters = (text) =>
    text
      .split(/[\n,]+/)
      .map((s) => s.trim())
      .filter(Boolean)
      .map((s) => (s.includes(':') ? s : `${s}:53`))

  const resetForm = () => {
    setName('')
    setMastersText('')
    setTsigKey('')
    setRefreshSec(0)
    setEditZone(null)
  }

  const startEdit = (z) => {
    setErr('')
    setOk('')
    setEditZone(z.name)
    setName(z.name || '')
    setMastersText((z.masters || []).join('\n'))
    setTsigKey(z.tsig_key || '')
    setRefreshSec(Number(z.refresh_seconds) || 0)
  }

  const submitForm = async (e) => {
    e.preventDefault()
    setErr('')
    setOk('')
    const zName = name.trim()
    const masters = parseMasters(mastersText)
    if (!zName) {
      setErr('Zone name is required')
      return
    }
    if (!masters.length) {
      setErr('At least one primary master server (IP or host:port) is required')
      return
    }
    const payload = {
      name: zName,
      masters,
      tsig_key: tsigKey.trim() || undefined,
      refresh_seconds: Math.max(0, Number(refreshSec) || 0),
    }
    setBusy(true)
    try {
      let r
      if (editZone) {
        r = await api.updateSecondary(editZone, payload)
        setOk(`Updated slave zone ${editZone}`)
      } else {
        r = await api.upsertSecondary(payload)
        setOk(`Added slave zone ${r?.zone || zName} — initial SOA/AXFR sync started`)
      }
      applyPayload(r)
      resetForm()
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  const handleSync = async (zName) => {
    setErr('')
    setOk('')
    setSyncingZone(zName)
    try {
      const r = await api.transferSecondary(zName)
      applyPayload(r)
      const updated = (r?.zones || []).find((z) => z.name === zName)
      setOk(
        `Sync ${zName}: mode=${updated?.last_mode || 'ok'} · serial=${updated?.serial || 0} · records=${updated?.record_count ?? 0}`,
      )
    } catch (ex) {
      setErr(`Sync failed for ${zName}: ${ex.message}`)
      load()
    } finally {
      setSyncingZone('')
    }
  }

  const handleDelete = async (zName) => {
    if (!window.confirm(`Remove secondary zone "${zName}" and delete its local replicated records?`)) {
      return
    }
    setErr('')
    setOk('')
    setBusy(true)
    try {
      await api.deleteSecondary(zName)
      setZones((prev) => prev.filter((z) => z.name !== zName))
      if (editZone === zName) resetForm()
      setOk(`Deleted secondary zone ${zName}`)
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  const modeBadgeTone = (mode) => {
    switch (mode) {
      case 'ixfr':
      case 'axfr':
        return 'border-emerald-500/30 text-emerald-700 bg-emerald-500/10'
      case 'skipped':
        return 'border-sky-500/30 text-sky-700 bg-sky-500/10'
      case 'failed':
        return 'border-[var(--danger)]/30 text-[var(--danger)] bg-[var(--danger)]/10'
      default:
        return 'border-[var(--border)] text-[var(--muted)] bg-[var(--bg)]'
    }
  }

  return (
    <section className="panel overflow-hidden reveal reveal-delay-3" aria-labelledby="secondary-zones-heading">
      <div className="p-4 border-b border-[var(--border)] bg-[var(--bg-elevated)] flex flex-wrap items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="p-1 rounded bg-[var(--accent-soft)] text-[var(--accent)]">
              <GlobeSimple size={18} weight="bold" />
            </span>
            <span className="text-[10px] font-semibold uppercase tracking-wider text-[var(--accent)]">
              Role: Slave · Authoritative Zone Replication
            </span>
          </div>
          <h3 id="secondary-zones-heading" className="text-base font-bold text-[var(--text)] tracking-tight">
            Secondary (Slave) Authoritative Zones
          </h3>
          <p className="text-xs text-[var(--muted)] leading-relaxed max-w-[66ch]">
            Replicates upstream authoritative zones into PowerSVX via RFC 1995 <span className="mono text-[var(--text)]">IXFR</span> / <span className="mono text-[var(--text)]">AXFR</span>,
            honors master <span className="mono text-[var(--text)]">SOA Refresh/Retry</span> timers &amp; signed <span className="mono text-[var(--text)]">NOTIFY</span>, and persists zone records to disk across restarts.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            disabled={busy}
            onClick={load}
            className="btn btn-secondary text-xs min-h-[34px] px-3 font-medium flex items-center gap-1.5"
          >
            <ArrowsClockwise size={14} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      <div className="p-4 space-y-4">
        {err ? <ErrorBox msg={err} /> : null}
        {ok ? (
          <div className="border border-[var(--ok)]/40 bg-[var(--ok-soft)] text-[var(--ok)] text-xs px-3.5 py-2.5 rounded-[var(--radius)] font-medium">
            {ok}
          </div>
        ) : null}

        <div className="space-y-2.5">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-[var(--muted)]">
            Replicated Slave Zones ({zones.length})
          </h4>
          {zones.length ? (
            zones.map((z) => {
              const isSyncing = syncingZone === z.name
              return (
                <div
                  key={z.name}
                  className={`p-3.5 rounded-[var(--radius)] border border-[var(--border)] bg-[var(--bg-elevated)] flex flex-col md:flex-row md:items-center justify-between gap-3 ${
                    editZone === z.name ? 'border-[var(--accent)] ring-1 ring-[var(--accent)]' : ''
                  }`}
                >
                  <div className="space-y-1.5 min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono font-semibold text-xs text-[var(--text)]">{z.name}</span>
                      <span className={`text-[10px] font-mono font-semibold uppercase px-2 py-0.5 rounded border ${modeBadgeTone(z.last_mode)}`}>
                        {z.last_mode || 'pending'}
                      </span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-[var(--border)] bg-[var(--bg)] text-[var(--text)]">
                        Serial {z.serial ?? 0}
                      </span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-[var(--border)] bg-[var(--bg)] text-[var(--muted)]">
                        {z.record_count ?? 0} RRs
                      </span>
                      {z.tsig_key ? (
                        <span className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded border border-[var(--accent)]/30 bg-[var(--accent-soft)] text-[var(--accent)]">
                          <Key size={10} weight="bold" />
                          <span>TSIG: {z.tsig_key}</span>
                        </span>
                      ) : null}
                    </div>
                    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-[var(--muted)] mono">
                      <span>Masters: <strong className="text-[var(--text)]">{(z.masters || []).join(', ')}</strong></span>
                      <span>
                        Refresh:{' '}
                        <strong className="text-[var(--text)]">
                          {z.refresh_seconds > 0
                            ? `${z.refresh_seconds}s (override)`
                            : z.soa_refresh
                              ? `${z.soa_refresh}s (SOA)`
                              : '3600s (default)'}
                        </strong>
                      </span>
                      {z.soa_retry ? <span>Retry: {z.soa_retry}s</span> : null}
                      {z.soa_expire ? <span>Expire: {z.soa_expire}s</span> : null}
                    </div>
                    <div className={`text-[11px] mono ${z.last_error ? 'text-[var(--danger)]' : 'text-[var(--muted)]'}`}>
                      {z.last_master ? `via ${z.last_master}` : 'not pulled yet'}
                      {z.last_check ? ` · checked ${z.last_check}` : ''}
                      {z.last_pull ? ` · synced ${z.last_pull}` : ''}
                      {z.last_error ? ` · error: ${z.last_error}` : ''}
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0 pt-2 md:pt-0 border-t md:border-t-0 border-[var(--border)]">
                    <button
                      type="button"
                      disabled={!isAdmin || busy || isSyncing}
                      onClick={() => handleSync(z.name)}
                      className="btn btn-secondary text-xs min-h-[30px] px-2.5 flex items-center gap-1 disabled:opacity-40"
                    >
                      <ArrowsClockwise size={13} className={isSyncing ? 'animate-spin' : ''} />
                      <span>{isSyncing ? 'Syncing…' : 'Sync Now'}</span>
                    </button>
                    <button
                      type="button"
                      disabled={!isAdmin || busy || isSyncing}
                      onClick={() => startEdit(z)}
                      className="btn btn-ghost text-xs min-h-[30px] px-2.5 text-[var(--muted)] hover:text-[var(--text)] disabled:opacity-40"
                    >
                      <PencilSimple size={13} className="mr-1 inline" />
                      <span>Edit</span>
                    </button>
                    <button
                      type="button"
                      disabled={!isAdmin || busy || isSyncing}
                      onClick={() => handleDelete(z.name)}
                      className="btn btn-ghost text-xs min-h-[30px] px-2.5 text-[var(--danger)] hover:bg-[var(--danger)]/10 disabled:opacity-40"
                    >
                      <Trash size={13} className="mr-1 inline" />
                      <span>Delete</span>
                    </button>
                  </div>
                </div>
              )
            })
          ) : (
            <div className="p-6 text-center text-xs text-[var(--muted)] border border-dashed border-[var(--border)] rounded-[var(--radius)]">
              No secondary authoritative zones configured. Add a slave zone below to replicate records from an upstream primary server.
            </div>
          )}
        </div>

        <form onSubmit={submitForm} className="p-4 rounded-[var(--radius)] border border-[var(--border)] bg-[var(--bg-panel)] space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-[var(--border)]">
            <h4 className="text-xs font-bold text-[var(--text)] uppercase tracking-wider">
              {editZone ? `Edit Slave Zone: ${editZone}` : 'Add Secondary (Slave) Zone'}
            </h4>
            {editZone ? (
              <button
                type="button"
                onClick={resetForm}
                className="text-[11px] text-[var(--muted)] hover:text-[var(--text)] underline"
              >
                Cancel Edit
              </button>
            ) : null}
          </div>

          <div className="grid gap-3 sm:grid-cols-2">
            <label className="text-xs font-medium text-[var(--muted)] space-y-1 block">
              <span>Zone FQDN</span>
              <input
                className="w-full input text-xs font-mono"
                value={name}
                onChange={(e) => setName(e.target.value)}
                disabled={!isAdmin || busy || !!editZone}
                placeholder="e.g. corp.example.id"
              />
            </label>
            <label className="text-xs font-medium text-[var(--muted)] space-y-1 block">
              <span>Refresh Interval Override (seconds, 0 = use SOA)</span>
              <input
                type="number"
                min={0}
                className="w-full input text-xs font-mono"
                value={refreshSec}
                onChange={(e) => setRefreshSec(e.target.value)}
                disabled={!isAdmin || busy}
              />
            </label>
            <label className="text-xs font-medium text-[var(--muted)] space-y-1 block sm:col-span-2">
              <span>Primary Master Servers (one per line or comma-separated, host:port)</span>
              <textarea
                className="w-full input text-xs font-mono min-h-[3.5rem]"
                value={mastersText}
                onChange={(e) => setMastersText(e.target.value)}
                disabled={!isAdmin || busy}
                placeholder="10.10.1.10:53"
              />
            </label>
            <label className="text-xs font-medium text-[var(--muted)] space-y-1 block sm:col-span-2">
              <span>TSIG Key Name (optional RFC 2845 auth)</span>
              <input
                list="secondary-tsig-keys-list"
                className="w-full input text-xs font-mono"
                value={tsigKey}
                onChange={(e) => setTsigKey(e.target.value)}
                disabled={!isAdmin || busy}
                placeholder="Leave blank if master uses IP ACL"
              />
              <datalist id="secondary-tsig-keys-list">
                {tsigKeys.map((k) => (
                  <option key={k} value={k} />
                ))}
              </datalist>
            </label>
          </div>

          <div className="pt-1 flex items-center gap-2">
            <button
              type="submit"
              disabled={!isAdmin || busy}
              className="btn btn-primary text-xs min-h-[34px] px-4 font-semibold disabled:opacity-50"
            >
              {busy ? 'Saving…' : editZone ? 'Save Slave Zone' : 'Add Slave Zone'}
            </button>
          </div>
        </form>
      </div>
    </section>
  )
}

function RPZPanel({ initial, onChange }) {
  const defaultRedirectTarget = '139.255.196.196'
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
  const [name, setName] = useState('')
  const [source, setSource] = useState('')
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
    setName('')
    setSource('')
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
    <div className="space-y-6 max-w-[var(--content-max)]" aria-labelledby="tools-rpz-heading">
      {/* Header Banner */}
      <header className="reveal flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-4 border-b border-[var(--border)]">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="p-1.5 rounded-lg bg-[var(--accent-soft)] text-[var(--accent)]">
              <ShieldCheck size={20} weight="bold" />
            </span>
            <span className="text-[11px] font-semibold uppercase tracking-wider text-[var(--muted)]">Domain Filtering Engine</span>
          </div>
          <h2 id="tools-rpz-heading" className="text-2xl font-bold tracking-tight text-[var(--text)]">
            RPZ Feeds &amp; Custom Blocklists
          </h2>
          <p className="text-xs text-[var(--muted)] mt-1.5 max-w-[65ch] leading-relaxed">
            Attach supplementary plain-text hosts files or URLs for ad-blocking and custom blacklists. Rules are indexed into the PowerSVX high-performance CDB dataplane.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            disabled={busy || loading}
            onClick={resync}
            className="btn btn-secondary text-xs min-h-[36px] px-3 font-medium flex items-center gap-1.5 disabled:opacity-50"
          >
            <ArrowsClockwise size={14} className={loading ? 'animate-spin' : ''} />
            <span>Re-sync</span>
          </button>
          <button
            type="button"
            disabled={busy || loading}
            onClick={saveSync}
            className="btn btn-primary text-xs min-h-[36px] px-4 font-semibold disabled:opacity-50"
          >
            {busy ? 'Saving…' : 'Save & Sync'}
          </button>
        </div>
      </header>

      {/* Metrics Row (AdGuard Home Style) */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <div className="p-4 rounded-[var(--radius)] bg-[var(--bg-panel)] border border-[var(--border)] flex items-center gap-3">
          <span className="p-2 rounded bg-[var(--bg)] border border-[var(--border)] text-[var(--accent)]">
            <FileText size={20} />
          </span>
          <div>
            <span className="text-[10px] font-semibold uppercase tracking-wider text-[var(--muted)] block">Custom Feeds</span>
            <span className="text-base font-bold text-[var(--text)] font-mono">{policies.length} Active</span>
          </div>
        </div>

        <div className="p-4 rounded-[var(--radius)] bg-[var(--bg-panel)] border border-[var(--border)] flex items-center gap-3">
          <span className="p-2 rounded bg-[var(--bg)] border border-[var(--border)] text-emerald-700">
            <Clock size={20} />
          </span>
          <div>
            <span className="text-[10px] font-semibold uppercase tracking-wider text-[var(--muted)] block">Auto-Reload</span>
            <span className="text-base font-bold text-[var(--text)] font-mono truncate">
              {updateAt ? `Daily at ${updateAt}` : intervalSec > 0 ? `Every ${intervalSec}s` : 'Manual only'}
            </span>
          </div>
        </div>

        <div className="p-4 rounded-[var(--radius)] bg-[var(--bg-panel)] border border-[var(--border)] flex items-center gap-3">
          <span className="p-2 rounded bg-[var(--bg)] border border-[var(--border)] text-[var(--muted)]">
            <Database size={20} />
          </span>
          <div>
            <span className="text-[10px] font-semibold uppercase tracking-wider text-[var(--muted)] block">Total CDB Engine</span>
            <span className="text-base font-bold text-[var(--text)] font-mono">
              {status?.entries ? `${Number(status.entries).toLocaleString()} rules` : 'Ready'}
            </span>
          </div>
        </div>
      </div>

      {/* Info Callout */}
      <div className="p-3.5 rounded-[var(--radius)] bg-[var(--bg-elevated)] border border-[var(--border)] text-xs text-[var(--muted)] leading-relaxed flex items-start gap-2.5">
        <ShieldCheck size={18} weight="bold" className="text-[var(--accent)] shrink-0 mt-0.5" />
        <div>
          <strong className="text-[var(--text)]">Standard Filtering Policy:</strong> PowerSVX utilizes authoritative Kominfo AXFR/IXFR synchronization (managed under <strong className="text-[var(--text)]">Tools → AXFR Sync</strong>) as its primary national blocklist. Adding external web hosts feeds is optional; zero automatic scraping is enabled by default.
        </div>
      </div>

      {err ? <ErrorBox msg={err} /> : null}
      {ok ? (
        <div className="border border-[var(--ok)]/40 bg-[var(--ok-soft)] text-[var(--ok)] text-xs px-4 py-3 rounded-[var(--radius)] font-medium flex items-center gap-2">
          <CheckCircle size={16} weight="bold" />
          <span>{ok}</span>
        </div>
      ) : null}
      {loading ? (
        <div className="border border-amber-500/40 bg-amber-500/10 text-amber-900 text-xs px-4 py-3 rounded-[var(--radius)] flex items-center gap-2">
          <ArrowsClockwise size={16} className="animate-spin text-amber-800" />
          <span>Large hosts lists are compiling to disk snapshot in background. Resolving operations remain active.</span>
        </div>
      ) : null}

      {/* Schedule Configuration Card */}
      <section className="panel p-4 space-y-3">
        <div className="border-b border-[var(--border)] pb-2.5">
          <h3 className="text-xs font-bold uppercase tracking-wider text-[var(--text)]">
            Refresh Schedule
          </h3>
          <p className="text-[11px] text-[var(--muted)] mt-0.5">
            Configure periodic re-downloading and compilation for hosts file sources.
          </p>
        </div>

        <div className="grid gap-4 sm:grid-cols-2 max-w-xl">
          <label className="text-xs text-[var(--muted)] space-y-1 block">
            <span className="font-medium text-[var(--text)]">Reload Interval (seconds)</span>
            <input
              type="number"
              min={0}
              step={60}
              className="w-full input text-xs font-mono"
              value={intervalSec}
              onChange={(e) => setIntervalSec(e.target.value)}
              placeholder="0 = disabled, 86400 = 24h"
            />
            <span className="text-[10px] text-[var(--muted)] block">Set to 0 to disable periodic interval pulls.</span>
          </label>
          <label className="text-xs text-[var(--muted)] space-y-1 block">
            <span className="font-medium text-[var(--text)]">Fixed Daily Time (HH:MM)</span>
            <input
              type="time"
              className="w-full input text-xs font-mono"
              value={updateAt || ''}
              onChange={(e) => setUpdateAt(e.target.value)}
            />
            <span className="text-[10px] text-[var(--muted)] block">Executes once per day at server clock (e.g. Asia/Jakarta).</span>
          </label>
        </div>
      </section>

      {/* Feeds List Cards */}
      <section className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-[var(--muted)]">
            Configured Hosts Feeds ({policies.length})
          </h3>
        </div>

        <div className="space-y-2.5">
          {policies.length ? (
            policies.map((p) => (
              <div
                key={p.name}
                className={`p-3.5 rounded-[var(--radius)] border border-[var(--border)] bg-[var(--bg-panel)] flex flex-col md:flex-row md:items-center justify-between gap-3 transition-colors ${
                  editName === p.name ? 'border-[var(--accent)] ring-1 ring-[var(--accent)]' : ''
                }`}
              >
                <div className="space-y-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-semibold text-xs text-[var(--text)]">{p.name}</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[var(--bg-elevated)] border border-[var(--border)] text-[var(--muted)]">
                      {p.format || 'hosts'}
                    </span>
                    <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-[var(--accent-soft)] text-[var(--accent)] border border-[var(--accent)]/30 font-semibold">
                      {p.action || 'nxdomain'} {p.target ? `→ ${p.target}` : ''}
                    </span>
                  </div>
                  <div className="mono text-xs text-[var(--muted)] break-all flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-[var(--muted)]" />
                    <span>{p.source}</span>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0 pt-2 md:pt-0 border-t md:border-t-0 border-[var(--border)]">
                  <button
                    type="button"
                    disabled={busy || loading}
                    onClick={() => startEdit(p)}
                    className="btn btn-ghost text-xs min-h-[30px] px-2.5 text-[var(--muted)] hover:text-[var(--text)] disabled:opacity-40"
                  >
                    <PencilSimple size={13} className="mr-1 inline" />
                    <span>Edit</span>
                  </button>
                  <button
                    type="button"
                    disabled={busy || loading}
                    onClick={() => remove(p.name)}
                    className="btn btn-ghost text-xs min-h-[30px] px-2.5 text-[var(--danger)] hover:bg-[var(--danger)]/10 disabled:opacity-40"
                  >
                    <Trash size={13} className="mr-1 inline" />
                    <span>Remove</span>
                  </button>
                </div>
              </div>
            ))
          ) : (
            <div className="p-8 text-center border border-dashed border-[var(--border)] rounded-[var(--radius)] bg-[var(--bg)]/40">
              <ShieldCheck size={28} className="mx-auto text-[var(--muted)] mb-2" />
              <p className="text-xs font-semibold text-[var(--text)]">No custom hosts feeds configured</p>
              <p className="text-[11px] text-[var(--muted)] mt-1 max-w-md mx-auto leading-relaxed">
                National censorship &amp; malware protection is actively handled by Kominfo AXFR. To add additional domain blocklists or internal hostfiles, use the form below.
              </p>
            </div>
          )}
        </div>
      </section>

      {/* Add / Edit Feed Form */}
      <section className="panel p-4 space-y-3">
        <div className="border-b border-[var(--border)] pb-2.5 flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-[var(--text)]">
            {editName != null ? `Edit Feed: ${editName}` : 'Add Custom Hosts Feed'}
          </h3>
          {editName != null ? (
            <span className="text-[11px] text-[var(--warn)] font-medium">Drafting changes</span>
          ) : null}
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          <label className="text-xs font-medium text-[var(--muted)] space-y-1 block">
            <span>Feed Name</span>
            <input
              className="w-full input text-xs"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. adblock-malware"
            />
          </label>
          <label className="text-xs font-medium text-[var(--muted)] space-y-1 block">
            <span>Filter Action</span>
            <select
              className="w-full input text-xs"
              value={action}
              onChange={(e) => setAction(e.target.value)}
            >
              <option value="nxdomain">NXDOMAIN (Drop / Non-existent)</option>
              <option value="nodata">NODATA (Empty response)</option>
              <option value="pass">PASS (Bypass rule)</option>
              <option value="redirect">REDIRECT (Sinkhole IP)</option>
              <option value="cname">CNAME (Landing hostname)</option>
            </select>
            {action === 'redirect' ? (
              <p className="text-[11px] text-[var(--warn)] leading-relaxed pt-1">
                Sinkhole redirection breaks some Indonesian banking apps. PowerSVX will reply with NXDOMAIN for bank-branded queries.
              </p>
            ) : null}
          </label>
          {action === 'redirect' || action === 'cname' ? (
            <label className="text-xs font-medium text-[var(--muted)] space-y-1 block sm:col-span-2">
              <span>{action === 'redirect' ? 'Sinkhole Landing IP' : 'Landing Hostname'}</span>
              <input
                className="w-full input text-xs font-mono"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder={action === 'redirect' ? defaultRedirectTarget : 'block.corp.local'}
              />
            </label>
          ) : null}
          <label className="text-xs font-medium text-[var(--muted)] space-y-1 block sm:col-span-2">
            <span>Source URL or File Path</span>
            <input
              className="w-full input text-xs font-mono"
              value={source}
              onChange={(e) => setSource(e.target.value)}
              placeholder="e.g. /etc/powersvx/custom-hosts.txt or https://example.com/hosts.txt"
            />
          </label>
        </div>

        <div className="pt-2 flex items-center gap-2">
          <button
            type="button"
            disabled={busy || loading}
            onClick={addOrUpdate}
            className="btn btn-secondary text-xs min-h-[34px] px-4 font-medium"
          >
            {editName != null ? 'Save Changes' : 'Add Feed to List'}
          </button>
          {editName != null ? (
            <button
              type="button"
              disabled={busy || loading}
              onClick={cancelEdit}
              className="btn btn-ghost text-xs min-h-[34px] px-3"
            >
              Cancel
            </button>
          ) : null}
        </div>
      </section>
    </div>
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
      setOk(editing ? `Updated user ${name}` : `Created user ${name}`)
      resetForm()
      await load()
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  const remove = async (n) => {
    if (!window.confirm(`Delete user account "${n}"?`)) return
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
    <div className="space-y-4 max-w-4xl">
      <div className="panel p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--border)] pb-4">
          <div>
            <h3 className="text-base font-semibold flex items-center gap-2">
              <Users weight="bold" className="w-5 h-5 text-[var(--accent)]" />
              Local Access & User Accounts (RBAC)
            </h3>
            <p className="text-xs text-[var(--muted)] mt-1">
              Manage operators and administrators stored in local authentication storage.
            </p>
          </div>
          <span className="text-xs font-mono px-2.5 py-1 rounded-full bg-[var(--bg-elevated)] border border-[var(--border)] text-[var(--muted)]">
            {users.length} {users.length === 1 ? 'Account' : 'Accounts'}
          </span>
        </div>

        {err ? <ErrorBox msg={err} /> : null}
        {ok ? (
          <div className="border border-[var(--ok)]/40 bg-[var(--ok-soft)] text-[var(--ok)] text-sm px-3.5 py-2.5 rounded-[var(--radius)] font-medium">
            {ok}
          </div>
        ) : null}

        {/* Cloudflare Style Users Table */}
        <div className="cf-table-wrap">
          <table className="cf-table">
            <thead>
              <tr>
                <th>User Account</th>
                <th>Role &amp; Permissions</th>
                <th>Status</th>
                <th className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => {
                const isSelf = me?.name === u.name
                const roleTone =
                  u.role === 'admin'
                    ? 'bg-[var(--accent-soft)] text-[var(--accent)] font-semibold'
                    : u.role === 'operator'
                      ? 'bg-[var(--info-soft)] text-[var(--info)] font-semibold'
                      : 'bg-[var(--bg-elevated)] text-[var(--muted)]'
                return (
                  <tr key={u.name}>
                    <td>
                      <div className="flex items-center gap-2.5">
                        <div className="w-7 h-7 rounded-full bg-[var(--bg-elevated)] border border-[var(--border)] flex items-center justify-center font-bold text-xs uppercase text-[var(--accent)]">
                          {u.name.slice(0, 2)}
                        </div>
                        <div>
                          <span className="mono font-semibold text-sm">{u.name}</span>
                          {isSelf ? (
                            <span className="ml-2 text-[10px] uppercase font-bold text-[var(--ok)] bg-[var(--ok-soft)] px-1.5 py-0.5 rounded">
                              Current
                            </span>
                          ) : null}
                        </div>
                      </div>
                    </td>
                    <td>
                      <span className={`text-xs px-2.5 py-0.5 rounded font-mono ${roleTone}`}>
                        {u.role || 'operator'}
                      </span>
                    </td>
                    <td>
                      <span className="inline-flex items-center gap-1.5 text-xs text-[var(--ok)] font-medium">
                        <span className="w-1.5 h-1.5 rounded-full bg-[var(--ok)]" />
                        Active
                      </span>
                    </td>
                    <td className="text-right space-x-1">
                      <button
                        type="button"
                        onClick={() => startEdit(u)}
                        className="btn btn-secondary text-xs min-h-[32px] px-2.5"
                      >
                        Edit
                      </button>
                      <button
                        type="button"
                        disabled={isSelf}
                        onClick={() => remove(u.name)}
                        className="btn btn-secondary text-xs min-h-[32px] px-2.5 text-[var(--danger)] disabled:opacity-30"
                        title={isSelf ? 'Cannot delete your own account' : 'Remove user'}
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>

        {/* Add / Edit Form Card */}
        <div className="mt-4 p-4 rounded-[var(--radius)] bg-[var(--bg-elevated)] border border-[var(--border)]">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-[var(--text)] mb-3">
            {editing ? `Update Credentials for "${name}"` : 'Add New Local Account'}
          </h4>
          <form onSubmit={save} className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <label className="text-xs text-[var(--muted)] space-y-1">
              <span>Username</span>
              <input
                className="input mono w-full"
                placeholder="username"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                disabled={editing}
              />
            </label>
            <label className="text-xs text-[var(--muted)] space-y-1">
              <span>Password {editing ? '(leave blank to keep current)' : ''}</span>
              <input
                type="password"
                className="input mono w-full"
                placeholder={editing ? '•••••••• (unchanged)' : 'Enter secure password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required={!editing}
              />
            </label>
            <label className="text-xs text-[var(--muted)] space-y-1">
              <span>Role Assignment</span>
              <select
                className="input w-full font-medium"
                value={role}
                onChange={(e) => setRole(e.target.value)}
              >
                <option value="admin">Administrator (Full Control)</option>
                <option value="operator">Operator (Zones &amp; Feeds)</option>
                <option value="readonly">Read-Only (Viewer)</option>
              </select>
            </label>
            <div className="md:col-span-3 flex items-center gap-2 pt-2">
              <button
                type="submit"
                disabled={busy}
                className="btn btn-primary min-h-[40px] px-5"
              >
                {busy ? 'Saving…' : editing ? 'Update User Account' : 'Create User Account'}
              </button>
              {editing ? (
                <button
                  type="button"
                  onClick={resetForm}
                  className="btn btn-secondary min-h-[40px] px-4"
                >
                  Cancel Edit
                </button>
              ) : null}
            </div>
          </form>
        </div>
      </div>
    </div>
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
      setOk('Backup downloaded successfully as JSON manifest')
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
      setOk('Backup restored successfully — authoritative zones reloaded')
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-4 max-w-4xl">
      {err ? <ErrorBox msg={err} /> : null}
      {ok ? (
        <div className="border border-[var(--ok)]/40 bg-[var(--ok-soft)] text-[var(--ok)] text-sm px-3.5 py-2.5 rounded-[var(--radius)] font-medium">
          {ok}
        </div>
      ) : null}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Export Card */}
        <div className="panel p-5 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-lg bg-[var(--accent-soft)] text-[var(--accent)]">
                <CloudArrowDown weight="bold" className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-sm font-semibold">Download Configuration Backup</h3>
                <span className="text-[10px] text-[var(--muted)] font-mono">Format: JSON Manifest</span>
              </div>
            </div>
            <p className="text-xs text-[var(--muted)] leading-relaxed">
              Generates a snapshot containing all authoritative DNS zones, resource records,
              forwarding rules, rate-limiting policies, and access control masks.
            </p>
          </div>
          <div className="mt-5 pt-4 border-t border-[var(--border)]">
            <button
              type="button"
              disabled={busy}
              onClick={download}
              className="btn btn-primary w-full min-h-[42px] flex items-center justify-center gap-2"
            >
              <DownloadSimple weight="bold" className="w-4 h-4" />
              {busy ? 'Preparing Download…' : 'Export JSON Backup'}
            </button>
          </div>
        </div>

        {/* Restore Card */}
        <div className="panel p-5 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-lg bg-[var(--info-soft)] text-[var(--info)]">
                <CloudArrowUp weight="bold" className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-sm font-semibold">Restore Configuration</h3>
                <span className="text-[10px] text-[var(--muted)] font-mono">Replaces local database zones</span>
              </div>
            </div>
            <p className="text-xs text-[var(--muted)] leading-relaxed">
              Upload and apply a previously exported PowerSVX JSON configuration file.
              All existing zones with matching names will be safely updated.
            </p>
          </div>
          <div className="mt-5 pt-4 border-t border-[var(--border)]">
            <button
              type="button"
              disabled={busy || !isAdmin}
              onClick={() => fileRef.current?.click()}
              className="btn btn-secondary w-full min-h-[42px] flex items-center justify-center gap-2 disabled:opacity-40"
            >
              <CloudArrowUp weight="bold" className="w-4 h-4" />
              {busy ? 'Applying Backup…' : 'Select Backup JSON File…'}
            </button>
            <input ref={fileRef} type="file" accept="application/json,.json" className="hidden" onChange={restore} />
            {!isAdmin ? <p className="text-[10px] text-[var(--warn)] text-center mt-1.5">Restoring requires Administrator permissions.</p> : null}
          </div>
        </div>
      </div>
    </div>
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
      setOk('Certificate obtained successfully — point [server.tls] at certs/acme and restart if needed')
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  if (!st) return null

  const isCertActive = !!st.cert_present

  return (
    <div className="space-y-4 max-w-4xl">
      {/* Hero Certificate Status Card */}
      <div className="panel p-5 relative overflow-hidden">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className={`p-3 rounded-xl ${isCertActive ? 'bg-[var(--ok-soft)] text-[var(--ok)]' : 'bg-[var(--accent-soft)] text-[var(--accent)]'}`}>
              <Certificate weight="bold" className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-semibold">Let's Encrypt Automated TLS (ACME DNS-01)</h3>
                <span className={`text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded-full ${isCertActive ? 'bg-[var(--ok-soft)] text-[var(--ok)]' : 'bg-[var(--warn-soft)] text-[var(--warn)]'}`}>
                  {isCertActive ? 'Certificate Active' : 'No Certificate Issued'}
                </span>
              </div>
              <p className="text-xs text-[var(--muted)] mt-1 max-w-xl leading-relaxed">
                Issues and verifies TLS certificates using DNS-01 TXT challenges answered natively by PowerSVX.
                Zero port 80/443 HTTP validation required.
              </p>
            </div>
          </div>
          <button
            type="button"
            disabled={busy || !st.enabled}
            onClick={obtain}
            className="btn btn-primary min-h-[42px] px-5"
          >
            {busy ? (
              <span className="flex items-center gap-2">
                <span className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                Obtaining Certificate…
              </span>
            ) : isCertActive ? 'Renew Certificate' : 'Issue Certificate'}
          </button>
        </div>

        {/* Certificate Properties Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mt-5 pt-4 border-t border-[var(--border)]">
          <div className="p-3 rounded-[var(--radius)] bg-[var(--bg-elevated)] border border-[var(--border)]">
            <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold block">DNS-01 ACME Engine</span>
            <span className="font-mono text-sm font-semibold mt-1 flex items-center gap-1.5">
              <span className={`w-2 h-2 rounded-full ${st.enabled ? 'bg-[var(--ok)]' : 'bg-[var(--danger)]'}`} />
              {st.enabled ? 'Enabled' : 'Disabled in Config'}
            </span>
          </div>

          <div className="p-3 rounded-[var(--radius)] bg-[var(--bg-elevated)] border border-[var(--border)]">
            <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold block">Environment Target</span>
            <span className="font-mono text-sm font-semibold mt-1 flex items-center gap-1.5">
              <span className={`w-2 h-2 rounded-full ${st.staging ? 'bg-[var(--info)]' : 'bg-[var(--accent)]'}`} />
              {st.staging ? "Let's Encrypt Staging" : "Let's Encrypt Production"}
            </span>
          </div>

          <div className="p-3 rounded-[var(--radius)] bg-[var(--bg-elevated)] border border-[var(--border)]">
            <span className="text-[10px] uppercase tracking-wider text-[var(--muted)] font-semibold block">Disk Presence</span>
            <span className="font-mono text-sm font-semibold mt-1 flex items-center gap-1.5">
              <span className={`w-2 h-2 rounded-full ${isCertActive ? 'bg-[var(--ok)]' : 'bg-[var(--warn)]'}`} />
              {isCertActive ? 'certs/acme present' : 'missing on disk'}
            </span>
          </div>
        </div>

        {err ? <div className="mt-4"><ErrorBox msg={err} /></div> : null}
        {ok ? (
          <div className="mt-4 border border-[var(--ok)]/40 bg-[var(--ok-soft)] text-[var(--ok)] text-sm px-3.5 py-2.5 rounded-[var(--radius)] font-medium">
            {ok}
          </div>
        ) : null}
      </div>

      {/* Instructional Guidance Card */}
      <div className="panel p-4 bg-[var(--bg-elevated)] text-xs text-[var(--muted)] space-y-2">
        <h4 className="text-xs font-semibold text-[var(--text)] uppercase tracking-wider">How Automated DNS-01 Verification Works</h4>
        <ul className="list-disc list-inside space-y-1 pl-1">
          <li>PowerSVX creates an in-memory TXT record for <code className="mono text-[var(--accent)]">_acme-challenge.&lt;your-domain&gt;</code>.</li>
          <li>Let's Encrypt verifies authoritative response on UDP/TCP port 53.</li>
          <li>Once validated, the keypair is written to <code className="mono text-[var(--accent)]">certs/acme/fullchain.pem</code> &amp; <code className="mono text-[var(--accent)]">privkey.pem</code>.</li>
        </ul>
      </div>
    </div>
  )
}



function TokensPanel() {
  const { isAdmin } = useAuth()
  const [tokens, setTokens] = useState([])
  const [name, setName] = useState('')
  const [role, setRole] = useState('operator')
  const [ttlDays, setTtlDays] = useState(90)
  const [createdSecret, setCreatedSecret] = useState('')
  const [copied, setCopied] = useState(false)
  const [err, setErr] = useState('')
  const [ok, setOk] = useState('')
  const [busy, setBusy] = useState(false)

  const load = () =>
    api
      .listTokens()
      .then((r) => setTokens(r?.tokens || []))
      .catch((e) => setErr(e.message))

  useEffect(() => {
    load()
  }, [])

  const create = async (e) => {
    e.preventDefault()
    if (!name.trim()) return
    setBusy(true)
    setErr('')
    setOk('')
    setCreatedSecret('')
    try {
      const r = await api.createToken({
        name: name.trim(),
        role,
        ttl_days: Number(ttlDays) || 0,
      })
      setCreatedSecret(r?.token || '')
      setName('')
      setOk(`Created API token "${r?.name || name}" (${r?.prefix || ''}) — copy it now; it won't be shown again.`)
      await load()
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  const revoke = async (id, tokName) => {
    if (!window.confirm(`Revoke API token "${tokName}"? Scripts using it will lose access immediately.`)) return
    setBusy(true)
    setErr('')
    setOk('')
    try {
      await api.revokeToken(id)
      setOk(`Revoked token "${tokName}"`)
      await load()
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  const copySecret = () => {
    if (!createdSecret) return
    try {
      navigator.clipboard.writeText(createdSecret)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      /* ignore */
    }
  }

  return (
    <div className="space-y-4 max-w-4xl">
      {err ? <ErrorBox msg={err} /> : null}
      {ok ? (
        <div className="border border-[var(--ok)]/40 bg-[var(--ok-soft)] text-[var(--ok)] text-sm px-3.5 py-2.5 rounded-[var(--radius)] font-medium">
          {ok}
        </div>
      ) : null}

      {createdSecret ? (
        <div className="panel p-4 border border-[var(--accent)] bg-[var(--bg-elevated)] space-y-2">
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-[var(--accent)]">
              New Bearer Token (Shown Once)
            </span>
            <button type="button" onClick={copySecret} className="btn btn-primary text-xs">
              {copied ? <Check size={14} weight="bold" /> : <Copy size={14} weight="bold" />}
              <span>{copied ? 'Copied!' : 'Copy Token'}</span>
            </button>
          </div>
          <pre className="mono text-xs p-2.5 rounded bg-[var(--bg)] border border-[var(--border)] select-all break-all">
            {createdSecret}
          </pre>
        </div>
      ) : null}

      <div className="panel overflow-hidden">
        <div className="p-4 border-b border-[var(--border)] bg-[var(--bg-elevated)] flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-[var(--accent-soft)] text-[var(--accent)]">
              <Key weight="bold" className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-semibold">API Tokens &amp; Automation Keys</h3>
              <p className="text-xs text-[var(--muted)]">
                Scoped Bearer tokens for Terraform, scripts, and CI/CD (Authorization: Bearer psvx_…)
              </p>
            </div>
          </div>
          <span className="text-xs font-mono text-[var(--muted)]">{tokens.length} active</span>
        </div>

        <div className="divide-y divide-[var(--border)]">
          {tokens.length === 0 ? (
            <div className="p-6 text-center text-xs text-[var(--muted)]">
              No API tokens minted yet. Create one below for programmatic REST API access.
            </div>
          ) : (
            tokens.map((t) => (
              <div key={t.id} className="px-4 py-3 flex flex-wrap items-center justify-between gap-3">
                <div className="space-y-0.5 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-semibold text-[var(--text)]">{t.name}</span>
                    <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-[var(--bg-elevated)] border border-[var(--border)] text-[var(--accent)]">
                      {t.role}
                    </span>
                  </div>
                  <div className="text-[11px] font-mono text-[var(--muted)] flex flex-wrap gap-3">
                    <span>Prefix: {t.prefix}…</span>
                    <span>Created: {t.created_at ? new Date(t.created_at).toLocaleDateString() : '—'}</span>
                    <span>Expires: {t.expires_at ? new Date(t.expires_at).toLocaleDateString() : 'Never'}</span>
                  </div>
                </div>
                {isAdmin && (
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => revoke(t.id, t.name)}
                    className="btn btn-secondary text-xs text-[var(--danger)]"
                  >
                    <Trash size={14} />
                    <span>Revoke</span>
                  </button>
                )}
              </div>
            ))
          )}
        </div>

        {isAdmin && (
          <div className="p-4 border-t border-[var(--border)] bg-[var(--bg-elevated)]/60">
            <form onSubmit={create} className="grid grid-cols-1 md:grid-cols-4 gap-3 items-end">
              <label className="text-xs text-[var(--muted)] space-y-1 md:col-span-2">
                <span>Token Label</span>
                <input
                  className="input text-xs w-full"
                  placeholder="e.g. certbot-dns01 or netops-ci"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  required
                />
              </label>
              <label className="text-xs text-[var(--muted)] space-y-1">
                <span>Role</span>
                <select className="input text-xs w-full" value={role} onChange={(e) => setRole(e.target.value)}>
                  <option value="admin">admin</option>
                  <option value="operator">operator</option>
                  <option value="readonly">readonly</option>
                </select>
              </label>
              <label className="text-xs text-[var(--muted)] space-y-1">
                <span>TTL (days, 0 = never)</span>
                <div className="flex gap-2">
                  <input
                    type="number"
                    min={0}
                    max={3650}
                    className="input text-xs mono w-full"
                    value={ttlDays}
                    onChange={(e) => setTtlDays(Number(e.target.value))}
                  />
                  <button type="submit" disabled={busy || !name.trim()} className="btn btn-primary text-xs shrink-0">
                    Mint Token
                  </button>
                </div>
              </label>
            </form>
          </div>
        )}
      </div>
    </div>
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
        tokens: TokensPanel,
      }}
    />
  )
}
