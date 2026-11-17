import { useState, useEffect, useCallback, useRef } from 'react'
import { api } from '../../api'
import { useAuth } from '../../auth'
import { useI18n } from '../../i18n'
import { EmptyState, PageHeader } from '../../ui'

function getInitialGrafanaURL() {
  const { protocol, hostname } = window.location
  const defaultURL = `${protocol}//${hostname}:3000`
  try {
    const stored = localStorage.getItem('powersvx_grafana_url')
    if (stored) {
      const clean = stored.replace(/\/$/, '')
      if (
        (clean.includes('127.0.0.1') || clean.includes('localhost')) &&
        hostname !== '127.0.0.1' &&
        hostname !== 'localhost'
      ) {
        return defaultURL
      }
      return clean
    }
  } catch {
    /* ignore */
  }
  return defaultURL
}

function buildGrafanaURL(base, { kiosk = true } = {}) {
  const root = (base || getInitialGrafanaURL()).replace(/\/$/, '')
  const path = '/d/powersvx-dns/powersvx-dns'
  const q = new URLSearchParams({
    orgId: '1',
    from: 'now-6h',
    to: 'now',
    theme: 'dark',
  })
  if (kiosk) q.set('kiosk', 'tv')
  return `${root}${path}?${q}`
}

export default function Analytics() {
  const { canWrite } = useAuth()
  const { lang } = useI18n()
  const isID = lang === 'id'

  const [tab, setTab] = useState('live') // 'live' | 'grafana'
  const [queries, setQueries] = useState([])
  const [buffered, setBuffered] = useState({ count: 0, capacity: 20000 })
  const [paused, setPaused] = useState(false)
  const pausedRef = useRef(false)
  pausedRef.current = paused
  const [qFilter, setQFilter] = useState('')
  const [clientFilter, setClientFilter] = useState('')
  const [blockedOnly, setBlockedOnly] = useState(false)
  const [liveStatus, setLiveStatus] = useState('connecting')
  const [actionMsg, setActionMsg] = useState('')

  const [base, setBase] = useState(() => getInitialGrafanaURL())
  const [draft, setDraft] = useState(() => getInitialGrafanaURL())
  const [status, setStatus] = useState('checking')
  const [forceShow, setForceShow] = useState(false)

  const src = buildGrafanaURL(base, { kiosk: true })
  const openURL = buildGrafanaURL(base, { kiosk: false })

  useEffect(() => {
    if (tab !== 'live') return undefined
    let alive = true
    let es
    let retry
    api
      .liveQueries({ q: qFilter, client: clientFilter, blocked: blockedOnly, limit: 150 })
      .then((res) => {
        if (!alive) return
        setQueries(res?.queries || [])
        setBuffered({ count: res?.buffered || 0, capacity: res?.capacity || 20000 })
      })
      .catch(() => {})

    const connect = () => {
      es = new EventSource(api.liveQueriesStreamURL({ q: qFilter, client: clientFilter, blocked: blockedOnly }))
      es.addEventListener('query', (msg) => {
        if (pausedRef.current) return
        try {
          const ev = JSON.parse(msg.data)
          setQueries((prev) => {
            if (prev.some((x) => x.seq === ev.seq && ev.seq)) return prev
            return [ev, ...prev].slice(0, 200)
          })
          setBuffered((b) => ({ ...b, count: Math.min(b.capacity, (b.count || 0) + 1) }))
        } catch {
          /* ignore */
        }
      })
      es.onopen = () => setLiveStatus('live')
      es.onerror = () => {
        setLiveStatus('reconnecting')
        es.close()
        retry = setTimeout(() => {
          if (alive) connect()
        }, 3000)
      }
    }
    connect()
    return () => {
      alive = false
      clearTimeout(retry)
      if (es) es.close()
    }
  }, [tab, qFilter, clientFilter, blockedOnly])

  const checkConnectivity = useCallback(async (targetBase) => {
    setStatus('checking')
    try {
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), 3500)
      await fetch(`${targetBase}/api/health`, { mode: 'no-cors', signal: controller.signal })
      clearTimeout(timer)
      setStatus('online')
    } catch {
      setStatus('offline')
    }
  }, [])

  useEffect(() => {
    if (tab === 'grafana') checkConnectivity(base)
  }, [tab, base, checkConnectivity])

  const saveBase = (e) => {
    e?.preventDefault?.()
    const v = draft.trim().replace(/\/$/, '')
    if (!v) return
    try {
      localStorage.setItem('powersvx_grafana_url', v)
    } catch {
      /* ignore */
    }
    setBase(v)
    setForceShow(false)
  }

  const resetToCurrentHost = () => {
    const { protocol, hostname } = window.location
    const defaultURL = `${protocol}//${hostname}:3000`
    setDraft(defaultURL)
    try {
      localStorage.setItem('powersvx_grafana_url', defaultURL)
    } catch {
      /* ignore */
    }
    setBase(defaultURL)
    setForceShow(false)
  }

  const quickAction = async (kind, value) => {
    setActionMsg('')
    try {
      if (kind === 'allow') {
        await api.addWhitelist(value)
        setActionMsg(`Whitelisted ${value}`)
      } else if (kind === 'block') {
        await api.addBlacklist(value)
        setActionMsg(`Blacklisted ${value}`)
      } else if (kind === 'ban') {
        await api.securityBan({ prefix: value, reason: 'Blocked from Live Stream' })
        setActionMsg(`Banned client ${value}`)
      }
    } catch (ex) {
      setActionMsg(`Error: ${ex.message}`)
    }
  }

  return (
    <div className="space-y-5 max-w-[1400px]">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[var(--border)] pb-4">
        <PageHeader
          eyebrow={isID ? 'OBSERVABILITAS' : 'OBSERVABILITY'}
          title={isID ? 'Live Query Stream & Telemetry Grafana' : 'Live Query Stream & Grafana Telemetry'}
          sub={
            isID
              ? 'Aliran query in-memory 20.000 entri (zero disk IOPS) ditambah grafik Prometheus & Grafana.'
              : 'Zero-disk-IOPS 20k-entry RAM ring buffer stream paired with Prometheus + Grafana metrics.'
          }
          className="mb-0"
        />
        <div className="cf-tabs">
          <button
            type="button"
            className={`cf-tab-btn ${tab === 'live' ? 'is-active' : ''}`}
            onClick={() => setTab('live')}
          >
            Live Query Stream
          </button>
          <button
            type="button"
            className={`cf-tab-btn ${tab === 'grafana' ? 'is-active' : ''}`}
            onClick={() => setTab('grafana')}
          >
            Grafana Dashboard
          </button>
        </div>
      </div>

      {tab === 'live' ? (
        <div className="space-y-4 reveal">
          <div className="panel p-4 flex flex-wrap gap-2 items-center justify-between">
            <div className="flex flex-wrap gap-2 items-center flex-1">
              <input
                className="input text-xs mono min-w-[12rem]"
                placeholder="Filter domain..."
                value={qFilter}
                onChange={(e) => setQFilter(e.target.value)}
              />
              <input
                className="input text-xs mono min-w-[9rem]"
                placeholder="Filter client IP..."
                value={clientFilter}
                onChange={(e) => setClientFilter(e.target.value)}
              />
              <label className="inline-flex items-center gap-1.5 text-xs cursor-pointer">
                <input
                  type="checkbox"
                  checked={blockedOnly}
                  onChange={(e) => setBlockedOnly(e.target.checked)}
                />
                <span>Blocked only</span>
              </label>
            </div>
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <span className={`status-pill ${liveStatus === 'live' ? 'ok' : ''}`}>
                <span className={`pulse-dot ${liveStatus === 'live' ? 'on' : ''}`} aria-hidden />
                {liveStatus}
              </span>
              <span className="mono text-[var(--muted)]">
                RAM {buffered.count.toLocaleString()} / {buffered.capacity.toLocaleString()}
              </span>
              <button type="button" className="btn btn-secondary text-xs" onClick={() => setPaused((p) => !p)}>
                {paused ? 'Resume' : 'Pause'}
              </button>
              <button type="button" className="btn btn-ghost text-xs" onClick={() => setQueries([])}>
                Clear View
              </button>
            </div>
          </div>

          {actionMsg ? (
            <div className="px-3.5 py-2 rounded bg-[var(--bg-elevated)] border border-[var(--accent)]/40 text-xs text-[var(--accent)] mono">
              {actionMsg}
            </div>
          ) : null}

          <div className="cf-table-wrap max-h-[620px] overflow-auto">
            <table className="cf-table text-xs">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Client IP</th>
                  <th>QName</th>
                  <th>Type</th>
                  <th>RCode / Path</th>
                  <th>Latency</th>
                  {canWrite && <th className="text-right">Quick Action</th>}
                </tr>
              </thead>
              <tbody>
                {queries.length > 0 ? (
                  queries.map((q, idx) => (
                    <tr key={`${q.seq || idx}-${q.time}-${q.qname}`}>
                      <td className="mono text-[11px] text-[var(--muted)]">
                        {q.time ? new Date(q.time).toLocaleTimeString() : '—'}
                      </td>
                      <td className="mono">{q.client_ip || '—'}</td>
                      <td className="mono font-medium text-[var(--text)]">{q.qname || '—'}</td>
                      <td className="mono">{q.qtype || 'A'}</td>
                      <td className="mono">
                        <span className={q.blocked ? 'text-[var(--danger)] font-semibold' : 'text-[var(--ok)]'}>
                          {q.rcode}
                        </span>
                        <span className="text-[var(--muted)] ml-1.5">· {q.path}</span>
                      </td>
                      <td className="mono text-[var(--muted)]">{Number(q.latency_ms || 0).toFixed(2)} ms</td>
                      {canWrite && (
                        <td className="text-right space-x-2">
                          {q.qname && (
                            <>
                              <button
                                type="button"
                                onClick={() => quickAction('allow', q.qname)}
                                className="text-[11px] text-[var(--ok)] hover:underline"
                              >
                                Allow
                              </button>
                              <button
                                type="button"
                                onClick={() => quickAction('block', q.qname)}
                                className="text-[11px] text-[var(--danger)] hover:underline"
                              >
                                Block
                              </button>
                            </>
                          )}
                          {q.client_ip && (
                            <button
                              type="button"
                              onClick={() => quickAction('ban', q.client_ip)}
                              className="text-[11px] text-[var(--warn)] hover:underline"
                            >
                              Ban IP
                            </button>
                          )}
                        </td>
                      )}
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={canWrite ? 7 : 6} className="py-8">
                      <EmptyState
                        title="Waiting for live DNS queries"
                        hint="Every query answered by PowerSVX or sampled from dnsdist streams here immediately with zero Postgres IOPS."
                      />
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        <div className="space-y-4 reveal">
          <div className="flex flex-wrap justify-between items-center gap-3 panel px-4 py-3 text-sm text-[var(--muted)]">
            <div>
              <strong className="text-[var(--text)]">Panels:</strong> dnsdist QPS / packet-cache / CDB spoof, Unbound
              recurse latency, host CPU · MemAvailable · disk %, control-plane RSS.
            </div>
            <a href={openURL} target="_blank" rel="noreferrer" className="btn btn-primary text-xs">
              Open in Grafana
            </a>
          </div>

          <form onSubmit={saveBase} className="panel px-4 py-3 flex flex-wrap gap-2 items-end">
            <label className="field flex-1 min-w-[14rem]">
              <span className="label-quiet">Grafana URL</span>
              <input
                className="input mono"
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
                placeholder="http://127.0.0.1:3000"
              />
            </label>
            <button type="submit" className="btn btn-secondary">
              Save
            </button>
            <button type="button" onClick={resetToCurrentHost} className="btn btn-ghost text-xs">
              Reset to Current Host
            </button>
            <div className="flex items-center gap-2 self-center ml-auto text-xs mono">
              <span className="text-[var(--muted)]">Status:</span>
              {status === 'checking' && <span className="badge badge-warning">Checking...</span>}
              {status === 'online' && <span className="badge badge-success">Online</span>}
              {status === 'offline' && <span className="badge badge-danger">Offline / Unreachable</span>}
            </div>
          </form>

          {status === 'offline' && !forceShow ? (
            <section className="panel p-6 text-center flex flex-col items-center justify-center gap-4" style={{ minHeight: 420 }}>
              <div className="max-w-md space-y-1">
                <h3 className="text-base font-semibold text-[var(--text)]">
                  {isID ? 'Grafana Tidak Terdeteksi di Port 3000' : 'Grafana Unreachable on Port 3000'}
                </h3>
                <p className="text-xs text-[var(--muted)]">
                  {isID
                    ? `Grafana secara default di-bind ke 127.0.0.1:3000 untuk keamanan. Gunakan SSH tunnel atau sesuaikan URL di atas.`
                    : `Grafana binds to loopback 127.0.0.1:3000 by default for security. Open via SSH tunnel or configure reverse-proxy URL above.`}
                </p>
              </div>
              <div className="flex gap-2">
                <button type="button" onClick={() => checkConnectivity(base)} className="btn btn-secondary text-xs">
                  {isID ? 'Cek Ulang Koneksi' : 'Retry Connection'}
                </button>
                <button type="button" onClick={() => setForceShow(true)} className="btn btn-ghost text-xs">
                  {isID ? 'Tetap Tampilkan Frame' : 'Show Frame Anyway'}
                </button>
              </div>
            </section>
          ) : (
            <section className="panel overflow-hidden" style={{ minHeight: '70vh' }}>
              <iframe
                title="PowerSVX Grafana"
                src={src}
                className="w-full border-0 bg-[var(--bg)]"
                style={{ height: '70vh', minHeight: 520 }}
                referrerPolicy="no-referrer"
              />
            </section>
          )}
        </div>
      )}
    </div>
  )
}
