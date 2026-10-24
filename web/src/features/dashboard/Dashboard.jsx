import { useEffect, useRef, useState } from 'react'
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { api } from '../../api'
import {
  Badge,
  chartTip,
  EmptyState,
  ErrorBox,
  formatUptime,
  LoadingBlock,
  Metric,
  PageHeader,
  releaseLabel,
  Stat,
} from '../../ui'

function formatEventTime(t) {
  try {
    return new Date(t).toLocaleTimeString()
  } catch {
    return t
  }
}

function LiveErrorLog() {
  const [events, setEvents] = useState([])
  const [live, setLive] = useState(false)
  const [paused, setPaused] = useState(false)
  const [pushOn, setPushOn] = useState(() => localStorage.getItem('powersvx_push') === '1')
  const [pushPerm, setPushPerm] = useState(
    typeof Notification !== 'undefined' ? Notification.permission : 'denied',
  )
  const pausedRef = useRef(false)
  const pushOnRef = useRef(pushOn)
  pausedRef.current = paused
  pushOnRef.current = pushOn

  const notifyBrowser = (ev) => {
    if (!pushOnRef.current) return
    if (typeof Notification === 'undefined') return
    if (Notification.permission !== 'granted') return
    if (ev.level !== 'error' && ev.level !== 'warn') return
    try {
      new Notification(`PowerSVX · ${ev.level}`, {
        body: `${ev.kind}: ${ev.message}`,
        tag: `powersvx-${ev.kind}-${ev.id}`,
      })
    } catch {
      /* ignore */
    }
  }

  const enablePush = async () => {
    if (typeof Notification === 'undefined') {
      setPushPerm('denied')
      return
    }
    const perm = await Notification.requestPermission()
    setPushPerm(perm)
    if (perm === 'granted') {
      setPushOn(true)
      localStorage.setItem('powersvx_push', '1')
    }
  }

  const togglePush = () => {
    if (!pushOn && pushPerm !== 'granted') {
      enablePush()
      return
    }
    const next = !pushOn
    setPushOn(next)
    localStorage.setItem('powersvx_push', next ? '1' : '0')
  }

  useEffect(() => {
    let es
    let alive = true
    let reconnectTimer
    api
      .events()
      .then((d) => {
        if (alive && Array.isArray(d.events)) setEvents(d.events.slice().reverse())
      })
      .catch(() => {})

    const connect = () => {
      es = new EventSource(api.eventsStreamURL())
      es.addEventListener('log', (msg) => {
        if (pausedRef.current) return
        try {
          const ev = JSON.parse(msg.data)
          setEvents((prev) => {
            if (prev.some((p) => p.id === ev.id)) return prev
            return [ev, ...prev].slice(0, 100)
          })
          notifyBrowser(ev)
        } catch {
          /* ignore */
        }
      })
      es.onopen = () => setLive(true)
      es.onerror = () => {
        setLive(false)
        es.close()
        reconnectTimer = setTimeout(() => {
          if (alive) connect()
        }, 3000)
      }
    }
    connect()
    return () => {
      alive = false
      clearTimeout(reconnectTimer)
      if (es) es.close()
    }
  }, [])

  return (
    <section className="panel overflow-hidden">
      <div className="px-4 py-3 border-b border-[var(--border)] flex items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-medium">Live errors</h2>
          <p className="text-xs text-[var(--muted)] mt-0.5">
            Warnings and errors only — browser push for warn/error when enabled
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap justify-end">
          <span className={`status-pill ${live ? 'ok' : ''}`}>
            <span className={`pulse-dot ${live ? 'on' : ''}`} aria-hidden />
            {live ? 'live' : 'reconnecting'}
          </span>
          <button
            type="button"
            className={`btn btn-ghost text-xs ${pushOn && pushPerm === 'granted' ? 'text-[var(--accent)]' : ''}`}
            onClick={togglePush}
            title={pushPerm === 'denied' ? 'Notifications blocked by browser' : 'Desktop notifications'}
          >
            {pushOn && pushPerm === 'granted' ? 'Push on' : 'Push off'}
          </button>
          <button type="button" className="btn btn-ghost text-xs" onClick={() => setPaused((p) => !p)}>
            {paused ? 'Resume' : 'Pause'}
          </button>
          <button type="button" className="btn btn-ghost text-xs" onClick={() => setEvents([])}>
            Clear
          </button>
        </div>
      </div>
      <div className="max-h-64 overflow-auto space-y-1.5 mono text-xs px-4 py-3">
        {events.length === 0 ? (
          <p className="text-[var(--muted)] font-sans py-4">No errors yet. Healthy.</p>
        ) : (
          events.map((e) => (
            <div
              key={e.id}
              className={`rounded-[var(--radius)] border px-2.5 py-1.5 ${
                e.level === 'error'
                  ? 'border-[var(--danger)]/40 bg-[color-mix(in_srgb,var(--danger)_10%,transparent)]'
                  : 'border-[var(--warn)]/30 bg-[color-mix(in_srgb,var(--warn)_6%,transparent)]'
              }`}
            >
              <div className="flex flex-wrap gap-x-2 gap-y-0.5 text-[var(--muted)]">
                <span>{formatEventTime(e.time)}</span>
                <span className={e.level === 'error' ? 'text-[var(--danger)]' : 'text-[var(--warn)]'}>
                  {e.level}
                </span>
                <span className="text-[var(--accent)]">{e.kind}</span>
              </div>
              <div className="text-[var(--text)] mt-0.5">{e.message}</div>
              {e.attrs && Object.keys(e.attrs).length ? (
                <div className="text-[var(--muted)] mt-0.5 truncate">
                  {Object.entries(e.attrs)
                    .filter(([k]) => k !== 'kind')
                    .map(([k, v]) => `${k}=${v}`)
                    .join(' · ')}
                </div>
              ) : null}
            </div>
          ))
        )}
      </div>
    </section>
  )
}

export default function Dashboard() {
  const [data, setData] = useState(null)
  const [err, setErr] = useState('')

  useEffect(() => {
    let alive = true
    const load = () =>
      api
        .dashboard()
        .then((d) => {
          if (alive) {
            setData(d)
            setErr('')
          }
        })
        .catch((e) => {
          if (alive) setErr(e.message || 'Connection lost')
        })
    load()
    const timer = setInterval(load, 5000)
    return () => {
      alive = false
      clearInterval(timer)
    }
  }, [])

  if (err && !data) return <ErrorBox msg={err} />
  if (!data) return <LoadingBlock label="Loading dashboard" />

  const s = data.status
  const anomaly = data.anomaly || { alerts: [] }
  const anomalyAlerts = anomaly.alerts || []
  const mon = data.monitor || {}
  const health = data.health || { checks: {}, status: '—' }
  const checks = health.checks || {}
  const dataplane = data.dns_dataplane || s.dns_dataplane || 'powersvx'
  const isDnsdist = dataplane === 'dnsdist'
  const isUnboundDP = dataplane === 'unbound'
  const planeLabel = isDnsdist ? 'dnsdist + CDB' : isUnboundDP ? 'Unbound RPZ' : 'PowerSVX edge'
  const qpsChart = (mon.qps_series || []).map((p) => ({
    t: new Date((p.t || 0) * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    qps: Number(p.qps || 0),
  }))
  const lat = mon.latency || {}
  const res = mon.resources || {}
  const hostAvailGiB = Number(res.host_mem_available_mb || 0) / 1024
  const hostTotalGiB = Number(res.host_mem_total_mb || 0) / 1024
  const diskUsed = Number(res.disk_used_pct || 0)
  const memUsed = Number(res.host_mem_used_pct || 0)
  const cdbEntries = checks.rpz?.entries ?? s.rpz_entries ?? 0
  const healthItems = [
    ['DNS :53', checks.dns_udp],
    ['Dataplane', checks.dns_dataplane || { status: 'pass', engine: planeLabel }],
    ['Unbound', checks.unbound || (isDnsdist || isUnboundDP ? { status: '—' } : { status: 'disabled' })],
    ['Database', checks.database],
    ['Blocklist', checks.rpz || { status: 'pass', entries: cdbEntries, engine: isDnsdist ? 'cdb' : 'rpz' }],
    ['API process', checks.resources],
  ]

  return (
    <div className="space-y-7">
      <PageHeader
        eyebrow="Operate"
        title="Dashboard"
        sub={`${releaseLabel(s) || `v${s.version || ''}`} · uptime ${formatUptime(s.uptime_seconds)} · ${planeLabel} · QPS ${Number(mon.qps_now || 0).toFixed(0)}`}
        actions={
          <div className="flex items-center gap-2">
            {err ? (
              <span className="badge-chip off text-xs flex items-center gap-1.5" title={err}>
                <span className="badge-dot" /> Reconnecting…
              </span>
            ) : null}
            <a href="/analytics" className="btn btn-secondary">
              Analytics
            </a>
          </div>
        }
      />

      <div className="flex flex-wrap gap-2 reveal reveal-delay-1">
        <Badge on={isDnsdist} label={isDnsdist ? 'Edge: dnsdist' : isUnboundDP ? 'Edge: Unbound' : 'Edge: PowerSVX'} />
        <Badge on={isDnsdist || !!s.rpz_enabled} label={isDnsdist ? 'CDB blocklist' : 'RPZ'} />
        <Badge on={isDnsdist || isUnboundDP} label="Backend Unbound" />
        {!isDnsdist && !isUnboundDP ? (
          <>
            <Badge on={s.dot_enabled} label="DoT" />
            <Badge on={s.doh_enabled} label="DoH" />
          </>
        ) : null}
      </div>

      <section className="panel overflow-hidden reveal reveal-delay-1">
        <div className="px-4 py-3 border-b border-[var(--border)] flex flex-wrap items-center justify-between gap-2">
          <h2 className="section-title mb-0">Health</h2>
          <span className={`status-pill ${health.status === 'healthy' ? 'ok' : 'warn'}`}>
            <span className={`pulse-dot ${health.status === 'healthy' ? 'on' : ''}`} aria-hidden />
            {health.status || '—'}
          </span>
        </div>
        <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 divide-x divide-y lg:divide-y-0 divide-[var(--border)]">
          {healthItems.map(([label, c]) => {
            const st = c?.status || '—'
            const ok = st === 'pass' || st === 'idle' || st === 'disabled'
            return (
              <div key={label} className="px-4 py-3.5">
                <div className="text-xs text-[var(--muted)]">{label}</div>
                <div className={`mono text-sm mt-1 ${ok || st === '—' ? '' : 'text-[var(--warn)]'}`}>
                  {c?.engine || st}
                </div>
                {c?.latency_ms != null ? (
                  <div className="text-xs text-[var(--muted)] mt-1">{c.latency_ms} ms</div>
                ) : null}
                {c?.addr ? <div className="text-xs text-[var(--muted)] truncate mono mt-0.5">{c.addr}</div> : null}
                {c?.backend ? <div className="text-xs text-[var(--muted)] truncate mono mt-0.5">{c.backend}</div> : null}
                {c?.entries != null ? (
                  <div className="text-xs text-[var(--muted)] mt-1 mono">{Number(c.entries).toLocaleString()} names</div>
                ) : null}
                {c?.reason ? <div className="text-xs text-[var(--warn)] mt-1">{c.reason}</div> : null}
                {label === 'API process' && c?.goroutines != null ? (
                  <div className="text-xs text-[var(--muted)] mt-1 mono">
                    {c.goroutines} g · {Number(c.rss_mb || 0).toFixed(0)} MB
                  </div>
                ) : null}
              </div>
            )
          })}
        </div>
      </section>

      <div className="metric-rail reveal reveal-delay-2">
        <Metric
          label="QPS"
          value={Number(mon.qps_now || 0).toFixed(0)}
          sub={`total ${Number(mon.queries_total ?? s.queries_total ?? 0).toLocaleString()}`}
        />
        <Metric
          label="Blocked"
          value={`${Number(mon.blocked_percent || 0).toFixed(1)}%`}
          sub={`${Number(mon.blocked_total ?? 0).toLocaleString()} · list ${Number(cdbEntries).toLocaleString()}`}
        />
        <Metric
          label="Host RAM free"
          value={hostAvailGiB > 0 ? `${hostAvailGiB.toFixed(1)} GiB` : '—'}
          sub={
            hostTotalGiB > 0
              ? `${memUsed.toFixed(0)}% used of ${hostTotalGiB.toFixed(0)} GiB · load ${Number(res.load1 || 0).toFixed(2)}`
              : `API CPU ${Number(res.cpu_percent || 0).toFixed(1)}% · RSS ${Number(res.rss_mb || 0).toFixed(0)} MB`
          }
        />
        <Metric
          label="Disk / latency"
          value={diskUsed > 0 ? `${diskUsed.toFixed(0)}%` : `${Number(lat.p95_ms || 0).toFixed(0)} ms`}
          sub={
            diskUsed > 0
              ? `${Number(res.disk_used_gb || 0).toFixed(0)} / ${Number(res.disk_total_gb || 0).toFixed(0)} GiB root`
              : isDnsdist || isUnboundDP
                ? `cache ${Number(s.cache_hits || 0).toLocaleString()} / ${Number(s.cache_misses || 0).toLocaleString()}`
                : `p50 ${Number(lat.p50_ms || 0).toFixed(1)} · p99 ${Number(lat.p99_ms || 0).toFixed(1)}`
          }
        />
      </div>

      <div className="text-xs text-[var(--muted)] px-1 reveal reveal-delay-2">
        {isDnsdist
          ? 'Live QPS from dnsdist edge. Host RAM/disk from the API host (/proc). Longer CPU/disk trends → Analytics (Grafana + node-exporter).'
          : isUnboundDP
            ? 'Live QPS from Unbound. Host RAM/disk from the API host. Trends → Analytics.'
            : 'Go-edge resolver. Host RAM/disk from this process host.'}
      </div>

      <div className="bento bento-hero reveal reveal-delay-2">
        <section className="panel chart-panel">
          <h2>QPS (15 min)</h2>
          {qpsChart.length ? (
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={qpsChart}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                <XAxis dataKey="t" stroke="var(--muted)" fontSize={10} minTickGap={28} />
                <YAxis stroke="var(--muted)" fontSize={12} allowDecimals={false} />
                <Tooltip contentStyle={chartTip} />
                <Area type="monotone" dataKey="qps" stroke="var(--accent)" fill="var(--accent)" fillOpacity={0.18} />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <EmptyState title="Waiting for traffic" hint="QPS series fills as queries arrive." />
          )}
        </section>
        <section className="panel p-4">
          <h2 className="section-title mb-1">Host resources</h2>
          <p className="text-xs text-[var(--muted)] mb-3">Machine running the control plane (and DNS on host-net).</p>
          <div className="grid grid-cols-2 gap-3">
            <Stat label="Mem available" value={hostAvailGiB > 0 ? `${hostAvailGiB.toFixed(1)} GiB` : '—'} />
            <Stat label="Mem used" value={memUsed > 0 ? `${memUsed.toFixed(0)}%` : '—'} />
            <Stat label="Disk used" value={diskUsed > 0 ? `${diskUsed.toFixed(0)}%` : '—'} />
            <Stat label="Load 1m" value={Number(res.load1 || 0) > 0 ? Number(res.load1).toFixed(2) : '—'} />
          </div>
          <div className="mt-4 pt-3 border-t border-[var(--border)] text-xs text-[var(--muted)] mono space-y-1">
            <div>
              API RSS {Number(res.rss_mb || 0).toFixed(0)} MB · CPU {Number(res.cpu_percent || 0).toFixed(1)}% ·{' '}
              {res.num_cpu ?? '—'} cores · {res.goroutines ?? '—'} g
            </div>
            <a href="/analytics" className="text-[var(--accent)] hover:underline underline-offset-4">
              Open Analytics for host CPU / disk charts →
            </a>
          </div>
        </section>
      </div>

      <div className="bento bento-lists reveal reveal-delay-3">
        <section className="panel p-4">
          <div className="flex items-center justify-between gap-2 mb-2">
            <h2 className="section-title mb-0">Top blocked</h2>
            <a href="/domains" className="text-xs text-[var(--accent)] hover:underline underline-offset-4">
              Domains
            </a>
          </div>
          {(mon.top_blocked || []).length ? (
            <>
              <ul>
                {mon.top_blocked.slice(0, 15).map((n, i) => (
                  <li key={n.key} className="data-row text-sm mono" style={{ '--index': i }}>
                    <span className="truncate">{n.key}</span>
                    <span className="text-[var(--warn)] shrink-0">{n.count}</span>
                  </li>
                ))}
              </ul>
              {(mon.blocked_cover || []).length ? (
                <p className="text-xs text-[var(--muted)] mt-2 mono">
                  cover{' '}
                  {mon.blocked_cover.map((c) => `top${c.n}=${Number(c.percent).toFixed(0)}%`).join(' · ')}
                </p>
              ) : null}
            </>
          ) : (
            <EmptyState
              title="No live block samples"
              hint={
                isDnsdist
                  ? 'CDB spoofs at dnsdist; sample tops appear when the monitor bridge fills. Manage list in Domains.'
                  : 'Appears when the dataplane reports blocked qnames.'
              }
            />
          )}
        </section>

        <section className="panel p-4">
          <div className="flex items-center justify-between gap-2 mb-2">
            <h2 className="section-title mb-0">Top clients</h2>
            <a href="/settings" className="text-xs text-[var(--accent)] hover:underline underline-offset-4">
              Settings
            </a>
          </div>
          {(mon.top_clients || []).length ? (
            <ul>
              {mon.top_clients.map((n, i) => (
                <li key={n.key} className="data-row text-sm mono" style={{ '--index': i }}>
                  <span className="truncate">{n.key}</span>
                  <span className="shrink-0">{n.count}</span>
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState title="No client samples" hint="Fills when the edge monitor has per-client counters." />
          )}
          {(mon.top_subnets || []).length ? (
            <div className="mt-4 pt-3 border-t border-[var(--border)]">
              <h3 className="text-xs text-[var(--muted)] mb-1">Top subnets</h3>
              <ul>
                {mon.top_subnets.map((n, i) => (
                  <li key={n.key} className="data-row text-sm mono" style={{ '--index': i }}>
                    <span className="truncate">{n.key}</span>
                    <span className="shrink-0 text-[var(--accent)]">{n.count}</span>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </section>
      </div>

      <div className="bento bento-split reveal reveal-delay-3">
        <section className="panel p-4">
          <h2 className="section-title mb-1">Anomaly alerts</h2>
          <p className="text-xs text-[var(--muted)] mb-3">
            EWMA spike detector · baseline QPS {anomaly.qps_baseline ?? '—'} · errors {anomaly.error_baseline ?? '—'}
          </p>
          {anomalyAlerts.length ? (
            <ul className="space-y-2 text-sm max-h-56 overflow-auto">
              {anomalyAlerts.map((a, i) => (
                <li
                  key={`${a.time}-${a.kind}-${i}`}
                  className="border border-[var(--warn)]/40 bg-[color-mix(in_srgb,var(--warn)_10%,transparent)] px-2.5 py-2 rounded-[var(--radius)]"
                >
                  <div className="text-xs text-[var(--muted)] mono">{a.kind}</div>
                  <div>{a.message}</div>
                  <div className="text-xs text-[var(--muted)] mono mt-0.5">
                    score {Number(a.score).toFixed?.(2) ?? a.score} · cur {a.current} / base {a.baseline}
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-[var(--muted)]">No spikes detected yet.</p>
          )}
        </section>
        <section className="panel p-4">
          <h2 className="section-title mb-1">ACL</h2>
          {mon.acl_open_resolver ? (
            <p className="text-xs text-[var(--warn)] mb-3 border border-[var(--warn)]/40 bg-[color-mix(in_srgb,var(--warn)_10%,transparent)] px-2.5 py-2 rounded-[var(--radius)]">
              Open resolver: allow_query is empty — any client may query. Restrict in Settings.
            </p>
          ) : (
            <p className="text-xs text-[var(--muted)] mb-3">
              {isDnsdist ? 'Public ACL is on dnsdist; control-plane auth is separate.' : 'Query ACL is restricted.'}
            </p>
          )}
          <div className="grid grid-cols-2 gap-3 mb-3">
            <Stat label="Allowed" value={mon.acl_allow ?? 0} />
            <Stat label="Denied" value={mon.acl_deny ?? 0} />
          </div>
          <a href="/lookup" className="text-xs text-[var(--accent)] hover:underline underline-offset-4">
            Test a name with Lookup →
          </a>
        </section>
      </div>

      <div className="reveal reveal-delay-4">
        <LiveErrorLog />
      </div>
    </div>
  )
}
