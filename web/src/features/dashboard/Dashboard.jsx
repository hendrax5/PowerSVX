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
  const [actionMsg, setActionMsg] = useState('')

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
  if (!data) return <LoadingBlock label="Loading dashboard telemetry" />

  const s = data.status || {}
  const anomaly = data.anomaly || { alerts: [] }
  const anomalyAlerts = anomaly.alerts || []
  const mon = data.monitor || {}
  const health = data.health || { checks: {}, status: '—' }
  const checks = health.checks || {}
  const dataplane = data.dns_dataplane || s.dns_dataplane || 'powersvx'
  const isDnsdist = dataplane === 'dnsdist'
  const isUnboundDP = dataplane === 'unbound'
  const planeLabel = isDnsdist ? 'dnsdist + CDB' : isUnboundDP ? 'Unbound RPZ' : 'PowerSVX Edge'
  
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

  const isUnboundBackend =
    isDnsdist ||
    isUnboundDP ||
    (s.forwarders || []).some((f) => f.includes('5353')) ||
    s.resolver_mode === 'unbound' ||
    checks.unbound?.status === 'pass' ||
    checks.unbound?.status === 'fail' ||
    checks.unbound?.status === 'degraded'

  const cdbEntries = checks.rpz?.entries ?? s?.rpz_entries ?? 0
  const totalQueries = Number(mon.queries_total ?? s.queries_total ?? 0)
  const blockedTotal = Number(mon.blocked_total ?? 0)
  const blockedPercent = mon.blocked_percent != null ? Number(mon.blocked_percent).toFixed(1) : '0.0'
  const qpsNow = Number(mon.qps_now || 0).toFixed(0)

  // Unbound cache statistics
  const unboundStats = checks.unbound?.stats || {}
  const cacheHits = Number(unboundStats['total.num.cachehits'] ?? s.cache_hits ?? 0)
  const cacheMisses = Number(unboundStats['total.num.cachemiss'] ?? s.cache_misses ?? 0)
  const totalCacheReqs = cacheHits + cacheMisses
  const cacheHitRatio = totalCacheReqs > 0 ? ((cacheHits / totalCacheReqs) * 100).toFixed(1) : '0.0'
  const avgLatencyMs = unboundStats['total.recursion.time.avg']
    ? (Number(unboundStats['total.recursion.time.avg']) * 1000).toFixed(1)
    : lat.p50_ms != null
      ? Number(lat.p50_ms).toFixed(1)
      : null

  // Top blocked items with proportional fill calculation (AdGuard Home grammar)
  const topBlocked = mon.top_blocked || []
  const maxBlockedCount = topBlocked.length ? Math.max(...topBlocked.map((b) => Number(b.count) || 1), 1) : 1

  // Top clients with proportional fill calculation
  const topClients = mon.top_clients || []
  const maxClientCount = topClients.length ? Math.max(...topClients.map((c) => Number(c.count) || 1), 1) : 1

  // Quick Whitelist helper
  const handleQuickWhitelist = async (domain) => {
    try {
      await api.addWhitelist(domain)
      setActionMsg(`Whitelisted ${domain}`)
      setTimeout(() => setActionMsg(''), 4000)
    } catch (e) {
      setActionMsg(`Error: ${e.message}`)
    }
  }

  // Upstream Health checks (AWS Route53 grammar)
  const upstreamItems = [
    {
      name: 'Unbound Recursive Core',
      target: '127.0.0.1:5353',
      role: 'Recursive DNS Resolver & DNSSEC',
      status: checks.unbound?.status || (isUnboundBackend ? 'unknown' : 'disabled'),
      latency: avgLatencyMs != null ? `${avgLatencyMs} ms` : '—',
      detail: `${cacheHits.toLocaleString()} cache hits · ${cacheHitRatio}% hit ratio`,
    },
    {
      name: 'Edge Dataplane (dnsdist)',
      target: checks.dns_udp?.addr || '0.0.0.0:53',
      role: 'High-throughput UDP/TCP Listener & DoH/DoT',
      status: checks.dns_udp?.status || 'unknown',
      latency: checks.dns_udp?.latency_ms != null ? `${checks.dns_udp.latency_ms} ms` : '—',
      detail: planeLabel,
    },
    {
      name: 'Kominfo AXFR / RPZ Filter',
      target: '182.23.79.202:53',
      role: 'Official National Blocklist & CDB Fast Spoofing',
      status: checks.rpz?.status || (cdbEntries > 0 ? 'pass' : 'disabled'),
      latency: cdbEntries > 0 ? 'Instant (CDB)' : '—',
      detail: `${Number(cdbEntries).toLocaleString()} domains synced`,
    },
    {
      name: 'PostgreSQL Relational DB',
      target: '127.0.0.1:5432',
      role: 'Authoritative Zones & Config Storage',
      status: checks.database?.status || 'disabled',
      latency: checks.database?.latency_ms != null ? `${checks.database.latency_ms} ms` : '—',
      detail: checks.database?.status === 'pass' ? 'Connection pool active' : checks.database?.status || 'not enabled',
    },
  ]

  return (
    <div className="space-y-6">
      {/* AdGuard Home Style Hero Protection Banner */}
      <section className="protection-hero-banner reveal">
        <div className="flex items-center gap-3.5">
          <div className="w-11 h-11 rounded-full bg-[var(--ok)]/15 border border-[var(--ok)]/35 text-[var(--ok)] flex items-center justify-center text-xl shrink-0">
            <span className="pulse-dot on scale-125" aria-hidden />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h2 className="text-base font-semibold text-[var(--text)] tracking-tight">
                PowerSVX Active Protection: Operational
              </h2>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-[var(--ok)]/15 text-[var(--ok)] font-medium border border-[var(--ok)]/30">
                HEALTHY
              </span>
            </div>
            <p className="text-xs text-[var(--muted)] mt-0.5">
              Engine: <strong className="text-[var(--text)]">{planeLabel}</strong> · Filtering{' '}
              <strong className="text-[var(--ok)]">{Number(cdbEntries).toLocaleString()} rules</strong> (Kominfo AXFR
              CDB) · Resolving via{' '}
              <strong className="text-[var(--text)]">Unbound (127.0.0.1:5353)</strong>
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {actionMsg ? (
            <span className="text-xs text-[var(--ok)] px-2.5 py-1 rounded bg-[var(--ok)]/10 border border-[var(--ok)]/30 mono">
              {actionMsg}
            </span>
          ) : null}
          <a href="/domains" className="btn btn-secondary text-xs">
            Manage Filter Feeds
          </a>
          <a href="/analytics" className="btn btn-primary text-xs">
            Grafana Analytics
          </a>
        </div>
      </section>

      {/* 4 Hero KPI Cards (AdGuard Home + Cloudflare Grammar) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 reveal reveal-delay-1">
        {/* Metric 1: Total Queries */}
        <div className="stat-card p-4 flex flex-col justify-between relative overflow-hidden border border-[var(--border)]">
          <div className="flex items-center justify-between">
            <span className="label-quiet">DNS Queries Total</span>
            <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-[var(--accent-soft)] text-[var(--accent)] font-semibold border border-[var(--accent)]/30 flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-[var(--accent)] animate-pulse" />
              {qpsNow} QPS
            </span>
          </div>
          <div className="mt-3">
            <div className="text-3xl font-bold mono tracking-tight text-[var(--text)] tabular-nums">
              {totalQueries.toLocaleString()}
            </div>
            <div className="text-xs text-[var(--muted)] mt-1">
              Real-time resolver traffic across all network listeners
            </div>
          </div>
          <div className="mt-4 pt-3 border-t border-[var(--border)]/60 flex items-center justify-between text-[11px] text-[var(--muted)]">
            <span>Uptime: {formatUptime(s.uptime_seconds)}</span>
            <span className="mono">v{s.version || '—'}</span>
          </div>
        </div>

        {/* Metric 2: Blocked Queries */}
        <div className="stat-card p-4 flex flex-col justify-between relative overflow-hidden border border-[var(--border)]">
          <div className="flex items-center justify-between">
            <span className="label-quiet">Blocked by Protection</span>
            <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-red-500/10 text-red-400 font-semibold border border-red-500/30">
              {blockedPercent}% BLOCKED
            </span>
          </div>
          <div className="mt-3">
            <div className="text-3xl font-bold mono tracking-tight text-red-400 tabular-nums">
              {blockedTotal.toLocaleString()}
            </div>
            <div className="text-xs text-[var(--muted)] mt-1">
              Threats &amp; unauthorized domains spoofed to NXDOMAIN
            </div>
          </div>
          <div className="mt-4 pt-3 border-t border-[var(--border)]/60 flex items-center justify-between text-[11px] text-[var(--muted)]">
            <span>Rules active</span>
            <span className="text-[var(--text)] font-mono">{Number(cdbEntries).toLocaleString()}</span>
          </div>
        </div>

        {/* Metric 3: Response Latency */}
        <div className="stat-card p-4 flex flex-col justify-between relative overflow-hidden border border-[var(--border)]">
          <div className="flex items-center justify-between">
            <span className="label-quiet">Average Latency</span>
            <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-[var(--ok)]/10 text-[var(--ok)] font-semibold border border-[var(--ok)]/30">
              {avgLatencyMs != null && Number(avgLatencyMs) < 1 ? 'SUB-MILLISECOND' : 'RESOLVER RTT'}
            </span>
          </div>
          <div className="mt-3">
            <div className="text-3xl font-bold mono tracking-tight text-[var(--text)] tabular-nums">
              {avgLatencyMs != null ? avgLatencyMs : '—'}{' '}
              {avgLatencyMs != null ? <span className="text-lg font-normal text-[var(--muted)]">ms</span> : null}
            </div>
            <div className="text-xs text-[var(--muted)] mt-1">
              Recursive resolve &amp; CDB memory lookup latency
            </div>
          </div>
          <div className="mt-4 pt-3 border-t border-[var(--border)]/60 flex items-center justify-between text-[11px] text-[var(--muted)]">
            <span>P95 latency</span>
            <span className="font-mono text-[var(--text)]">{lat.p95_ms != null ? `${Number(lat.p95_ms).toFixed(0)} ms` : '—'}</span>
          </div>
        </div>

        {/* Metric 4: Cache & System Load */}
        <div className="stat-card p-4 flex flex-col justify-between relative overflow-hidden border border-[var(--border)]">
          <div className="flex items-center justify-between">
            <span className="label-quiet">Cache &amp; Host Resources</span>
            <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-[var(--info)]/10 text-[var(--info)] font-semibold border border-[var(--info)]/30">
              {cacheHitRatio}% HITS
            </span>
          </div>
          <div className="mt-3">
            <div className="text-3xl font-bold mono tracking-tight text-[var(--text)] tabular-nums">
              {hostAvailGiB > 0 ? `${hostAvailGiB.toFixed(1)}` : '—'}{' '}
              {hostAvailGiB > 0 ? <span className="text-lg font-normal text-[var(--muted)]">GiB free</span> : null}
            </div>
            <div className="text-xs text-[var(--muted)] mt-1">
              Host RAM: {memUsed.toFixed(0)}% used · Load: {Number(res.load1 || 0).toFixed(2)}
            </div>
          </div>
          <div className="mt-4 pt-3 border-t border-[var(--border)]/60 flex items-center justify-between text-[11px] text-[var(--muted)]">
            <span>Cache hits / total</span>
            <span className="font-mono text-[var(--text)]">
              {cacheHits.toLocaleString()} / {totalCacheReqs.toLocaleString()}
            </span>
          </div>
        </div>
      </div>

      {/* Cloudflare Style Traffic Telemetry Chart */}
      <section className="panel p-5 space-y-4 reveal reveal-delay-2">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--border)] pb-3">
          <div>
            <h2 className="text-sm font-semibold text-[var(--text)] flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-[var(--accent)]" />
              DNS Query Volume (15-Minute Rolling Window)
            </h2>
            <p className="text-xs text-[var(--muted)] mt-0.5">
              Real-time query ingestion rate across all UDP, TCP, and DoH sockets
            </p>
          </div>
          <div className="flex items-center gap-3 text-xs mono text-[var(--muted)]">
            <span className="flex items-center gap-1.5">
              <span className="w-3 h-1.5 rounded-sm bg-[var(--accent)]" /> Live QPS
            </span>
            <span>Current: <strong className="text-[var(--text)]">{qpsNow} queries/sec</strong></span>
          </div>
        </div>

        {qpsChart.length ? (
          <ResponsiveContainer width="100%" height={230}>
            <AreaChart data={qpsChart}>
              <defs>
                <linearGradient id="cfQpsGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="var(--accent)" stopOpacity={0.35} />
                  <stop offset="95%" stopColor="var(--accent)" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" opacity={0.6} />
              <XAxis dataKey="t" stroke="var(--muted)" fontSize={11} minTickGap={30} />
              <YAxis stroke="var(--muted)" fontSize={11} allowDecimals={false} />
              <Tooltip contentStyle={chartTip} />
              <Area
                type="monotone"
                dataKey="qps"
                stroke="var(--accent)"
                strokeWidth={2}
                fill="url(#cfQpsGrad)"
              />
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <EmptyState title="Waiting for telemetry traffic" hint="The QPS chart fills continuously as queries arrive." />
        )}
      </section>

      {/* AdGuard Home Proportional Lists: Top Blocked Domains & Top Client IPs */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 reveal reveal-delay-3">
        {/* Top Blocked Domains */}
        <section className="panel p-4 space-y-3">
          <div className="flex items-center justify-between gap-2 border-b border-[var(--border)] pb-2.5">
            <div>
              <h2 className="text-sm font-semibold text-[var(--text)]">Top Blocked Domains</h2>
              <p className="text-xs text-[var(--muted)] mt-0.5">
                Domains intercepted by CDB / RPZ with proportional query distribution
              </p>
            </div>
            <a href="/domains" className="text-xs text-[var(--accent)] hover:underline">
              Manage Rules →
            </a>
          </div>

          {topBlocked.length ? (
            <div className="space-y-2 max-h-[360px] overflow-auto pr-1">
              {topBlocked.slice(0, 10).map((item, idx) => {
                const count = Number(item.count) || 0
                const pct = Math.min(100, Math.max(8, (count / maxBlockedCount) * 100))
                return (
                  <div key={item.key || idx} className="ag-bar-row">
                    <div
                      className="ag-bar-fill ag-bar-fill-danger"
                      style={{ width: `${pct}%` }}
                      aria-hidden
                    />
                    <div className="ag-bar-content">
                      <div className="flex items-center gap-2.5 truncate pr-2">
                        <span className="text-[11px] font-mono text-[var(--muted)] w-5 shrink-0">
                          #{idx + 1}
                        </span>
                        <span className="text-xs font-mono text-[var(--text)] truncate font-medium">
                          {item.key}
                        </span>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <span className="text-xs font-mono text-red-400 font-semibold tabular-nums">
                          {count.toLocaleString()}
                        </span>
                        <button
                          type="button"
                          onClick={() => handleQuickWhitelist(item.key)}
                          className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-[var(--bg-panel)] border border-[var(--border)] text-[var(--muted)] hover:text-[var(--text)] hover:border-[var(--accent)]"
                          title="Whitelist domain"
                        >
                          Allow
                        </button>
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          ) : (
            <EmptyState
              title="No blocked queries recorded yet"
              hint="Blocked queries will appear here automatically with real-time volume bars as traffic hits blocked domains."
            />
          )}
        </section>

        {/* Top Clients */}
        <section className="panel p-4 space-y-3">
          <div className="flex items-center justify-between gap-2 border-b border-[var(--border)] pb-2.5">
            <div>
              <h2 className="text-sm font-semibold text-[var(--text)]">Top Client Devices</h2>
              <p className="text-xs text-[var(--muted)] mt-0.5">
                Client IPs generating the highest DNS query volume
              </p>
            </div>
            <a href="/settings" className="text-xs text-[var(--accent)] hover:underline">
              Access Control →
            </a>
          </div>

          {topClients.length ? (
            <div className="space-y-2 max-h-[360px] overflow-auto pr-1">
              {topClients.slice(0, 10).map((item, idx) => {
                const count = Number(item.count) || 0
                const pct = Math.min(100, Math.max(8, (count / maxClientCount) * 100))
                return (
                  <div key={item.key || idx} className="ag-bar-row">
                    <div
                      className="ag-bar-fill"
                      style={{ width: `${pct}%` }}
                      aria-hidden
                    />
                    <div className="ag-bar-content">
                      <div className="flex items-center gap-2.5 truncate pr-2">
                        <span className="text-[11px] font-mono text-[var(--muted)] w-5 shrink-0">
                          #{idx + 1}
                        </span>
                        <span className="text-xs font-mono text-[var(--text)] truncate font-medium">
                          {item.key}
                        </span>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <span className="text-xs font-mono text-[var(--accent)] font-semibold tabular-nums">
                          {count.toLocaleString()}
                        </span>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--bg-panel)] border border-[var(--border)] text-[var(--muted)]">
                          CLIENT
                        </span>
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          ) : (
            <EmptyState
              title="No client query statistics yet"
              hint="Active client IPs and their query volumes will display here as queries are answered."
            />
          )}
        </section>
      </div>

      {/* AWS Route53 Style Upstream Resolvers & Health Checks Table */}
      <section className="panel p-5 space-y-3 reveal reveal-delay-3">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--border)] pb-3">
          <div>
            <h2 className="text-sm font-semibold text-[var(--text)]">
              Upstream Resolvers & Dataplane Health (Route53 Grammar)
            </h2>
            <p className="text-xs text-[var(--muted)] mt-0.5">
              Real-time connectivity and status of internal recursers, edge dataplane, and upstream datasets
            </p>
          </div>
          <span className="text-xs font-mono px-2 py-0.5 rounded bg-[var(--bg-elevated)] border border-[var(--border)] text-[var(--muted)]">
            {upstreamItems.filter((u) => u.status === 'pass' || u.status === 'healthy').length} / {upstreamItems.length} Active Targets
          </span>
        </div>

        <div className="cf-table-wrap">
          <table className="cf-table">
            <thead>
              <tr>
                <th>Target Component</th>
                <th>Socket / Endpoint</th>
                <th>Architecture Role</th>
                <th>Latency</th>
                <th>Status</th>
                <th>Operational Details</th>
              </tr>
            </thead>
            <tbody>
              {upstreamItems.map((u) => {
                const isPass = u.status === 'pass' || u.status === 'healthy'
                return (
                  <tr key={u.name}>
                    <td className="font-medium text-[var(--text)]">{u.name}</td>
                    <td className="mono text-xs text-[var(--accent)]">{u.target}</td>
                    <td className="text-xs text-[var(--muted)]">{u.role}</td>
                    <td className="mono text-xs">{u.latency}</td>
                    <td>
                      <span className={`status-pill ${isPass ? 'ok' : 'warn'} text-xs`}>
                        <span className={`pulse-dot ${isPass ? 'on' : ''}`} aria-hidden />
                        {isPass ? 'HEALTHY' : u.status}
                      </span>
                    </td>
                    <td className="text-xs text-[var(--muted)] mono">{u.detail}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </section>

      {/* Live Error and Event Log Stream */}
      <div className="reveal reveal-delay-4">
        <LiveErrorLog />
      </div>
    </div>
  )
}

