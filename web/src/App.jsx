import { useEffect, useRef, useState } from 'react'
import { NavLink, Navigate, Route, Routes, useLocation, useNavigate, useParams } from 'react-router-dom'
import {
  ChartLine,
  ClipboardText,
  Gauge,
  GearSix,
  Globe,
  MagnifyingGlass,
  Scroll,
  Stack,
} from '@phosphor-icons/react'
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { api, setToken } from './api'
import { AuthCtx, useAuth } from './auth'
import Settings from './Settings'
import { ErrorBox, LoadingBlock, PageHeader } from './ui'

const ICON_WEIGHT = 'regular'
const chartTip = {
  background: 'var(--bg-elevated)',
  border: '1px solid var(--border)',
  borderRadius: 6,
  color: 'var(--text)',
  fontSize: 12,
}

function EmptyState({ title, hint, action }) {
  return (
    <div className="px-1 py-8 text-left" role="status">
      <p className="text-base font-semibold tracking-tight">{title}</p>
      {hint ? <p className="text-sm text-[var(--muted)] mt-2 max-w-[52ch] leading-relaxed">{hint}</p> : null}
      {action ? <div className="mt-5">{action}</div> : null}
    </div>
  )
}

function Shell({ children }) {
  const { me, refresh } = useAuth()
  const nav = useNavigate()
  const loc = useLocation()
  const navGroups = [
    {
      label: 'Operate',
      links: [
        ['/', 'Dashboard', Gauge],
        ['/domains', 'Domains', Globe],
        ['/zones', 'Zones', Stack],
        ['/lookup', 'Lookup', MagnifyingGlass],
      ],
    },
    {
      label: 'Observe',
      links: [
        ['/analytics', 'Analytics', ChartLine],
        ['/logs', 'Query logs', Scroll],
        ['/audit', 'Audit', ClipboardText],
      ],
    },
    {
      label: 'Configure',
      links: [['/settings', 'Settings', GearSix]],
    },
  ]
  const hereLabel =
    navGroups.flatMap((g) => g.links).find(([to]) => (to === '/' ? loc.pathname === '/' : loc.pathname.startsWith(to)))?.[1] ||
    'Dashboard'

  const logout = async () => {
    try {
      await api.logout()
    } catch {
      /* ignore */
    }
    setToken('')
    await refresh()
    nav('/login')
  }
  return (
    <div className="shell">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:z-[60] focus:top-3 focus:left-3 focus:bg-[var(--accent)] focus:text-[#17140f] focus:px-3 focus:py-2.5 focus:rounded-[var(--radius)]"
      >
        Skip to content
      </a>
      <aside className="shell-aside" aria-label="Sidebar">
        <div className="shell-brand reveal">
          <div className="brand-mark text-[clamp(1.4rem,2vw,1.7rem)]" aria-label="PowerSVX">
            <span>Power</span>
            <span className="svx">SVX</span>
          </div>
          <div className="crumb-live" aria-current="page">
            <span className="pulse-dot on" aria-hidden />
            <span>dns</span>
            <span aria-hidden>/</span>
            <strong>{hereLabel}</strong>
          </div>
        </div>
        <nav className="shell-nav" aria-label="Primary">
          {navGroups.map((group) => (
            <div key={group.label} className="shell-nav-group">
              <div className="shell-nav-label">{group.label}</div>
              {group.links.map(([to, label, Icon]) => (
                <NavLink
                  key={to}
                  to={to}
                  end={to === '/'}
                  className={({ isActive }) => `nav-link ${isActive ? 'is-active' : ''}`}
                >
                  <Icon className="nav-ico" size={18} weight={ICON_WEIGHT} aria-hidden />
                  {label}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
        <div className="shell-user space-y-2 text-xs">
          {me?.auth_required ? (
            <>
              <div className="text-[var(--muted)] px-1">
                <span className="text-[var(--text)] font-medium">{me.name}</span>
                <span className="mx-1.5 text-[var(--border-strong)]">·</span>
                <span className="text-[var(--accent)]">{me.role}</span>
              </div>
              <button type="button" onClick={logout} className="btn btn-secondary w-full">
                Log out
              </button>
            </>
          ) : (
            <div className="text-[var(--muted)] px-1">Open access</div>
          )}
        </div>
      </aside>
      <main id="main" tabIndex={-1} className="shell-main">
        <div className="shell-main-inner">{children}</div>
      </main>
    </div>
  )
}

function friendlyAuthError(raw) {
  const m = String(raw || '').toLowerCase()
  if (m.includes('unauthorized') || m.includes('401') || m.includes('forbidden') || m.includes('invalid credentials')) {
    return 'Sign-in failed. Check username and password.'
  }
  if (m.includes('too many')) {
    return 'Too many login attempts. Wait a minute and try again.'
  }
  if (m.includes('network') || m.includes('failed to fetch')) {
    return 'Cannot reach the server. Check that PowerSVX is running.'
  }
  return raw || 'Sign-in failed'
}

function LoginPage() {
  const { me, refresh } = useAuth()
  const nav = useNavigate()
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [err, setErr] = useState('')
  const [errDetail, setErrDetail] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (me && !me.auth_required) nav('/', { replace: true })
    if (me?.auth_required && me.name && me.name !== 'anonymous') nav('/', { replace: true })
  }, [me, nav])

  const submit = async (e) => {
    e.preventDefault()
    setBusy(true)
    setErr('')
    setErrDetail('')
    try {
      setToken('')
      await api.login(username, password)
      await refresh()
      nav('/', { replace: true })
    } catch (ex) {
      const raw = ex.message || 'Login failed'
      setErr(friendlyAuthError(raw))
      setErrDetail(raw)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login-shell">
      <div className="login-brand-pane">
        <div>
          <div className="brand-mark text-4xl md:text-5xl tracking-tighter">
            <span>Power</span>
            <span className="svx">SVX</span>
          </div>
          <p className="text-sm text-[var(--muted)] mt-5 max-w-[36ch] leading-relaxed">
            DNS control plane for resolve, filter, zones, and live ops.
          </p>
        </div>
        <p className="text-xs text-[var(--muted)] mono">recursive · rpz · axfr · observe</p>
      </div>
      <div className="login-form-pane">
        <form onSubmit={submit} className="login-card space-y-5 reveal">
          <div>
            <p className="eyebrow">Sign in</p>
            <h1 className="text-xl font-semibold tracking-tight">Local admin</h1>
            <p className="text-sm text-[var(--muted)] mt-2 leading-relaxed">
              Default user <span className="mono text-[var(--text)]">admin</span> — password from{' '}
              <span className="mono text-[var(--text)]">ADMIN_PASSWORD</span>.
            </p>
          </div>
          {err ? <ErrorBox msg={err} detail={errDetail !== err ? errDetail : undefined} /> : null}
          <label className="field label-quiet">
            Username
            <input
              className="input"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              required
            />
          </label>
          <label className="field label-quiet">
            Password
            <input
              type="password"
              className="input"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
            />
          </label>
          <button type="submit" disabled={busy} className="btn btn-primary w-full">
            {busy ? 'Signing in…' : 'Sign in'}
          </button>
        </form>
      </div>
    </div>
  )
}

function RequireAuth({ children }) {
  const { me, loading } = useAuth()
  if (loading) return <LoadingBlock label="Checking session" />
  if (me?.auth_required && (!me.name || me.name === 'anonymous')) {
    return <Navigate to="/login" replace />
  }
  return children
}

function Stat({ label, value, sub }) {
  return (
    <div className="stat-card px-3.5 py-3.5">
      <div className="label-quiet">{label}</div>
      <div className="text-[clamp(1.3rem,2vw,1.65rem)] font-semibold mt-1.5 mono leading-none tabular-nums tracking-tight">
        {value}
      </div>
      {sub ? <div className="text-[11px] text-[var(--muted)] mt-2 leading-snug">{sub}</div> : null}
    </div>
  )
}

function Metric({ label, value, sub }) {
  return (
    <div className="metric-cell">
      <div className="metric-label">{label}</div>
      <div className="metric-value">{value}</div>
      {sub ? <div className="metric-sub">{sub}</div> : null}
    </div>
  )
}

function Badge({ on, label }) {
  return (
    <span className={`badge-chip ${on ? 'on' : 'off'}`}>
      <span className="badge-dot" aria-hidden />
      {label}
    </span>
  )
}

function Dashboard() {
  const [data, setData] = useState(null)
  const [err, setErr] = useState('')

  useEffect(() => {
    let alive = true
    const load = () =>
      api
        .dashboard()
        .then((d) => alive && setData(d))
        .catch((e) => alive && setErr(e.message))
    load()
    const timer = setInterval(load, 5000)
    return () => {
      alive = false
      clearInterval(timer)
    }
  }, [])

  if (err) return <ErrorBox msg={err} />
  if (!data) return <LoadingBlock label="Loading dashboard" />

  const s = data.status
  const names = data.top_names || []
  const rcodes = data.rcodes || []
  const anomaly = data.anomaly || { alerts: [] }
  const anomalyAlerts = anomaly.alerts || []
  const mon = data.monitor || {}
  const health = data.health || { checks: {}, status: '—' }
  const checks = health.checks || {}
  const trafficChart = [
    { name: 'Hits', value: s.cache_hits },
    { name: 'Misses', value: s.cache_misses },
    { name: 'Queries', value: s.queries_total },
    { name: 'Limited', value: s.rate_limited },
  ]
  const rcodeChart = rcodes.map((r) => ({ name: r.rcode, value: r.count }))
  const qpsChart = (mon.qps_series || []).map((p) => ({
    t: new Date((p.t || 0) * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    qps: Number(p.qps || 0),
  }))
  const pathChart = (mon.paths || []).map((p) => ({ name: p.key, value: p.count }))
  const errChart = (mon.errors || []).map((p) => ({ name: p.key, value: p.count }))
  const lat = mon.latency || {}
  const res = mon.resources || {}
  const healthItems = [
    ['UDP :53', checks.dns_udp],
    ['Database', checks.database],
    ['Cache', checks.cache],
    ['Forwarders', checks.forwarders],
    ['Resolver', checks.resolver],
    ['Resources', checks.resources],
  ]

  return (
    <div className="space-y-7">
      <PageHeader
        eyebrow="Operate"
        title="Dashboard"
        sub={`v${s.version} · uptime ${formatUptime(s.uptime_seconds)} · mode ${s.mode} · QPS ${Number(mon.qps_now || 0).toFixed(0)}`}
        actions={
          <a href="/analytics" className="btn btn-secondary">
            Longer trends
          </a>
        }
      />

      <div className="flex flex-wrap gap-2 reveal reveal-delay-1">
        <Badge on={s.dot_enabled} label="DoT" />
        <Badge on={s.doh_enabled} label="DoH" />
        <Badge on={!!s.doh3_enabled} label="DoH3" />
        <Badge on={s.doq_enabled} label="DoQ" />
        <Badge on={s.rpz_enabled} label="RPZ" />
        <Badge on={s.ecs_enabled} label="ECS" />
        <Badge on={s.geodns_enabled} label="GeoDNS" />
        <Badge on={s.split_horizon_enabled} label="Split Horizon" />
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
                <div className={`mono text-sm mt-1 ${ok ? '' : 'text-[var(--warn)]'}`}>{st}</div>
                {c?.latency_ms != null ? (
                  <div className="text-xs text-[var(--muted)] mt-1">{c.latency_ms} ms</div>
                ) : null}
                {c?.addr ? <div className="text-xs text-[var(--muted)] truncate mono mt-0.5">{c.addr}</div> : null}
                {c?.reason ? <div className="text-xs text-[var(--warn)] mt-1">{c.reason}</div> : null}
                {label === 'Forwarders' && Array.isArray(c?.forwarders) && c.forwarders.length ? (
                  <ul className="mt-1 space-y-0.5 text-[10px] text-[var(--muted)] mono">
                    {c.forwarders.slice(0, 3).map((f) => {
                      const total = Number(f.ok || 0) + Number(f.fail || 0)
                      const pct = total ? Math.round((100 * Number(f.fail || 0)) / total) : 0
                      return (
                        <li key={f.addr} className="truncate" title={`${f.addr} ok=${f.ok} fail=${f.fail}`}>
                          {f.addr}: {pct}% fail
                        </li>
                      )
                    })}
                  </ul>
                ) : null}
                {label === 'Resources' && c?.goroutines != null ? (
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
        <Metric label="QPS" value={Number(mon.qps_now || 0).toFixed(0)} sub={`total ${mon.queries_total ?? s.queries_total}`} />
        <Metric
          label="Blocked"
          value={`${Number(mon.blocked_percent || 0).toFixed(1)}%`}
          sub={`${mon.blocked_total ?? 0} blocked · RPZ ${s.rpz_entries ?? 0}`}
        />
        <Metric
          label="Latency p50 / p95"
          value={`${Number(lat.p50_ms || 0).toFixed(1)} / ${Number(lat.p95_ms || 0).toFixed(1)}`}
          sub={`p99 ${Number(lat.p99_ms || 0).toFixed(1)} ms`}
        />
        <Metric
          label="CPU / RAM"
          value={`${Number(res.cpu_percent || 0).toFixed(1)}%`}
          sub={`RSS ${Number(res.rss_mb || 0).toFixed(0)} MB · ${res.num_cpu ?? '—'} cores · ${res.goroutines ?? '—'} g`}
        />
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
        <section className="panel chart-panel">
          <h2>Resolver path</h2>
          {pathChart.length ? (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={pathChart}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                <XAxis dataKey="name" stroke="var(--muted)" fontSize={10} interval={0} angle={-20} textAnchor="end" height={50} />
                <YAxis stroke="var(--muted)" fontSize={12} />
                <Tooltip contentStyle={chartTip} />
                <Bar dataKey="value" fill="var(--accent)" radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <EmptyState title="No path samples" hint="Appears after the resolver answers queries." />
          )}
        </section>
      </div>

      <div className="bento bento-split reveal reveal-delay-3">
        <section className="panel chart-panel">
          <h2>Error kinds</h2>
          {errChart.length ? (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={errChart}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                <XAxis dataKey="name" stroke="var(--muted)" fontSize={11} />
                <YAxis stroke="var(--muted)" fontSize={12} />
                <Tooltip contentStyle={chartTip} />
                <Bar dataKey="value" fill="var(--warn)" radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <EmptyState title="No errors recorded" hint="Error buckets stay empty while the resolver is healthy." />
          )}
        </section>
        <section className="panel chart-panel">
          <h2>RCODE distribution</h2>
          {rcodeChart.length ? (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={rcodeChart}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                <XAxis dataKey="name" stroke="var(--muted)" fontSize={11} />
                <YAxis stroke="var(--muted)" fontSize={12} />
                <Tooltip contentStyle={chartTip} />
                <Bar dataKey="value" fill="var(--muted)" radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <EmptyState title="No aggregates yet" hint="RCODE bars appear after query logging starts." />
          )}
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
            <ul>
              {mon.top_blocked.map((n, i) => (
                <li key={n.key} className="data-row text-sm mono" style={{ '--index': i }}>
                  <span className="truncate">{n.key}</span>
                  <span className="text-[var(--warn)] shrink-0">{n.count}</span>
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState title="No blocks yet" hint="Appears when RPZ or a plugin blocks a query." />
          )}
        </section>

        <section className="panel p-4">
          <div className="flex items-center justify-between gap-2 mb-2">
            <h2 className="section-title mb-0">Top clients</h2>
            <a href="/settings" className="text-xs text-[var(--accent)] hover:underline underline-offset-4">
              ACL
            </a>
          </div>
          {(mon.top_clients || []).length ? (
            <ul>
              {mon.top_clients.map((n, i) => (
                <li key={n.key} className="data-row text-sm mono" style={{ '--index': i }}>
                  <a className="truncate text-[var(--accent)]" href={`/logs?client_ip=${encodeURIComponent(n.key)}`}>
                    {n.key}
                  </a>
                  <span className="shrink-0">{n.count}</span>
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState title="No client traffic" hint="Appears after allowed queries arrive." />
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
          <h2 className="section-title">Recent queries</h2>
          {(mon.recent || []).length ? (
            <ul className="max-h-80 overflow-auto">
              {mon.recent.slice(0, 25).map((q, i) => (
                <li
                  key={`${q.time}-${q.qname}-${i}`}
                  className="data-row !items-start flex-col !justify-start gap-0.5"
                  style={{ '--index': i }}
                >
                  <div className="flex justify-between gap-2 w-full text-sm mono">
                    <span className={`truncate ${q.blocked ? 'text-[var(--warn)]' : ''}`}>{q.qname || '—'}</span>
                    <span className="text-xs text-[var(--muted)] shrink-0">{Number(q.ms || 0).toFixed(0)}ms</span>
                  </div>
                  <div className="text-xs text-[var(--muted)] flex justify-between gap-2 w-full mono">
                    <span className="truncate">{q.client_ip || '—'}</span>
                    <span>
                      {q.blocked ? 'blocked' : q.path} · {q.rcode}
                    </span>
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState title="No recent queries" hint="Live ring fills as DNS traffic arrives." />
          )}
        </section>

        <div className="space-y-4">
          <section className="panel p-4">
            <h2 className="section-title mb-1">ACL</h2>
            {mon.acl_open_resolver ? (
              <p className="text-xs text-[var(--warn)] mb-3 border border-[var(--warn)]/40 bg-[color-mix(in_srgb,var(--warn)_10%,transparent)] px-2.5 py-2 rounded-[var(--radius)]">
                Open resolver: allow_query is empty — any client may query. Restrict in Settings.
              </p>
            ) : (
              <p className="text-xs text-[var(--muted)] mb-3">Query ACL is restricted.</p>
            )}
            <div className="grid grid-cols-2 gap-3 mb-3">
              <Stat label="Allowed" value={mon.acl_allow ?? 0} />
              <Stat label="Denied" value={mon.acl_deny ?? 0} />
            </div>
            <a href="/settings" className="text-xs text-[var(--accent)] hover:underline underline-offset-4">
              Edit allow / deny lists
            </a>
          </section>

          <section className="panel p-4">
            <h2 className="section-title mb-1">Rate limit</h2>
            <p className="text-xs text-[var(--muted)] mb-3">
              Lifetime limited {mon.rate_limited_total ?? s.rate_limited ?? 0}
              {s.ratelimit_enabled ? '' : ' · limiter off'}
            </p>
            {(mon.rate_limit_active || []).length ? (
              <div className="mb-3">
                <h3 className="text-xs text-[var(--muted)] mb-1">Currently blocked</h3>
                <ul>
                  {mon.rate_limit_active.map((n, i) => (
                    <li key={n.key} className="data-row text-sm mono" style={{ '--index': i }}>
                      <span className="truncate">{n.key}</span>
                      <span className="text-[var(--warn)] shrink-0">{n.count}s</span>
                    </li>
                  ))}
                </ul>
              </div>
            ) : (
              <p className="text-xs text-[var(--muted)] mb-3">No active blocks.</p>
            )}
            {(mon.rate_limit_top || []).length ? (
              <div>
                <h3 className="text-xs text-[var(--muted)] mb-1">Top offenders</h3>
                <ul>
                  {mon.rate_limit_top.map((n, i) => (
                    <li key={n.key} className="data-row text-sm mono" style={{ '--index': i }}>
                      <span className="truncate">{n.key}</span>
                      <span className="shrink-0">{n.count}</span>
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
          </section>
        </div>
      </div>

      <div className="bento bento-split reveal reveal-delay-4">
        <section className="panel p-4">
          <h2 className="section-title">Top queried names</h2>
          {names.length ? (
            <ul className="max-h-56 overflow-auto">
              {names.map((n, i) => (
                <li key={n.name} className="data-row text-sm mono" style={{ '--index': i }}>
                  <span className="truncate">{n.name}</span>
                  <span className="text-[var(--accent)] shrink-0">{n.count}</span>
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState title="No queries yet" hint="Totals appear after DNS traffic hits this instance." />
          )}
        </section>
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
            <p className="text-sm text-[var(--muted)]">No spikes detected yet (needs a few windows of traffic).</p>
          )}
        </section>
      </div>

      <section className="panel chart-panel reveal reveal-delay-4">
        <h2>Traffic snapshot</h2>
        <ResponsiveContainer width="100%" height={180}>
          <BarChart data={trafficChart}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
            <XAxis dataKey="name" stroke="var(--muted)" fontSize={12} />
            <YAxis stroke="var(--muted)" fontSize={12} />
            <Tooltip contentStyle={chartTip} />
            <Bar dataKey="value" fill="var(--accent)" radius={[3, 3, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </section>

      <section className="reveal reveal-delay-4">
        <h2 className="section-title">Zones</h2>
        {data.zones?.length ? (
          <ul className="panel divide-y divide-[var(--border)] overflow-hidden">
            {data.zones.map((z) => (
              <li key={z.name} className="flex justify-between gap-3 px-4 py-3 text-sm">
                <span className="mono">{z.name}</span>
                <span className="text-[var(--muted)]">{z.record_count} records</span>
              </li>
            ))}
          </ul>
        ) : (
          <div className="panel px-4">
            <EmptyState
              title="No zones yet"
              hint="Add an authoritative zone to serve local records."
              action={
                <a href="/zones" className="btn btn-secondary">
                  Go to Zones
                </a>
              }
            />
          </div>
        )}
      </section>

      <div className="reveal reveal-delay-5">
        <LiveErrorLog />
      </div>
    </div>
  )
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

function formatEventTime(t) {
  try {
    return new Date(t).toLocaleTimeString()
  } catch {
    return t
  }
}

function Zones() {
  const { canWrite } = useAuth()
  const [zones, setZones] = useState([])
  const [secondary, setSecondary] = useState([])
  const [name, setName] = useState('')
  const [secName, setSecName] = useState('')
  const [secMasters, setSecMasters] = useState('')
  const [err, setErr] = useState('')
  const [secBusy, setSecBusy] = useState(false)
  const nav = useNavigate()

  const load = () =>
    Promise.all([api.zones(), api.secondary().catch(() => ({ zones: [] }))])
      .then(([d, sec]) => {
        setZones(d.zones || [])
        setSecondary(sec.zones || [])
      })
      .catch((e) => setErr(e.message))

  useEffect(() => {
    load()
  }, [])

  const create = async (e) => {
    e.preventDefault()
    setErr('')
    try {
      await api.createZone(name)
      setName('')
      await load()
    } catch (ex) {
      setErr(ex.message)
    }
  }

  const remove = async (z) => {
    if (!confirm(`Delete zone ${z}?`)) return
    try {
      await api.deleteZone(z)
      await load()
    } catch (ex) {
      setErr(ex.message)
    }
  }

  const addSecondary = async (e) => {
    e.preventDefault()
    setErr('')
    setSecBusy(true)
    try {
      const masters = String(secMasters || '')
        .split(/[\n,]+/)
        .map((x) => x.trim())
        .filter(Boolean)
      await api.upsertSecondary({ name: secName.trim(), masters })
      setSecName('')
      setSecMasters('')
      await load()
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setSecBusy(false)
    }
  }

  const transferSecondary = async (z) => {
    setErr('')
    setSecBusy(true)
    try {
      await api.transferSecondary(z)
      await load()
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setSecBusy(false)
    }
  }

  const removeSecondary = async (z) => {
    if (!confirm(`Remove secondary ${z}? (auth data left in store)`)) return
    setErr('')
    try {
      await api.deleteSecondary(z)
      await load()
    } catch (ex) {
      setErr(ex.message)
    }
  }

  return (
    <div className="space-y-6 max-w-4xl">
      <PageHeader
        eyebrow="Operate"
        title="Zones"
        sub="Authoritative zones, records, and secondary AXFR pulls."
      />
      {err ? <ErrorBox msg={err} /> : null}
      {canWrite ? (
        <form onSubmit={create} className="flex flex-col sm:flex-row gap-2 reveal">
          <input
            className="input flex-1 mono"
            placeholder="example.com"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
          />
          <button type="submit" className="btn btn-primary shrink-0">
            Add zone
          </button>
        </form>
      ) : (
        <p className="text-xs text-[var(--muted)]">Read-only role — zone create/delete disabled</p>
      )}
      <ul className="panel divide-y divide-[var(--border)] overflow-hidden reveal reveal-delay-1">
        {zones.length === 0 ? (
          <li className="px-4">
            <EmptyState title="No zones yet" hint="Add an authoritative zone to serve local records." />
          </li>
        ) : (
          zones.map((z, i) => (
            <li
              key={z.name}
              className="flex items-center justify-between gap-3 px-4 py-3"
              style={{ '--index': i }}
            >
              <button type="button" className="text-left" onClick={() => nav(`/zones/${encodeURIComponent(z.name)}`)}>
                <div className="mono font-medium">{z.name}</div>
                <div className="text-xs text-[var(--muted)]">{z.record_count} records</div>
              </button>
              {canWrite ? (
                <button type="button" className="btn btn-ghost text-xs text-[var(--danger)]" onClick={() => remove(z.name)}>
                  Delete
                </button>
              ) : null}
            </li>
          ))
        )}
      </ul>

      <section className="space-y-3 pt-2 reveal reveal-delay-2">
        <header>
          <p className="eyebrow">Secondary</p>
          <h2 className="text-xl font-semibold tracking-tight">AXFR pulls</h2>
          <p className="page-sub">
            Pull from masters. Inbound NOTIFY triggers transfer. IXFR from this server is answered as full AXFR.
          </p>
        </header>
        {canWrite ? (
          <form onSubmit={addSecondary} className="grid grid-cols-1 md:grid-cols-[1fr_1.4fr_auto] gap-2">
            <input
              className="input mono"
              placeholder="slave.example.com"
              value={secName}
              onChange={(e) => setSecName(e.target.value)}
              required
              disabled={secBusy}
            />
            <input
              className="input mono"
              placeholder="master IP:port (comma-separated)"
              value={secMasters}
              onChange={(e) => setSecMasters(e.target.value)}
              required
              disabled={secBusy}
            />
            <button type="submit" disabled={secBusy} className="btn btn-primary disabled:opacity-50">
              Add secondary
            </button>
          </form>
        ) : null}
        {secondary.length === 0 ? (
          <p className="text-sm text-[var(--muted)]">No secondary zones.</p>
        ) : (
          <ul className="panel divide-y divide-[var(--border)] overflow-hidden">
            {secondary.map((z) => (
              <li key={z.name} className="px-4 py-3 space-y-2">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div>
                    <div className="mono font-medium">{z.name}</div>
                    <div className="text-xs text-[var(--muted)] mono mt-0.5">
                      masters: {(z.masters || []).join(', ')}
                    </div>
                    <div className="text-xs text-[var(--muted)] mt-0.5">
                      serial {z.serial || 0}
                      {z.last_pull ? ` · last pull ${z.last_pull}` : ''}
                      {z.last_error ? ` · error: ${z.last_error}` : ''}
                    </div>
                  </div>
                  {canWrite ? (
                    <div className="flex gap-1">
                      <button
                        type="button"
                        disabled={secBusy}
                        className="btn btn-ghost text-xs disabled:opacity-50"
                        onClick={() => transferSecondary(z.name)}
                      >
                        Transfer now
                      </button>
                      <button
                        type="button"
                        className="btn btn-ghost text-xs text-[var(--danger)]"
                        onClick={() => removeSecondary(z.name)}
                      >
                        Remove
                      </button>
                    </div>
                  ) : null}
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  )
}

function ZoneDetail() {
  const { name } = useParams()
  const zone = decodeURIComponent(name)
  const [recs, setRecs] = useState([])
  const [meta, setMeta] = useState(null)
  const [err, setErr] = useState('')
  const [ok, setOk] = useState('')
  const [editing, setEditing] = useState(null)
  const [form, setForm] = useState({
    name: '',
    type: 'A',
    content: '',
    ttl: 3600,
    prio: 0,
    view: '',
    geo_tag: '',
  })
  const nav = useNavigate()

  const load = () =>
    Promise.all([api.getZone(zone), api.zoneDNSSEC(zone).catch(() => null)])
      .then(([d, dnssec]) => {
        setRecs(d.records || [])
        let m = d.meta || null
        if (dnssec?.enabled) {
          m = { ...(m || {}), dnssec_enabled: true, ds: dnssec.ds || (m && m.ds), signing: true }
        }
        setMeta(m)
      })
      .catch((e) => setErr(e.message))

  useEffect(() => {
    load()
  }, [zone])

  const resetForm = () => {
    setEditing(null)
    setForm({ name: '', type: 'A', content: '', ttl: 3600, prio: 0, view: '', geo_tag: '' })
  }

  const save = async (e) => {
    e.preventDefault()
    setErr('')
    setOk('')
    const payload = {
      ...form,
      ttl: Number(form.ttl) || 3600,
      prio: Number(form.prio) || 0,
    }
    try {
      if (editing) {
        await api.updateRecord(zone, {
          old_name: editing.name,
          old_type: editing.type,
          ...payload,
        })
        setOk('Record updated')
      } else {
        await api.addRecord(zone, payload)
        setOk('Record added')
      }
      resetForm()
      await load()
    } catch (ex) {
      setErr(ex.message)
    }
  }

  const startEdit = (r) => {
    setEditing(r)
    setForm({
      name: r.name || '',
      type: r.type || 'A',
      content: r.content || '',
      ttl: r.ttl || 3600,
      prio: r.prio || 0,
      view: r.view || '',
      geo_tag: r.geo_tag || '',
    })
    setOk('')
    setErr('')
  }

  const del = async (r) => {
    try {
      await api.deleteRecord(zone, r.name, r.type)
      if (editing && editing.name === r.name && editing.type === r.type) resetForm()
      await load()
    } catch (ex) {
      setErr(ex.message)
    }
  }

  const saveMeta = async (e) => {
    e.preventDefault()
    if (!meta) return
    setErr('')
    setOk('')
    try {
      const updated = await api.updateZoneMeta(zone, {
        dnssec_enabled: !!meta.dnssec_enabled,
        soa_serial: Number(meta.soa_serial) || 1,
        soa_refresh: Number(meta.soa_refresh) || 3600,
        soa_retry: Number(meta.soa_retry) || 600,
        soa_expire: Number(meta.soa_expire) || 86400,
        soa_minimum: Number(meta.soa_minimum) || 3600,
      })
      setMeta(updated)
      setOk('Zone meta saved (DB)')
    } catch (ex) {
      setErr(ex.message)
    }
  }

  return (
    <div className="space-y-6 max-w-5xl">
      <button type="button" className="btn btn-ghost text-sm mb-1" onClick={() => nav('/zones')}>
        Zones
      </button>
      <PageHeader eyebrow="Zone" title={<span className="mono">{zone}</span>} />
      {err ? <ErrorBox msg={err} /> : null}
      {ok ? <div className="flash-ok" role="status">{ok}</div> : null}

      {meta ? (
        <form onSubmit={saveMeta} className="panel p-4 space-y-3">
          <h2 className="text-sm font-medium">Zone meta (PostgreSQL)</h2>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
            {[
              ['soa_serial', 'SOA serial'],
              ['soa_refresh', 'refresh'],
              ['soa_retry', 'retry'],
              ['soa_expire', 'expire'],
              ['soa_minimum', 'minimum'],
            ].map(([k, label]) => (
              <label key={k} className="text-xs text-[var(--muted)] flex flex-col gap-1">
                {label}
                <input
                  className="input mono text-sm"
                  value={meta[k] ?? ''}
                  onChange={(e) => setMeta({ ...meta, [k]: e.target.value })}
                />
              </label>
            ))}
            <label className="text-xs text-[var(--muted)] flex items-center gap-2 mt-5">
              <input
                type="checkbox"
                checked={!!meta.dnssec_enabled}
                onChange={(e) => setMeta({ ...meta, dnssec_enabled: e.target.checked })}
              />
              DNSSEC signing (generates KSK/ZSK)
            </label>
          </div>
          {meta.ds ? (
            <div className="text-xs mono break-all text-[var(--muted)]">
              <span className="text-[var(--accent)]">DS </span>
              {meta.ds}
            </div>
          ) : null}
          <div className="flex flex-wrap gap-2">
            <button type="submit" className="btn btn-primary">
              Save zone meta
            </button>
            <button
              type="button"
              className="border border-[var(--border)] px-3 py-2 text-sm"
              onClick={async () => {
                try {
                  const d = await api.enableZoneDNSSEC(zone)
                  setMeta((m) => ({ ...(m || {}), dnssec_enabled: true, ds: d.ds, signing: true }))
                  setOk('DNSSEC keys ready — publish DS at parent')
                } catch (ex) {
                  setErr(ex.message)
                }
              }}
            >
              Enable signing / show DS
            </button>
          </div>
        </form>
      ) : (
        <div className="panel p-4 space-y-3">
          <h2 className="text-sm font-medium">DNSSEC signing</h2>
          <p className="text-xs text-[var(--muted)]">
            Zone meta/SOA editor appears when PostgreSQL is enabled. Signing keys work without DB.
          </p>
          {meta?.ds ? (
            <div className="text-xs mono break-all text-[var(--muted)]">
              <span className="text-[var(--accent)]">DS </span>
              {meta.ds}
            </div>
          ) : null}
          <button
            type="button"
            className="border border-[var(--border)] px-3 py-2 text-sm"
            onClick={async () => {
              try {
                const d = await api.enableZoneDNSSEC(zone)
                setMeta((m) => ({ ...(m || {}), dnssec_enabled: true, ds: d.ds, signing: true }))
                setOk('DNSSEC keys ready — publish DS at parent')
              } catch (ex) {
                setErr(ex.message)
              }
            }}
          >
            Enable signing / show DS
          </button>
        </div>
      )}

      <form onSubmit={save} className="grid grid-cols-2 md:grid-cols-3 gap-2 panel p-4">
        <div className="col-span-2 md:col-span-3 text-sm font-medium">
          {editing ? `Edit ${editing.name} ${editing.type}` : 'Add record'}
        </div>
        {['name', 'type', 'content', 'ttl', 'prio', 'view', 'geo_tag'].map((k) => (
          <label key={k} className="text-xs text-[var(--muted)] flex flex-col gap-1">
            {k}
            <input
              className="bg-[var(--bg)] border border-[var(--border)] cursor-text px-2 py-1.5 text-sm mono text-[var(--text)]"
              value={form[k]}
              onChange={(e) => setForm({ ...form, [k]: e.target.value })}
              required={k === 'name' || k === 'content' || k === 'type'}
            />
          </label>
        ))}
        <div className="col-span-2 md:col-span-3 flex gap-2">
          <button type="submit" className="btn btn-primary">
            {editing ? 'Save changes' : 'Add record'}
          </button>
          {editing ? (
            <button
              type="button"
              onClick={resetForm}
              className="border border-[var(--border)] px-3 py-2 text-sm text-[var(--muted)]"
            >
              Cancel
            </button>
          ) : null}
        </div>
      </form>

      <div className="overflow-x-auto">
        <table className="w-full text-sm min-w-[40rem]">
          <thead className="text-left text-[var(--muted)] border-b border-[var(--border)]">
            <tr>
              <th className="py-2 font-medium">Name</th>
              <th className="py-2 font-medium">Type</th>
              <th className="py-2 font-medium">Content</th>
              <th className="py-2 font-medium">TTL</th>
              <th className="py-2 font-medium">Prio</th>
              <th className="py-2 font-medium">View</th>
              <th className="py-2 font-medium">Geo</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {recs.map((r, i) => (
              <tr key={`${r.name}-${r.type}-${i}`} className="border-b border-[var(--border)]/60">
                <td className="py-2 mono">{r.name}</td>
                <td className="py-2 mono">{r.type}</td>
                <td className="py-2 mono">{r.content}</td>
                <td className="py-2 mono">{r.ttl}</td>
                <td className="py-2 mono">{r.prio || 0}</td>
                <td className="py-2 mono">{r.view || '—'}</td>
                <td className="py-2 mono">{r.geo_tag || '—'}</td>
                <td className="py-2 text-right space-x-2 whitespace-nowrap">
                  <button type="button" className="text-xs text-[var(--accent)]" onClick={() => startEdit(r)}>
                    Edit
                  </button>
                  <button type="button" className="text-xs text-[var(--danger)]" onClick={() => del(r)}>
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!recs.length ? <p className="text-sm text-[var(--muted)]">No records.</p> : null}
    </div>
  )
}

function Lookup() {
  const [name, setName] = useState('example.com')
  const [type, setType] = useState('A')
  const [result, setResult] = useState(null)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  const run = async (e) => {
    e.preventDefault()
    setBusy(true)
    setErr('')
    try {
      setResult(await api.lookup(name, type))
    } catch (ex) {
      setErr(ex.message)
      setResult(null)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-6 max-w-2xl">
      <PageHeader eyebrow="Operate" title="Lookup" sub="Resolve via this PowerSVX instance." />
      <form onSubmit={run} className="flex flex-wrap gap-2 reveal">
        <input
          className="input flex-1 min-w-[12rem] mono"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <select
          className="input"
          value={type}
          onChange={(e) => setType(e.target.value)}
        >
          {['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA'].map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
        <button
          type="submit"
          disabled={busy}
          className="btn btn-primary disabled:opacity-50"
        >
          {busy ? '…' : 'Query'}
        </button>
      </form>
      {err ? <ErrorBox msg={err} /> : null}
      {result ? (
        <div className="panel p-4 space-y-2">
          <div className="text-sm">
            RCODE <span className="mono text-[var(--accent)]">{result.rcode}</span>
            {result.ad ? <span className="ml-2 text-xs text-[var(--accent)]">AD</span> : null}
          </div>
          <pre className="mono text-xs whitespace-pre-wrap text-[var(--muted)]">
            {(result.answers || []).join('\n') || '(no answers)'}
          </pre>
        </div>
      ) : null}
    </div>
  )
}

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
    const axfrCount = (r?.policies || []).filter((p) => p.format === 'axfr').length
    setOk(
      `Sync OK · ${r?.entries ?? 0} RPZ entries total` +
        (axfrCount ? ` · ${axfrCount} AXFR feed(s) active` : ' · no AXFR feeds in policy list'),
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
    }
    if (editName != null) {
      if (policies.some((p) => p.name === n && p.name !== editName)) {
        setErr(`Feed "${n}" already exists`)
        return
      }
      setPolicies((list) => list.map((p) => (p.name === editName ? nextPolicy : p)))
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

  const saveSync = async () => {
    setBusy(true)
    setErr('')
    setOk('')
    try {
      const hostsSec = Math.max(0, Number(hostsIntervalSec) || 0)
      const axfrSec = Math.max(0, Number(axfrIntervalSec) || 0)
      const r = await api.updateRPZ([...hostsPolicies, ...policies], false, hostsSec, axfrSec, true)
      applyRPZ(r)
      if (r.loading) {
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
  const syncState = loading
    ? { label: 'Syncing…', tone: 'warn' }
    : status?.error
      ? { label: 'Failed', tone: 'danger' }
      : policies.length
        ? { label: 'Active', tone: 'ok' }
        : { label: 'Idle', tone: 'muted' }
  const toneClass =
    syncState.tone === 'ok'
      ? 'border-emerald-500/40 text-emerald-700 bg-emerald-500/10'
      : syncState.tone === 'danger'
        ? 'border-[var(--danger)]/40 text-[var(--danger)] bg-[var(--danger)]/10'
        : syncState.tone === 'warn'
          ? 'border-amber-500/40 text-amber-800 bg-amber-500/10'
          : 'border-[var(--border)] text-[var(--muted)] bg-[var(--bg)]'

  return (
    <section className="panel overflow-hidden reveal reveal-delay-3" aria-labelledby="axfr-filter-heading">
      <div className="px-4 py-3 border-b border-[var(--border)] flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-[10px] uppercase tracking-[0.12em] text-[var(--muted)] mb-1">Role: slave</p>
          <h3 id="axfr-filter-heading" className="text-sm font-medium">
            Filter feeds — pull blocklist (PowerSVX as slave)
          </h3>
          <p className="text-xs text-[var(--muted)] mt-1 leading-relaxed max-w-[56ch]">
            Komdigi-recommended path: AXFR zone <span className="mono text-[var(--text)]">trustpositifkominfo</span>{' '}
            from their masters into RPZ. First sync is full AXFR; later updates use IXFR. This does{' '}
            <em>not</em> make PowerSVX a DNS master for Komdigi.
          </p>
          <div className="mt-2 flex flex-wrap items-center gap-2 text-xs">
            <span className={`inline-flex items-center px-2 py-0.5 border mono ${toneClass}`}>{syncState.label}</span>
            {dirty ? (
              <span className="inline-flex items-center px-2 py-0.5 border border-amber-500/40 text-amber-800 bg-amber-500/10">
                Unsaved draft
              </span>
            ) : null}
            <span className="text-[var(--muted)]">
              {status ? `${status.entries ?? 0} RPZ entries total` : '…'}
              {status?.last_loaded ? ` · last ${status.last_loaded}` : ''}
              {status?.from_disk ? ' · from disk' : ''}
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
        {err || status?.error ? <ErrorBox msg={err || `Last sync error: ${status.error}`} /> : null}
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
        <p className="text-xs text-[var(--muted)]">
          First sync uses full AXFR; later refreshes use IXFR when the master serial changes (NOTIFY also
          triggers). Hosts feeds keep their own interval under Tools → RPZ.
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
                  <div className="mono text-xs text-[var(--muted)] break-all">zone {p.zone || p.source}</div>
                  <div className="mono text-xs text-[var(--muted)] break-all">
                    masters {(p.masters || []).join(', ') || '—'}
                  </div>
                  <div className="text-xs text-[var(--muted)] mt-0.5">
                    axfr · {p.action || 'nxdomain'}
                    {p.target ? ` → ${p.target}` : ''}
                  </div>
                </div>
                <div className="flex gap-1 shrink-0">
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
            ))
          ) : (
            <li className="text-sm text-[var(--muted)]">No slave filter feeds yet — add one below, then Save & sync.</li>
          )}
        </ul>

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
      const r = await api.updateRPZ([...policies, ...axfrPolicies], false, sec, axfrSec)
      setStatus(r)
      setPolicies(hostsOnlyPolicies(r.policies))
      setAxfrPolicies(axfrOnlyPolicies(r.policies))
      setIntervalSec(Number(r.update_interval) || 0)
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
      const r = await api.reloadRPZ()
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

      <label className="text-xs text-[var(--muted)] space-y-1 block max-w-xs">
        Hosts auto-refresh interval (seconds, 0 = off)
        <input
          type="number"
          min={0}
          step={60}
          className="w-full bg-[var(--bg)] border border-[var(--border)] px-2 py-1.5 text-sm mono text-[var(--text)]"
          value={intervalSec}
          onChange={(e) => setIntervalSec(e.target.value)}
        />
      </label>
      <p className="text-xs text-[var(--muted)]">
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

function rcodeLabel(code) {
  const map = {
    0: 'NOERROR',
    1: 'FORMERR',
    2: 'SERVFAIL',
    3: 'NXDOMAIN',
    5: 'REFUSED',
  }
  return map[code] || String(code)
}

function AuditLog() {
  const [events, setEvents] = useState([])
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  const load = () => {
    setBusy(true)
    setErr('')
    api
      .audit()
      .then((d) => setEvents(Array.isArray(d.events) ? d.events.slice().reverse() : []))
      .catch((e) => setErr(e.message))
      .finally(() => setBusy(false))
  }

  useEffect(() => {
    load()
  }, [])

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Observe"
        title="Audit"
        sub="Control-plane API mutations and auth failures (in-memory ring)."
        actions={
          <button type="button" disabled={busy} onClick={load} className="btn btn-secondary">
            {busy ? '…' : 'Refresh'}
          </button>
        }
      />
      {err ? <ErrorBox msg={err} /> : null}
      <div className="panel overflow-x-auto reveal">
        <table className="data-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Actor</th>
              <th>Role</th>
              <th>Action</th>
              <th>Path</th>
            </tr>
          </thead>
          <tbody>
            {events.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-3 py-6 text-[var(--muted)]">
                  No audit events yet.
                </td>
              </tr>
            ) : (
              events.map((e, i) => (
                <tr key={`${e.time}-${i}`} className="border-t border-[var(--border)]">
                  <td className="px-3 py-2 mono text-xs whitespace-nowrap">
                    {e.time ? new Date(e.time).toLocaleString() : '—'}
                  </td>
                  <td className="px-3 py-2 mono text-xs">{e.actor || '—'}</td>
                  <td className="px-3 py-2 text-xs">{e.role || '—'}</td>
                  <td className="px-3 py-2 mono text-xs">{e.action || '—'}</td>
                  <td className="px-3 py-2 mono text-xs break-all">{e.path || '—'}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function grafanaBaseURL() {
  try {
    const stored = localStorage.getItem('powersvx_grafana_url')
    if (stored) return stored.replace(/\/$/, '')
  } catch {
    /* ignore */
  }
  const { protocol, hostname } = window.location
  return `${protocol}//${hostname}:3000`
}

function buildGrafanaURL(base, { kiosk = true } = {}) {
  const root = (base || grafanaBaseURL()).replace(/\/$/, '')
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

function Analytics() {
  const [base, setBase] = useState(() => grafanaBaseURL())
  const [draft, setDraft] = useState(() => grafanaBaseURL())
  const src = buildGrafanaURL(base, { kiosk: true })
  const openURL = buildGrafanaURL(base, { kiosk: false })

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
  }

  return (
    <div className="space-y-5 max-w-[1400px]">
      <PageHeader
        eyebrow="Observe"
        title="Analytics"
        sub={
          <>
            Grafana trends (Prometheus). Live ops stay on{' '}
            <a href="/" className="text-[var(--accent)] hover:underline underline-offset-4">
              Dashboard
            </a>
            .
          </>
        }
        actions={
          <a href={openURL} target="_blank" rel="noreferrer" className="btn btn-primary">
            Open in Grafana
          </a>
        }
      />

      <form onSubmit={saveBase} className="panel px-4 py-3 flex flex-wrap gap-2 items-end reveal">
        <label className="field flex-1 min-w-[14rem]">
          <span className="label-quiet">Grafana URL</span>
          <input
            className="input mono"
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            placeholder="http://103.172.70.252:3000"
          />
        </label>
        <button type="submit" className="btn btn-secondary">
          Save
        </button>
        <span className="text-xs text-[var(--muted)] mono truncate max-w-full self-center">using {base}</span>
      </form>

      <section className="panel overflow-hidden reveal reveal-delay-1" style={{ minHeight: '70vh' }}>
        <iframe
          title="PowerSVX Grafana"
          src={src}
          className="w-full border-0 bg-[var(--bg)]"
          style={{ height: '70vh', minHeight: 520 }}
          referrerPolicy="no-referrer"
        />
      </section>

      <p className="text-xs text-[var(--muted)]">
        If the frame shows a login wall, sign in once in Grafana (Open in Grafana) or set anonymous viewer.
        Embedding needs <span className="mono">GF_SECURITY_ALLOW_EMBEDDING=true</span>.
      </p>
    </div>
  )
}

function DomainsPage() {
  const { canWrite } = useAuth()
  const [q, setQ] = useState('')
  const [result, setResult] = useState(null)
  const [domains, setDomains] = useState([])
  const [draft, setDraft] = useState('')
  const [err, setErr] = useState('')
  const [ok, setOk] = useState('')
  const [busy, setBusy] = useState(false)

  const loadWL = () =>
    api
      .whitelist()
      .then((r) => setDomains(r.domains || []))
      .catch((e) => setErr(e.message))

  useEffect(() => {
    loadWL()
  }, [])

  const search = async (e) => {
    e?.preventDefault?.()
    setErr('')
    setOk('')
    setResult(null)
    const name = q.trim()
    if (!name) {
      setErr('Enter a domain to search')
      return
    }
    setBusy(true)
    try {
      setResult(await api.domainLookup(name))
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  const add = async (e) => {
    e?.preventDefault?.()
    setErr('')
    setOk('')
    const name = draft.trim() || q.trim()
    if (!name) {
      setErr('Domain required')
      return
    }
    setBusy(true)
    try {
      const r = await api.addWhitelist(name)
      setDomains(r.domains || [])
      setDraft('')
      setOk(`Whitelisted ${r.domain}`)
      if (q.trim()) setResult(await api.domainLookup(q.trim()))
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  const remove = async (name) => {
    setErr('')
    setOk('')
    setBusy(true)
    try {
      const r = await api.removeWhitelist(name)
      setDomains(r.domains || [])
      setOk(`Removed ${name}`)
      if (q.trim()) setResult(await api.domainLookup(q.trim()))
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-6 max-w-4xl">
      <PageHeader
        eyebrow="Operate"
        title="Domains"
        sub="Search the RPZ blacklist and manage the whitelist (bypasses blocklists)."
      />

      {err ? <ErrorBox msg={err} /> : null}
      {ok ? <div className="flash-ok" role="status">{ok}</div> : null}

      <section className="panel p-4 space-y-3">
        <h2 className="text-sm font-medium">Blacklist lookup</h2>
        <form onSubmit={search} className="flex flex-wrap gap-2">
          <input
            className="input flex-1 min-w-[12rem] mono"
            placeholder="ads.example.com"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
          <button
            type="submit"
            disabled={busy}
            className="btn btn-primary"
          >
            Search
          </button>
          {canWrite ? (
            <button
              type="button"
              disabled={busy || !q.trim()}
              onClick={add}
              className="btn btn-secondary"
            >
              Add to whitelist
            </button>
          ) : null}
        </form>
        {result ? (
          <div className="border border-[var(--border)] px-3 py-3 text-sm space-y-1">
            <div className="mono font-medium">{result.name}</div>
            <div>
              Status:{' '}
              <span className={result.blocked ? 'text-[var(--warn)]' : 'text-[var(--ok)]'}>
                {result.whitelisted
                  ? 'whitelisted (allowed)'
                  : result.blocked
                    ? `blocked (${result.action || 'nxdomain'})`
                    : result.in_rpz
                      ? `in RPZ (${result.action})`
                      : 'not in blacklist'}
              </span>
            </div>
            {result.target ? <div className="text-xs text-[var(--muted)]">Target: {result.target}</div> : null}
          </div>
        ) : null}
      </section>

      <section className="panel p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-sm font-medium">Whitelist ({domains.length})</h2>
          <a href="/settings" className="text-xs text-[var(--accent)] underline">
            RPZ feeds
          </a>
        </div>
        {canWrite ? (
          <form onSubmit={add} className="flex flex-wrap gap-2">
            <input
              className="input flex-1 min-w-[12rem] mono"
              placeholder="example.com or *.cdn.example"
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
            />
            <button
              type="submit"
              disabled={busy}
              className="btn btn-primary"
            >
              Add
            </button>
          </form>
        ) : null}
        {domains.length ? (
          <ul className="space-y-1 text-sm mono max-h-96 overflow-auto">
            {domains.map((d) => (
              <li
                key={d}
                className="flex justify-between gap-3 border-b border-[var(--border)]/50 py-1.5 items-center"
              >
                <span className="truncate">{d}</span>
                {canWrite ? (
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => remove(d)}
                    className="text-xs text-[var(--warn)] cursor-pointer disabled:opacity-40"
                  >
                    Remove
                  </button>
                ) : null}
              </li>
            ))}
          </ul>
        ) : (
          <EmptyState title="Whitelist empty" hint="Add domains that should never be blocked by RPZ." />
        )}
      </section>
    </div>
  )
}

function QueryLogs() {
  const [clientIP, setClientIP] = useState(() => {
    try {
      return new URLSearchParams(window.location.search).get('client_ip') || ''
    } catch {
      return ''
    }
  })
  const [draftIP, setDraftIP] = useState(() => {
    try {
      return new URLSearchParams(window.location.search).get('client_ip') || ''
    } catch {
      return ''
    }
  })
  const [logs, setLogs] = useState([])
  const [total, setTotal] = useState(0)
  const [enabled, setEnabled] = useState(true)
  const [note, setNote] = useState('')
  const [offset, setOffset] = useState(0)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const limit = 50

  const load = (ip = clientIP, off = offset) => {
    setBusy(true)
    setErr('')
    api
      .queryLogs({ client_ip: ip, limit, offset: off })
      .then((d) => {
        setLogs(Array.isArray(d.logs) ? d.logs : [])
        setTotal(Number(d.total) || 0)
        setEnabled(d.enabled !== false)
        setNote(d.note || '')
      })
      .catch((e) => setErr(e.message))
      .finally(() => setBusy(false))
  }

  useEffect(() => {
    load('', 0)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const applyFilter = (e) => {
    e.preventDefault()
    const ip = draftIP.trim()
    setClientIP(ip)
    setOffset(0)
    load(ip, 0)
  }

  const clearFilter = () => {
    setDraftIP('')
    setClientIP('')
    setOffset(0)
    load('', 0)
  }

  const page = Math.floor(offset / limit) + 1
  const pages = Math.max(1, Math.ceil(total / limit))

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Observe"
        title="Query logs"
        sub="Per-query traffic from PostgreSQL. Filter by client IP to inspect a single user."
      />

      {!enabled ? (
        <div className="border border-[var(--warn)]/40 bg-[color-mix(in_srgb,var(--warn)_10%,transparent)] text-[var(--warn)] text-sm px-3 py-2 rounded-[var(--radius)]">
          Query logging is off — enable it in Settings to record new queries.
        </div>
      ) : null}
      {note ? <p className="text-xs text-[var(--muted)]">{note}</p> : null}
      {err ? <ErrorBox msg={err} /> : null}

      <form onSubmit={applyFilter} className="panel px-4 py-3 flex flex-wrap gap-2 items-end reveal">
        <label className="field flex-1 min-w-[12rem]">
          <span className="label-quiet">Client IP</span>
          <input
            value={draftIP}
            onChange={(e) => setDraftIP(e.target.value)}
            placeholder="e.g. 192.168.1.10"
            className="input mono"
          />
        </label>
        <button
          type="submit"
          disabled={busy}
          className="btn btn-primary"
        >
          {busy ? '…' : 'Filter'}
        </button>
        <button
          type="button"
          disabled={busy || (!clientIP && !draftIP)}
          onClick={clearFilter}
          className="btn btn-secondary"
        >
          Clear
        </button>
        <button
          type="button"
          disabled={busy}
          onClick={() => load(clientIP, offset)}
          className="btn btn-secondary"
        >
          Refresh
        </button>
      </form>

      <div className="panel overflow-x-auto reveal">
        <table className="data-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Client</th>
              <th>Name</th>
              <th>Type</th>
              <th>Rcode</th>
              <th>ms</th>
              <th>Proto</th>
              <th>Cache</th>
            </tr>
          </thead>
          <tbody className="mono text-xs">
            {logs.length === 0 ? (
              <tr>
                <td colSpan={8} className="text-[var(--muted)] font-sans">
                  {busy ? 'Loading…' : 'No query logs yet'}
                </td>
              </tr>
            ) : (
              logs.map((row) => (
                <tr key={row.id} className="border-t border-[var(--border)] hover:bg-[var(--bg-panel)]">
                  <td className="px-3 py-2 whitespace-nowrap">{formatEventTime(row.timestamp)}</td>
                  <td className="px-3 py-2 whitespace-nowrap">{row.client_ip}</td>
                  <td className="px-3 py-2 break-all max-w-[18rem]">{row.query_name}</td>
                  <td className="px-3 py-2">{row.query_type}</td>
                  <td className="px-3 py-2">{rcodeLabel(row.response_code)}</td>
                  <td className="px-3 py-2">{row.response_time_ms}</td>
                  <td className="px-3 py-2">{row.protocol}</td>
                  <td className="px-3 py-2">{row.cached ? 'yes' : ''}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between text-sm text-[var(--muted)]">
        <span>
          {total} total{clientIP ? ` · IP ${clientIP}` : ''} · page {page}/{pages}
        </span>
        <div className="flex gap-2">
          <button
            type="button"
            disabled={busy || offset <= 0}
            onClick={() => {
              const next = Math.max(0, offset - limit)
              setOffset(next)
              load(clientIP, next)
            }}
            className="btn btn-ghost text-xs"
          >
            Prev
          </button>
          <button
            type="button"
            disabled={busy || offset + limit >= total}
            onClick={() => {
              const next = offset + limit
              setOffset(next)
              load(clientIP, next)
            }}
            className="btn btn-ghost text-xs"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  )
}

function formatUptime(sec) {
  const s = Number(sec) || 0
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  return `${h}h ${m}m`
}

function SettingsPage() {
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

export default function App() {
  const [me, setMe] = useState(null)
  const [loading, setLoading] = useState(true)

  const refresh = async () => {
    try {
      const m = await api.me()
      setMe(m)
    } catch {
      setMe({ auth_required: true, name: '', role: '' })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    refresh()
  }, [])

  const role = (me?.role || '').toLowerCase()
  const value = {
    me,
    loading,
    refresh,
    canWrite: !me?.auth_required || role === 'admin' || role === 'operator',
    isAdmin: !me?.auth_required || role === 'admin',
  }

  return (
    <AuthCtx.Provider value={value}>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route
          path="/*"
          element={
            <RequireAuth>
              <Shell>
                <Routes>
                  <Route path="/" element={<Dashboard />} />
                  <Route path="/zones" element={<Zones />} />
                  <Route path="/domains" element={<DomainsPage />} />
                  <Route path="/zones/:name" element={<ZoneDetail />} />
                  <Route path="/lookup" element={<Lookup />} />
                  <Route path="/logs" element={<QueryLogs />} />
                  <Route path="/audit" element={<AuditLog />} />
                  <Route path="/settings" element={<SettingsPage />} />
                  <Route path="/analytics" element={<Analytics />} />
                </Routes>
              </Shell>
            </RequireAuth>
          }
        />
      </Routes>
    </AuthCtx.Provider>
  )
}
