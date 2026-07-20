import { useEffect, useRef, useState } from 'react'
import { NavLink, Route, Routes, useNavigate, useParams } from 'react-router-dom'
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { api, getToken, setToken } from './api'

function LoadingBlock({ label = 'Loading' }) {
  return (
    <div className="space-y-3" role="status" aria-live="polite" aria-busy="true">
      <span className="sr-only">{label}</span>
      <div className="h-8 w-48 bg-[var(--bg-panel)] animate-pulse border border-[var(--border)]" />
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[0, 1, 2, 3].map((i) => (
          <div key={i} className="h-20 panel animate-pulse bg-[var(--bg-panel)]" />
        ))}
      </div>
      <div className="h-40 panel animate-pulse bg-[var(--bg-panel)]" />
    </div>
  )
}

function EmptyState({ title, hint, action }) {
  return (
    <div className="panel px-4 py-8 text-center" role="status">
      <p className="text-sm font-medium">{title}</p>
      {hint ? <p className="text-xs text-[var(--muted)] mt-2 max-w-md mx-auto">{hint}</p> : null}
      {action || null}
    </div>
  )
}

function Shell({ children }) {
  const [token, setTok] = useState(getToken())
  const links = [
    ['/', 'Dashboard'],
    ['/zones', 'Zones'],
    ['/lookup', 'Lookup'],
    ['/settings', 'Settings'],
  ]
  return (
    <div className="min-h-full flex flex-col md:flex-row">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:z-50 focus:top-2 focus:left-2 focus:bg-[var(--accent)] focus:text-[#0e1014] focus:px-3 focus:py-2"
      >
        Skip to content
      </a>
      <aside
        className="md:w-56 shrink-0 border-b md:border-b-0 md:border-r border-[var(--border)] bg-[var(--bg-elevated)] px-4 py-5 flex md:flex-col gap-4 md:gap-6 sticky top-0 z-20 md:static"
        aria-label="Sidebar"
      >
        <div className="reveal">
          <div className="text-[clamp(1.35rem,2vw,1.65rem)] font-bold tracking-tight leading-none" aria-label="PowerSVX">
            <span className="text-[var(--text)]">Power</span>
            <span className="text-[var(--accent)]">SVX</span>
          </div>
          <div className="text-[11px] uppercase tracking-[0.14em] text-[var(--muted)] mt-2 mono">
            DNS control plane
          </div>
        </div>
        <nav className="flex md:flex-col gap-1 flex-1 overflow-x-auto" aria-label="Primary">
          {links.map(([to, label], i) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                `relative px-3 py-2 text-sm transition cursor-pointer whitespace-nowrap reveal reveal-delay-${Math.min(i + 1, 4)} ${
                  isActive
                    ? 'text-[var(--accent)] bg-[var(--accent-soft)] border-l-2 border-[var(--accent)] md:pl-[10px]'
                    : 'text-[var(--muted)] hover:text-[var(--text)] hover:bg-[var(--bg-panel)] border-l-2 border-transparent'
                }`
              }
            >
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="space-y-1.5 md:mt-auto w-full max-w-xs">
          <label className="text-[11px] uppercase tracking-wide text-[var(--muted)]" htmlFor="api-token">
            API token
          </label>
          <input
            id="api-token"
            className="w-full bg-[var(--bg)] border border-[var(--border)] px-2 py-1.5 text-xs mono text-[var(--text)] focus:border-[var(--accent)]"
            style={{ borderRadius: 'var(--radius)' }}
            type="password"
            placeholder="optional"
            value={token}
            onChange={(e) => {
              setTok(e.target.value)
              setToken(e.target.value)
            }}
          />
        </div>
      </aside>
      <main id="main" tabIndex={-1} className="flex-1 p-5 md:p-8 overflow-auto outline-none">{children}</main>
    </div>
  )
}

function Stat({ label, value, sub }) {
  return (
    <div
      className="panel px-3 py-3 border-l-2 border-l-[var(--accent)] hover:border-[var(--border-strong)] transition-colors"
    >
      <div className="text-[10px] uppercase tracking-[0.12em] text-[var(--muted)]">{label}</div>
      <div className="text-[clamp(1.35rem,2.2vw,1.75rem)] font-semibold mt-1 mono leading-none tabular-nums">
        {value}
      </div>
      {sub ? <div className="text-[11px] text-[var(--muted)] mt-2">{sub}</div> : null}
    </div>
  )
}

function Badge({ on, label }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 text-[11px] uppercase tracking-wide px-2 py-1 border mono ${
        on
          ? 'border-[var(--accent)]/50 text-[var(--accent)] bg-[var(--accent-soft)]'
          : 'border-[var(--border)] text-[var(--muted)]'
      }`}
      style={{ borderRadius: 'var(--radius)' }}
    >
      <span className={`h-1.5 w-1.5 ${on ? 'bg-[var(--accent)]' : 'bg-[var(--muted)]'}`} />
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
  const hitRatio =
    s.cache_hits + s.cache_misses > 0
      ? ((100 * s.cache_hits) / (s.cache_hits + s.cache_misses)).toFixed(1)
      : '—'
  const trafficChart = [
    { name: 'Hits', value: s.cache_hits },
    { name: 'Misses', value: s.cache_misses },
    { name: 'Queries', value: s.queries_total },
    { name: 'Limited', value: s.rate_limited },
  ]
  const rcodeChart = rcodes.map((r) => ({ name: r.rcode, value: r.count }))

  return (
    <div className="space-y-6 max-w-6xl">
      <header className="reveal">
        <h1 className="text-2xl font-semibold">Dashboard</h1>
        <p className="text-[var(--muted)] text-sm mt-1">
          v{s.version} · uptime {formatUptime(s.uptime_seconds)} · mode {s.mode}
        </p>
        <div className="flex flex-wrap gap-2 mt-3">
          <Badge on={s.dot_enabled} label="DoT" />
          <Badge on={s.doh_enabled} label="DoH" />
          <Badge on={!!s.doh3_enabled} label="DoH3" />
          <Badge on={s.doq_enabled} label="DoQ" />
          <Badge on={s.rpz_enabled} label="RPZ" />
          <Badge on={s.ecs_enabled} label="ECS" />
          <Badge on={s.geodns_enabled} label="GeoDNS" />
          <Badge on={s.split_horizon_enabled} label="Split Horizon" />
        </div>
      </header>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 reveal reveal-delay-1">
        <Stat label="Queries" value={s.queries_total} />
        <Stat label="Cache hit %" value={hitRatio} sub={`L1 size ${s.cache_l1_size}`} />
        <Stat label="Zones" value={s.zones} />
        <Stat label="RPZ / limited" value={s.rpz_entries} sub={`rate-limited ${s.rate_limited}`} />
      </div>

      <div className="grid md:grid-cols-2 gap-4 reveal reveal-delay-2">
        <section className="panel p-4 h-64">
          <h2 className="text-sm text-[var(--muted)] mb-3">Traffic snapshot</h2>
          <ResponsiveContainer width="100%" height="85%">
            <BarChart data={trafficChart}>
              <CartesianGrid strokeDasharray="3 3" stroke="#2c3340" />
              <XAxis dataKey="name" stroke="#8b939e" fontSize={12} />
              <YAxis stroke="#8b939e" fontSize={12} />
              <Tooltip
                contentStyle={{ background: '#1a1f28', border: '1px solid #2c3340', borderRadius: 2 }}
              />
              <Bar dataKey="value" fill="var(--accent)" radius={[2, 2, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </section>
        <section className="panel p-4 h-64">
          <h2 className="text-sm text-[var(--muted)] mb-3">RCODE distribution</h2>
          {rcodeChart.length ? (
            <ResponsiveContainer width="100%" height="85%">
              <BarChart data={rcodeChart}>
                <CartesianGrid strokeDasharray="3 3" stroke="#2c3340" />
                <XAxis dataKey="name" stroke="#8b939e" fontSize={11} />
                <YAxis stroke="#8b939e" fontSize={12} />
                <Tooltip
                  contentStyle={{ background: '#1a1f28', border: '1px solid #2c3340', borderRadius: 2 }}
                />
                <Bar dataKey="value" fill="#94a3b8" radius={[2, 2, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <p className="text-sm text-[var(--muted)] pt-8 text-center">No query aggregates yet</p>
          )}
        </section>
      </div>

      <div className="grid md:grid-cols-2 gap-4 reveal reveal-delay-3">
        <section className="panel p-4">
          <h2 className="text-sm text-[var(--muted)] mb-3">Top queried names</h2>
          {names.length ? (
            <ul className="space-y-1 text-sm mono max-h-56 overflow-auto">
              {names.map((n) => (
                <li key={n.name} className="flex justify-between gap-3 border-b border-[var(--border)]/50 py-1.5">
                  <span className="truncate">{n.name}</span>
                  <span className="text-[var(--accent)] shrink-0">{n.count}</span>
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState title="No queries yet" hint="Totals appear after DNS traffic hits this instance." />
          )}
        </section>
        <section>
          <h2 className="text-sm text-[var(--muted)] mb-2">Zones</h2>
          {data.zones?.length ? (
            <ul className="space-y-1">
              {data.zones.map((z) => (
                <li
                  key={z.name}
                  className="flex justify-between border border-[var(--border)] px-3 py-2 text-sm panel"
                >
                  <span className="mono">{z.name}</span>
                  <span className="text-[var(--muted)]">{z.record_count} records</span>
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState
              title="No zones yet"
              hint="Add an authoritative zone to serve local records."
              action={
                <a href="/zones" className="inline-block mt-4 text-sm text-[var(--accent)] underline cursor-pointer">
                  Go to Zones
                </a>
              }
            />
          )}
        </section>
      </div>

      <div className="reveal reveal-delay-4">
        <LiveErrorLog />
      </div>
    </div>
  )
}

function LiveErrorLog() {
  const [events, setEvents] = useState([])
  const [live, setLive] = useState(false)
  const [paused, setPaused] = useState(false)
  const pausedRef = useRef(false)
  pausedRef.current = paused

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
    <section className="panel p-4">
      <div className="flex items-center justify-between gap-3 mb-3">
        <div>
          <h2 className="text-sm font-medium">Live errors</h2>
          <p className="text-xs text-[var(--muted)] mt-0.5">
            Warnings & errors only — not per-query traffic
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span
            className={`text-xs px-2 py-1 border ${
              live
                ? 'border-[var(--accent-dim)] text-[var(--accent)]'
                : 'border-[var(--border)] text-[var(--muted)]'
            }`}
          >
            {live ? 'live' : 'reconnecting'}
          </span>
          <button
            type="button"
            className="text-xs px-2 py-1 border border-[var(--border)] text-[var(--muted)] hover:text-[var(--text)]"
            onClick={() => setPaused((p) => !p)}
          >
            {paused ? 'Resume' : 'Pause'}
          </button>
          <button
            type="button"
            className="text-xs px-2 py-1 border border-[var(--border)] text-[var(--muted)] hover:text-[var(--text)]"
            onClick={() => setEvents([])}
          >
            Clear
          </button>
        </div>
      </div>
      <div className="max-h-64 overflow-auto space-y-1.5 mono text-xs">
        {events.length === 0 ? (
          <p className="text-[var(--muted)] font-sans">No errors yet. Healthy.</p>
        ) : (
          events.map((e) => (
            <div
              key={e.id}
              className={`border px-2.5 py-1.5 ${
                e.level === 'error'
                  ? 'border-[var(--danger)]/40 bg-[var(--danger)]/10'
                  : 'border-[var(--warn)]/30 bg-[var(--warn)]/5'
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
  const [zones, setZones] = useState([])
  const [name, setName] = useState('')
  const [err, setErr] = useState('')
  const nav = useNavigate()

  const load = () =>
    api
      .zones()
      .then((d) => setZones(d.zones || []))
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

  return (
    <div className="space-y-6 max-w-3xl">
      <header>
        <h1 className="text-2xl font-semibold">Zones</h1>
        <p className="text-sm text-[var(--muted)] mt-1">Authoritative zones and records</p>
      </header>
      {err ? <ErrorBox msg={err} /> : null}
      <form onSubmit={create} className="flex gap-2">
        <input
          className="flex-1 bg-[var(--bg)] border border-[var(--border)] cursor-text px-3 py-2 text-sm mono"
          placeholder="example.com"
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
        />
        <button
          type="submit"
          className="bg-[var(--accent)] text-[#0e1014] cursor-pointer font-medium px-4 py-2 text-sm hover:opacity-90"
        >
          Add zone
        </button>
      </form>
      <ul className="space-y-2">
        {zones.map((z) => (
          <li
            key={z.name}
            className="flex items-center justify-between panel px-4 py-3"
          >
            <button className="text-left" onClick={() => nav(`/zones/${encodeURIComponent(z.name)}`)}>
              <div className="mono font-medium">{z.name}</div>
              <div className="text-xs text-[var(--muted)]">{z.record_count} records</div>
            </button>
            <button
              type="button"
              className="text-xs text-[var(--danger)] hover:underline"
              onClick={() => remove(z.name)}
            >
              Delete
            </button>
          </li>
        ))}
      </ul>
    </div>
  )
}

function ZoneDetail() {
  const { name } = useParams()
  const zone = decodeURIComponent(name)
  const [recs, setRecs] = useState([])
  const [err, setErr] = useState('')
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
    api
      .getZone(zone)
      .then((d) => setRecs(d.records || []))
      .catch((e) => setErr(e.message))

  useEffect(() => {
    load()
  }, [zone])

  const add = async (e) => {
    e.preventDefault()
    setErr('')
    try {
      await api.addRecord(zone, {
        ...form,
        ttl: Number(form.ttl) || 3600,
        prio: Number(form.prio) || 0,
      })
      setForm({ name: '', type: 'A', content: '', ttl: 3600, prio: 0, view: '', geo_tag: '' })
      await load()
    } catch (ex) {
      setErr(ex.message)
    }
  }

  const del = async (r) => {
    try {
      await api.deleteRecord(zone, r.name, r.type)
      await load()
    } catch (ex) {
      setErr(ex.message)
    }
  }

  return (
    <div className="space-y-6 max-w-4xl">
      <button type="button" className="text-sm text-[var(--muted)] hover:text-[var(--accent)]" onClick={() => nav('/zones')}>
        ← Zones
      </button>
      <header>
        <h1 className="text-2xl font-semibold mono">{zone}</h1>
      </header>
      {err ? <ErrorBox msg={err} /> : null}

      <form onSubmit={add} className="grid grid-cols-2 md:grid-cols-3 gap-2 panel p-4">
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
        <div className="col-span-2 md:col-span-3">
          <button type="submit" className="bg-[var(--accent)] text-[#0e1014] cursor-pointer font-medium px-4 py-2 text-sm">
            Add record
          </button>
        </div>
      </form>

      <table className="w-full text-sm">
        <thead className="text-left text-[var(--muted)] border-b border-[var(--border)]">
          <tr>
            <th className="py-2 font-medium">Name</th>
            <th className="py-2 font-medium">Type</th>
            <th className="py-2 font-medium">Content</th>
            <th className="py-2 font-medium">TTL</th>
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
              <td className="py-2 text-right">
                <button type="button" className="text-xs text-[var(--danger)]" onClick={() => del(r)}>
                  Delete
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
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
      <header>
        <h1 className="text-2xl font-semibold">Lookup</h1>
        <p className="text-sm text-[var(--muted)] mt-1">Resolve via this PowerSVX instance</p>
      </header>
      <form onSubmit={run} className="flex flex-wrap gap-2">
        <input
          className="flex-1 min-w-[12rem] bg-[var(--bg)] border border-[var(--border)] cursor-text px-3 py-2 text-sm mono"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <select
          className="bg-[var(--bg)] border border-[var(--border)] cursor-text px-3 py-2 text-sm"
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
          className="bg-[var(--accent)] text-[#0e1014] cursor-pointer font-medium px-4 py-2 text-sm disabled:opacity-50"
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

function Settings() {
  const [saved, setSaved] = useState(null)
  const [draft, setDraft] = useState(null)
  const [rpz, setRpz] = useState(null)
  const [err, setErr] = useState('')
  const [ok, setOk] = useState('')
  const [busy, setBusy] = useState(false)

  const toggleKeys = ['geodns', 'rpz_enabled', 'rate_limit', 'ecs_enabled', 'split_horizon']

  const load = () =>
    Promise.all([api.settings(), api.rpz()])
      .then(([s, r]) => {
        setSaved(s)
        setDraft({
          geodns: !!s.geodns,
          rpz_enabled: !!s.rpz_enabled,
          rate_limit: !!s.rate_limit,
          ecs_enabled: !!s.ecs_enabled,
          split_horizon: !!s.split_horizon,
        })
        setRpz(r)
      })
      .catch((e) => setErr(e.message))

  useEffect(() => {
    load()
  }, [])

  const dirty =
    saved &&
    draft &&
    toggleKeys.some((k) => !!draft[k] !== !!saved[k])

  const toggle = (key) => {
    setOk('')
    setErr('')
    setDraft((d) => ({ ...d, [key]: !d[key] }))
  }

  const discard = () => {
    if (!saved) return
    setDraft({
      geodns: !!saved.geodns,
      rpz_enabled: !!saved.rpz_enabled,
      rate_limit: !!saved.rate_limit,
      ecs_enabled: !!saved.ecs_enabled,
      split_horizon: !!saved.split_horizon,
    })
    setOk('')
    setErr('')
  }

  const save = async () => {
    if (!draft || !dirty) return
    setBusy(true)
    setErr('')
    setOk('')
    try {
      const s = await api.updateSettings(draft)
      setSaved(s)
      setDraft({
        geodns: !!s.geodns,
        rpz_enabled: !!s.rpz_enabled,
        rate_limit: !!s.rate_limit,
        ecs_enabled: !!s.ecs_enabled,
        split_horizon: !!s.split_horizon,
      })
      setOk('Settings saved and applied (no restart)')
      setRpz(await api.rpz())
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  if (err && !saved) return <ErrorBox msg={err} />
  if (!saved || !draft) return <p className="text-[var(--muted)]">Loading…</p>

  const toggles = [
    ['geodns', 'GeoDNS', 'Route answers by client country/continent (needs MMDB or IP overrides)'],
    ['rpz_enabled', 'RPZ / blocklist', 'Block domains from policy files'],
    ['rate_limit', 'Rate limit', 'Token-bucket per client IP'],
    ['ecs_enabled', 'ECS', 'EDNS Client Subnet on upstream queries'],
    ['split_horizon', 'Split horizon', 'Different answers by client network / view'],
  ]

  return (
    <div className="space-y-6 max-w-3xl">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">Settings</h1>
          <p className="text-sm text-[var(--muted)] mt-1">
            Change toggles, then press <strong>Save</strong> to apply. No restart needed.
          </p>
        </div>
        <div className="flex gap-2">
          <button
            type="button"
            disabled={!dirty || busy}
            onClick={discard}
            className="border border-[var(--border)] cursor-pointer px-3 py-2 text-sm text-[var(--muted)] disabled:opacity-40 hover:text-[var(--text)]"
          >
            Discard
          </button>
          <button
            type="button"
            disabled={!dirty || busy}
            onClick={save}
            className="bg-[var(--accent)] text-[#0e1014] cursor-pointer font-medium px-4 py-2 text-sm disabled:opacity-40"
          >
            {busy ? 'Saving…' : 'Save changes'}
          </button>
        </div>
      </header>
      {err ? <ErrorBox msg={err} /> : null}
      {ok ? (
        <div className="border border-[var(--accent)]/40 bg-[var(--accent-soft)] text-[var(--accent)] text-sm px-3 py-2">
          {ok}
        </div>
      ) : null}
      {dirty ? (
        <div className="border border-[var(--warn)]/40 bg-[var(--warn)]/10 text-[var(--warn)] text-sm px-3 py-2">
          Unsaved changes — not applied until you save
        </div>
      ) : null}

      <section className="panel divide-y divide-[var(--border)]">
        {toggles.map(([key, label, hint]) => (
          <div key={key} className="flex items-center justify-between gap-4 px-4 py-3">
            <div>
              <div className="text-sm font-medium flex items-center gap-2">
                {label}
                {!!draft[key] !== !!saved[key] ? (
                  <span className="text-[10px] uppercase tracking-wide text-[var(--warn)]">edited</span>
                ) : null}
              </div>
              <div className="text-xs text-[var(--muted)] mt-0.5">{hint}</div>
              {key === 'geodns' && saved.geodns_db ? (
                <div className="text-xs mono text-[var(--muted)] mt-1">{saved.geodns_db}</div>
              ) : null}
            </div>
            <button
              type="button"
              disabled={busy}
              onClick={() => toggle(key)}
              className={`shrink-0 relative h-7 w-12 transition cursor-pointer ${
                draft[key] ? 'bg-[var(--accent)]' : 'bg-[var(--border)]'
              } disabled:opacity-50`}
              style={{ borderRadius: 'var(--radius)' }}
              aria-pressed={!!draft[key]}
            >
              <span
                className={`absolute top-0.5 h-6 w-6 bg-[var(--bg)] transition ${
                  draft[key] ? 'left-5' : 'left-0.5'
                }`}
                style={{ borderRadius: 1 }}
              />
            </button>
          </div>
        ))}
      </section>

      <dl className="panel divide-y divide-[var(--border)] text-sm">
        {[
          ['resolver_mode', saved.resolver_mode],
          ['dnssec_mode', saved.dnssec_mode],
          ['udp_addr', saved.udp_addr],
          ['forwarders', (saved.forwarders || []).join(', ')],
        ].map(([k, v]) => (
          <div key={k} className="flex justify-between gap-4 px-4 py-2.5">
            <dt className="text-[var(--muted)]">{k}</dt>
            <dd className="mono text-right break-all">{String(v)}</dd>
          </div>
        ))}
      </dl>

      <ACMEPanel />
      <RPZPanel initial={rpz} onChange={setRpz} />
    </div>
  )
}

function RPZPanel({ initial, onChange }) {
  const [policies, setPolicies] = useState(() => clonePolicies(initial?.policies))
  const [intervalSec, setIntervalSec] = useState(() => Number(initial?.update_interval) || 0)
  const [status, setStatus] = useState(initial)
  const [name, setName] = useState('trustpositif')
  const [source, setSource] = useState('https://trustpositif.komdigi.go.id/assets/db/domains_isp')
  const [action, setAction] = useState('nxdomain')
  const [err, setErr] = useState('')
  const [ok, setOk] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    setPolicies(clonePolicies(initial?.policies))
    setIntervalSec(Number(initial?.update_interval) || 0)
    setStatus(initial)
  }, [initial])

  useEffect(() => {
    if (!status?.loading) return undefined
    const t = setInterval(() => {
      api
        .rpz()
        .then((r) => {
          setStatus(r)
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

  const add = () => {
    setErr('')
    setOk('')
    const n = name.trim()
    const s = source.trim()
    if (!n || !s) {
      setErr('Name and source (URL or file path) are required')
      return
    }
    if (policies.some((p) => p.name === n)) {
      setErr(`Policy "${n}" already exists`)
      return
    }
    setPolicies((p) => [...p, { name: n, source: s, format: 'hosts', action }])
  }

  const remove = (n) => {
    setErr('')
    setOk('')
    setPolicies((p) => p.filter((x) => x.name !== n))
  }

  const saveSync = async () => {
    setBusy(true)
    setErr('')
    setOk('')
    try {
      const sec = Math.max(0, Number(intervalSec) || 0)
      const r = await api.updateRPZ(policies, false, sec)
      setStatus(r)
      setPolicies(clonePolicies(r.policies))
      setIntervalSec(Number(r.update_interval) || 0)
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
            HTTP URL or local file · hosts format · radix lookup + Badger snapshot on disk
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
            className="border border-[var(--border)] cursor-pointer px-3 py-2 text-sm text-[var(--muted)] disabled:opacity-40 hover:text-[var(--text)]"
          >
            Re-sync
          </button>
          <button
            type="button"
            disabled={busy || loading}
            onClick={saveSync}
            className="bg-[var(--accent)] text-[#0e1014] cursor-pointer font-medium px-3 py-2 text-sm disabled:opacity-40"
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
        Auto-refresh interval (seconds, 0 = off)
        <input
          type="number"
          min={0}
          step={60}
          className="w-full bg-[var(--bg)] border border-[var(--border)] px-2 py-1.5 text-sm mono text-[var(--text)]"
          value={intervalSec}
          onChange={(e) => setIntervalSec(e.target.value)}
        />
      </label>

      <ul className="space-y-2 text-sm">
        {policies.length ? (
          policies.map((p) => (
            <li
              key={p.name}
              className="flex flex-wrap items-start justify-between gap-2 border-b border-[var(--border)]/60 pb-2"
            >
              <div className="min-w-0">
                <div className="font-medium">{p.name}</div>
                <div className="mono text-xs text-[var(--muted)] break-all">{p.source}</div>
                <div className="text-xs text-[var(--muted)] mt-0.5">
                  {p.format || 'hosts'} · {p.action || 'nxdomain'}
                </div>
              </div>
              <button
                type="button"
                disabled={busy || loading}
                onClick={() => remove(p.name)}
                className="text-[var(--danger)] text-xs cursor-pointer disabled:opacity-40"
              >
                Remove
              </button>
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
          </select>
        </label>
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
      <button
        type="button"
        disabled={busy || loading}
        onClick={add}
        className="border border-[var(--border)] cursor-pointer px-3 py-2 text-sm disabled:opacity-40 hover:border-[var(--accent)]"
      >
        Add feed to list
      </button>
    </section>
  )
}

function clonePolicies(list) {
  return (list || []).map((p) => ({
    name: p.name || '',
    source: p.source || '',
    format: p.format || 'hosts',
    action: p.action || 'nxdomain',
  }))
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
        className="bg-[var(--accent)] text-[#0e1014] cursor-pointer font-medium px-4 py-2 text-sm disabled:opacity-40"
      >
        {busy ? 'Obtaining…' : 'Obtain certificate'}
      </button>
    </section>
  )
}

function ErrorBox({ msg }) {
  return (
    <div className="border border-[var(--danger)]/40 bg-[var(--danger)]/10 text-[var(--danger)] text-sm px-3 py-2">
      {msg}
    </div>
  )
}

function formatUptime(sec) {
  const s = Number(sec) || 0
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  return `${h}h ${m}m`
}

export default function App() {
  return (
    <Shell>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/zones" element={<Zones />} />
        <Route path="/zones/:name" element={<ZoneDetail />} />
        <Route path="/lookup" element={<Lookup />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="/analytics" element={<Dashboard />} />
      </Routes>
    </Shell>
  )
}
