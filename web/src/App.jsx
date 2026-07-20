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

function Shell({ children }) {
  const [token, setTok] = useState(getToken())
  const links = [
    ['/', 'Dashboard'],
    ['/zones', 'Zones'],
    ['/lookup', 'Lookup'],
    ['/settings', 'Settings'],
  ]
  return (
    <div className="min-h-full flex">
      <aside className="w-56 shrink-0 border-r border-[var(--border)] bg-[var(--bg-elevated)]/80 backdrop-blur px-4 py-6 flex flex-col gap-6">
        <div>
          <div className="text-xl font-bold tracking-tight text-[var(--accent)]">PowerSVX</div>
          <div className="text-xs text-[var(--muted)] mt-1">DNS control plane</div>
        </div>
        <nav className="flex flex-col gap-1">
          {links.map(([to, label]) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                `px-3 py-2 rounded-md text-sm transition ${
                  isActive
                    ? 'bg-[var(--bg-panel)] text-[var(--accent)]'
                    : 'text-[var(--muted)] hover:text-[var(--text)] hover:bg-[var(--bg-panel)]/60'
                }`
              }
            >
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="mt-auto space-y-2">
          <label className="text-xs text-[var(--muted)]">API token</label>
          <input
            className="w-full rounded-md bg-[var(--bg)] border border-[var(--border)] px-2 py-1.5 text-xs mono"
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
      <main className="flex-1 p-6 md:p-8 overflow-auto">{children}</main>
    </div>
  )
}

function Stat({ label, value, sub }) {
  return (
    <div className="rounded-lg border border-[var(--border)] bg-[var(--bg-panel)]/70 px-4 py-3">
      <div className="text-xs uppercase tracking-wide text-[var(--muted)]">{label}</div>
      <div className="text-2xl font-semibold mt-1 mono">{value}</div>
      {sub ? <div className="text-xs text-[var(--muted)] mt-1">{sub}</div> : null}
    </div>
  )
}

function Badge({ on, label }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 text-xs px-2 py-1 rounded border ${
        on
          ? 'border-[var(--accent-dim)] text-[var(--accent)] bg-[var(--accent)]/10'
          : 'border-[var(--border)] text-[var(--muted)]'
      }`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${on ? 'bg-[var(--accent)]' : 'bg-[var(--muted)]'}`} />
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
    const t = setInterval(load, 5000)
    return () => {
      alive = false
      clearInterval(t)
    }
  }, [])

  if (err) return <ErrorBox msg={err} />
  if (!data) return <p className="text-[var(--muted)]">Loading…</p>

  const s = data.status
  const hitRatio =
    s.cache_hits + s.cache_misses > 0
      ? ((100 * s.cache_hits) / (s.cache_hits + s.cache_misses)).toFixed(1)
      : '—'
  const chart = [
    { name: 'Hits', value: s.cache_hits },
    { name: 'Misses', value: s.cache_misses },
    { name: 'Queries', value: s.queries_total },
    { name: 'Limited', value: s.rate_limited },
  ]

  return (
    <div className="space-y-6 max-w-5xl">
      <header>
        <h1 className="text-2xl font-semibold">Dashboard</h1>
        <p className="text-[var(--muted)] text-sm mt-1">
          v{s.version} · uptime {formatUptime(s.uptime_seconds)} · mode {s.mode}
        </p>
        <div className="flex flex-wrap gap-2 mt-3">
          <Badge on={s.dot_enabled} label="DoT" />
          <Badge on={s.doh_enabled} label="DoH" />
          <Badge on={s.doq_enabled} label="DoQ" />
          <Badge on={s.rpz_enabled} label="RPZ" />
          <Badge on={s.ecs_enabled} label="ECS" />
          <Badge on={s.geodns_enabled} label="GeoDNS" />
          <Badge on={s.split_horizon_enabled} label="Split Horizon" />
        </div>
      </header>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Stat label="Queries" value={s.queries_total} />
        <Stat label="Cache hit %" value={hitRatio} sub={`L1 size ${s.cache_l1_size}`} />
        <Stat label="Zones" value={s.zones} />
        <Stat label="RPZ entries" value={s.rpz_entries} sub={`blocked ${s.rate_limited}`} />
      </div>

      <LiveErrorLog />

      <section className="rounded-lg border border-[var(--border)] bg-[var(--bg-panel)]/50 p-4 h-64">
        <h2 className="text-sm text-[var(--muted)] mb-3">Traffic snapshot</h2>
        <ResponsiveContainer width="100%" height="85%">
          <BarChart data={chart}>
            <CartesianGrid strokeDasharray="3 3" stroke="#2a3a4f" />
            <XAxis dataKey="name" stroke="#8fa3b8" fontSize={12} />
            <YAxis stroke="#8fa3b8" fontSize={12} />
            <Tooltip
              contentStyle={{ background: '#1a2433', border: '1px solid #2a3a4f', borderRadius: 8 }}
            />
            <Bar dataKey="value" fill="#2dd4a8" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </section>

      <section>
        <h2 className="text-sm text-[var(--muted)] mb-2">Zones</h2>
        {data.zones?.length ? (
          <ul className="space-y-1">
            {data.zones.map((z) => (
              <li
                key={z.name}
                className="flex justify-between border border-[var(--border)] rounded-md px-3 py-2 text-sm"
              >
                <span className="mono">{z.name}</span>
                <span className="text-[var(--muted)]">{z.record_count} records</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-[var(--muted)]">No zones yet. Create one under Zones.</p>
        )}
      </section>
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
    <section className="rounded-lg border border-[var(--border)] bg-[var(--bg-panel)]/50 p-4">
      <div className="flex items-center justify-between gap-3 mb-3">
        <div>
          <h2 className="text-sm font-medium">Live errors</h2>
          <p className="text-xs text-[var(--muted)] mt-0.5">
            Warnings & errors only — not per-query traffic
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span
            className={`text-xs px-2 py-1 rounded border ${
              live
                ? 'border-[var(--accent-dim)] text-[var(--accent)]'
                : 'border-[var(--border)] text-[var(--muted)]'
            }`}
          >
            {live ? 'live' : 'reconnecting'}
          </span>
          <button
            type="button"
            className="text-xs px-2 py-1 rounded border border-[var(--border)] text-[var(--muted)] hover:text-[var(--text)]"
            onClick={() => setPaused((p) => !p)}
          >
            {paused ? 'Resume' : 'Pause'}
          </button>
          <button
            type="button"
            className="text-xs px-2 py-1 rounded border border-[var(--border)] text-[var(--muted)] hover:text-[var(--text)]"
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
              className={`rounded border px-2.5 py-1.5 ${
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
          className="flex-1 rounded-md bg-[var(--bg)] border border-[var(--border)] px-3 py-2 text-sm mono"
          placeholder="example.com"
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
        />
        <button
          type="submit"
          className="rounded-md bg-[var(--accent)] text-[#0c1219] font-medium px-4 py-2 text-sm hover:opacity-90"
        >
          Add zone
        </button>
      </form>
      <ul className="space-y-2">
        {zones.map((z) => (
          <li
            key={z.name}
            className="flex items-center justify-between border border-[var(--border)] rounded-lg px-4 py-3 bg-[var(--bg-panel)]/40"
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

      <form onSubmit={add} className="grid grid-cols-2 md:grid-cols-3 gap-2 border border-[var(--border)] rounded-lg p-4 bg-[var(--bg-panel)]/40">
        {['name', 'type', 'content', 'ttl', 'prio', 'view', 'geo_tag'].map((k) => (
          <label key={k} className="text-xs text-[var(--muted)] flex flex-col gap-1">
            {k}
            <input
              className="rounded-md bg-[var(--bg)] border border-[var(--border)] px-2 py-1.5 text-sm mono text-[var(--text)]"
              value={form[k]}
              onChange={(e) => setForm({ ...form, [k]: e.target.value })}
              required={k === 'name' || k === 'content' || k === 'type'}
            />
          </label>
        ))}
        <div className="col-span-2 md:col-span-3">
          <button type="submit" className="rounded-md bg-[var(--accent)] text-[#0c1219] font-medium px-4 py-2 text-sm">
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
          className="flex-1 min-w-[12rem] rounded-md bg-[var(--bg)] border border-[var(--border)] px-3 py-2 text-sm mono"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <select
          className="rounded-md bg-[var(--bg)] border border-[var(--border)] px-3 py-2 text-sm"
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
          className="rounded-md bg-[var(--accent)] text-[#0c1219] font-medium px-4 py-2 text-sm disabled:opacity-50"
        >
          {busy ? '…' : 'Query'}
        </button>
      </form>
      {err ? <ErrorBox msg={err} /> : null}
      {result ? (
        <div className="rounded-lg border border-[var(--border)] bg-[var(--bg-panel)]/50 p-4 space-y-2">
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
  const [settings, setSettings] = useState(null)
  const [rpz, setRpz] = useState(null)
  const [err, setErr] = useState('')

  useEffect(() => {
    Promise.all([api.settings(), api.rpz()])
      .then(([s, r]) => {
        setSettings(s)
        setRpz(r)
      })
      .catch((e) => setErr(e.message))
  }, [])

  if (err) return <ErrorBox msg={err} />
  if (!settings) return <p className="text-[var(--muted)]">Loading…</p>

  const rows = Object.entries(settings)

  return (
    <div className="space-y-6 max-w-2xl">
      <header>
        <h1 className="text-2xl font-semibold">Settings</h1>
        <p className="text-sm text-[var(--muted)] mt-1">Read-only snapshot from config</p>
      </header>
      <dl className="rounded-lg border border-[var(--border)] divide-y divide-[var(--border)]">
        {rows.map(([k, v]) => (
          <div key={k} className="flex justify-between gap-4 px-4 py-2.5 text-sm">
            <dt className="text-[var(--muted)]">{k}</dt>
            <dd className="mono text-right break-all">{Array.isArray(v) ? v.join(', ') : String(v)}</dd>
          </div>
        ))}
      </dl>
      {rpz ? (
        <section className="space-y-2">
          <h2 className="text-sm text-[var(--muted)]">RPZ</h2>
          <p className="text-sm">
            {rpz.enabled ? 'Enabled' : 'Disabled'} · {rpz.entries} entries
          </p>
          <ul className="text-sm space-y-1">
            {(rpz.policies || []).map((p) => (
              <li key={p.name} className="mono text-[var(--muted)]">
                {p.name} · {p.action} · {p.source}
              </li>
            ))}
          </ul>
        </section>
      ) : null}
    </div>
  )
}

function ErrorBox({ msg }) {
  return (
    <div className="rounded-md border border-[var(--danger)]/40 bg-[var(--danger)]/10 text-[var(--danger)] text-sm px-3 py-2">
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
      </Routes>
    </Shell>
  )
}
