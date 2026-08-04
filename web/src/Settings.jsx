import { useEffect, useMemo, useState } from 'react'
import {
  ChartLine,
  ClipboardText,
  Cpu,
  Gauge,
  GearSix,
  HardDrives,
  LockSimple,
  Network,
  ShieldCheck,
  Stack,
} from '@phosphor-icons/react'
import { api } from './api'
import { useAuth } from './auth'
import { ErrorBox, LoadingBlock, PageHeader } from './ui'

const ICON = 'regular'

function SettingSection({ id, title, hint, children, className = '' }) {
  return (
    <section className={`settings-section panel ${className}`.trim()} aria-labelledby={id}>
      <div className="settings-section-head">
        <h2 id={id} className="text-sm font-medium tracking-tight">
          {title}
        </h2>
        {hint ? <p className="text-xs text-[var(--muted)] mt-1 leading-relaxed max-w-[52ch]">{hint}</p> : null}
      </div>
      <div className="settings-section-body">{children}</div>
    </section>
  )
}

function SettingToggle({ label, hint, pressed, onToggle, disabled, dirty, extra }) {
  return (
    <div className="settings-toggle-row">
      <div className="min-w-0">
        <div className="text-sm font-medium flex items-center gap-2">
          {label}
          {dirty ? (
            <span className="text-[10px] uppercase tracking-wide text-[var(--warn)]">edited</span>
          ) : null}
        </div>
        {hint ? <div className="text-xs text-[var(--muted)] mt-0.5 leading-relaxed">{hint}</div> : null}
        {extra}
      </div>
      <button
        type="button"
        disabled={disabled}
        onClick={onToggle}
        className={`settings-switch shrink-0 ${pressed ? 'is-on' : ''} disabled:opacity-50`}
        aria-pressed={!!pressed}
        aria-label={label}
      >
        <span className="settings-switch-knob" />
      </button>
    </div>
  )
}

function SettingCallout({ tone = 'warn', children }) {
  return <div className={`settings-callout settings-callout--${tone}`}>{children}</div>
}

function parseHash() {
  const raw = (window.location.hash || '').replace(/^#/, '')
  if (!raw) return { section: 'dns', tool: 'axfr' }
  if (raw.startsWith('tools/') || raw.startsWith('tools-')) {
    const tool = raw.replace(/^tools[/|-]/, '') || 'axfr'
    return { section: 'tools', tool }
  }
  if (raw === 'tools') return { section: 'tools', tool: 'axfr' }
  if (raw === 'features' || raw === 'engines') return { section: 'engines', tool: 'axfr' }
  if (raw === 'rate_limit' || raw === 'ratelimit') return { section: 'rate-limit', tool: 'axfr' }
  if (raw === 'transparent' || raw === 'intercept') return { section: 'tproxy', tool: 'axfr' }
  if (raw === 'os' || raw === 'kernel' || raw === 'conntrack') return { section: 'conntrack', tool: 'axfr' }
  return { section: raw, tool: 'axfr' }
}

function setHash(section, tool) {
  const next = section === 'tools' ? `tools/${tool || 'axfr'}` : section
  if (window.location.hash.replace(/^#/, '') !== next) {
    window.history.replaceState(null, '', `#${next}`)
  }
}

export default function Settings({ tools = {} }) {
  const { isAdmin } = useAuth()
  const initial = parseHash()
  const [saved, setSaved] = useState(null)
  const [draft, setDraft] = useState(null)
  const [rpz, setRpz] = useState(null)
  const [err, setErr] = useState('')
  const [ok, setOk] = useState('')
  const [busy, setBusy] = useState(false)
  const [section, setSection] = useState(initial.section)
  const [tool, setTool] = useState(initial.tool)
  const [fwdInput, setFwdInput] = useState('')
  const [fwdEditIdx, setFwdEditIdx] = useState(-1)
  const [fzZone, setFzZone] = useState('')
  const [fzFwd, setFzFwd] = useState('')
  const [fzEditIdx, setFzEditIdx] = useState(-1)
  const [rlWlInput, setRlWlInput] = useState('')
  const [rlWlEditIdx, setRlWlEditIdx] = useState(-1)
  const [tproxy, setTproxy] = useState(null)
  const [tpDraft, setTpDraft] = useState(null)
  const [tpBusy, setTpBusy] = useState(false)
  const [conntrack, setConntrack] = useState(null)
  const [ctDraft, setCtDraft] = useState(null)
  const [ctBusy, setCtBusy] = useState(false)

  const toDraft = (s) => ({
    geodns: !!s.geodns,
    rpz_enabled: !!s.rpz_enabled,
    rate_limit: !!s.rate_limit,
    rate_limit_qps: Number(s.rate_limit_qps) || 2000,
    rate_limit_burst: Number(s.rate_limit_burst) || 400,
    rate_limit_block_duration: Number(s.rate_limit_block_duration) || 300,
    rate_limit_whitelist: Array.isArray(s.rate_limit_whitelist) ? [...s.rate_limit_whitelist] : [],
    ecs_enabled: !!s.ecs_enabled,
    split_horizon: !!s.split_horizon,
    forward_on_fail: s.forward_on_fail !== false,
    query_log_enabled: !!s.query_log_enabled,
    query_log_retention_days: Number(s.query_log_retention_days) || 3,
    query_log_max_size_mb: Number(s.query_log_max_size_mb) || 5120,
    query_log_sample_rate: s.query_log_sample_rate == null ? 0.05 : Number(s.query_log_sample_rate),
    resolver_mode: s.resolver_mode === 'forward' ? 'forward' : 'recursive',
    forwarders: Array.isArray(s.forwarders) ? [...s.forwarders] : [],
    forward_zones: Array.isArray(s.forward_zones)
      ? s.forward_zones.map((z) => ({
          zone: z.zone || '',
          forwarders: Array.isArray(z.forwarders) ? [...z.forwarders] : [],
        }))
      : [],
    allow_query: Array.isArray(s.allow_query) ? s.allow_query.join('\n') : '',
    deny_query: Array.isArray(s.deny_query) ? s.deny_query.join('\n') : '',
  })

  const linesToList = (text) =>
    String(text || '')
      .split(/[\n,]+/)
      .map((x) => x.trim())
      .filter(Boolean)

  const sameList = (a, b) => {
    const aa = Array.isArray(a) ? a : linesToList(a)
    const bb = Array.isArray(b) ? b : linesToList(b)
    if (aa.length !== bb.length) return false
    return aa.every((v, i) => v === bb[i])
  }

  const sameForwardZones = (a, b) => {
    const aa = Array.isArray(a) ? a : []
    const bb = Array.isArray(b) ? b : []
    if (aa.length !== bb.length) return false
    return aa.every(
      (z, i) => z.zone === bb[i].zone && sameList(z.forwarders || [], bb[i].forwarders || []),
    )
  }

  const toTpDraft = (t) => ({
    tproxy_listen: !!t.tproxy_listen,
    tproxy_intercept: !!t.tproxy_intercept,
    tproxy_iface: t.tproxy_iface || '',
    tproxy_mode: t.tproxy_mode === 'all' || t.tproxy_mode === 'custom' ? t.tproxy_mode : 'public',
    tproxy_resolvers: Array.isArray(t.tproxy_resolvers) ? t.tproxy_resolvers.join('\n') : '',
  })

  const toCtDraft = (c) => ({
    conntrack_managed: !!c.conntrack_managed,
    conntrack_max: Number(c.conntrack_max) || Number(c.default_max) || 2097152,
    conntrack_hashsize: Number(c.conntrack_hashsize) || 0,
    conntrack_persist: c.conntrack_persist !== false,
  })

  const load = () =>
    Promise.all([
      api.settings(),
      api.rpz(),
      api.tproxy().catch(() => null),
      api.conntrack().catch(() => null),
    ])
      .then(([s, r, t, ct]) => {
        setSaved(s)
        setDraft(toDraft(s))
        setRpz(r)
        if (t) {
          setTproxy(t)
          setTpDraft(toTpDraft(t))
        }
        if (ct) {
          setConntrack(ct)
          setCtDraft(toCtDraft(ct))
        }
      })
      .catch((e) => setErr(e.message))

  useEffect(() => {
    load()
  }, [])

  useEffect(() => {
    const onHash = () => {
      const h = parseHash()
      setSection(h.section)
      setTool(h.tool)
    }
    window.addEventListener('hashchange', onHash)
    return () => window.removeEventListener('hashchange', onHash)
  }, [])

  useEffect(() => {
    setHash(section, tool)
  }, [section, tool])

  const dirtyDns =
    saved &&
    draft &&
    ((draft.resolver_mode === 'forward' ? 'forward' : 'recursive') !==
      (saved.resolver_mode === 'forward' ? 'forward' : 'recursive') ||
      !!draft.forward_on_fail !== (saved.forward_on_fail !== false) ||
      !sameList(draft.forwarders, saved.forwarders || []) ||
      !sameForwardZones(draft.forward_zones, saved.forward_zones || []))

  const dirtyAcl =
    saved && draft && (!sameList(draft.allow_query, saved.allow_query) || !sameList(draft.deny_query, saved.deny_query))

  const dirtyRateLimit =
    saved &&
    draft &&
    (!!draft.rate_limit !== !!saved.rate_limit ||
      Number(draft.rate_limit_qps) !== Number(saved.rate_limit_qps || 0) ||
      Number(draft.rate_limit_burst) !== Number(saved.rate_limit_burst || 0) ||
      Number(draft.rate_limit_block_duration) !== Number(saved.rate_limit_block_duration || 0) ||
      !sameList(draft.rate_limit_whitelist, saved.rate_limit_whitelist || []))

  const dirtyEngines =
    saved &&
    draft &&
    ['geodns', 'rpz_enabled', 'ecs_enabled', 'split_horizon'].some((k) => !!draft[k] !== !!saved[k])

  const dirtyLogging =
    saved &&
    draft &&
    (!!draft.query_log_enabled !== !!saved.query_log_enabled ||
      Number(draft.query_log_retention_days) !== Number(saved.query_log_retention_days || 0) ||
      Number(draft.query_log_max_size_mb) !== Number(saved.query_log_max_size_mb || 0) ||
      Number(draft.query_log_sample_rate) !== Number(saved.query_log_sample_rate ?? 0.05))

  const dirtyFlags = useMemo(
    () => ({
      dns: !!dirtyDns,
      access: !!dirtyAcl,
      'rate-limit': !!dirtyRateLimit,
      engines: !!dirtyEngines,
      logging: !!dirtyLogging,
    }),
    [dirtyDns, dirtyAcl, dirtyRateLimit, dirtyEngines, dirtyLogging],
  )

  const dirtyCount = Object.values(dirtyFlags).filter(Boolean).length
  const dirty = dirtyCount > 0

  const toggle = (key) => {
    setOk('')
    setErr('')
    setDraft((d) => ({ ...d, [key]: !d[key] }))
  }

  const discard = () => {
    if (!saved) return
    setDraft(toDraft(saved))
    setFwdInput('')
    setFwdEditIdx(-1)
    setFzZone('')
    setFzFwd('')
    setFzEditIdx(-1)
    setRlWlInput('')
    setRlWlEditIdx(-1)
    setOk('')
    setErr('')
  }

  const save = async () => {
    if (!draft || !dirty) return
    setBusy(true)
    setErr('')
    setOk('')
    try {
      const payload = {
        geodns: draft.geodns,
        rpz_enabled: draft.rpz_enabled,
        rate_limit: draft.rate_limit,
        rate_limit_qps: Number(draft.rate_limit_qps) || 2000,
        rate_limit_burst: Number(draft.rate_limit_burst) || 400,
        rate_limit_block_duration: Number(draft.rate_limit_block_duration) || 300,
        rate_limit_whitelist: draft.rate_limit_whitelist || [],
        ecs_enabled: draft.ecs_enabled,
        split_horizon: draft.split_horizon,
        forward_on_fail: draft.forward_on_fail,
        query_log_enabled: draft.query_log_enabled,
        query_log_retention_days: Number(draft.query_log_retention_days) || 0,
        query_log_max_size_mb: Number(draft.query_log_max_size_mb) || 0,
        query_log_sample_rate: Math.min(1, Math.max(0, Number(draft.query_log_sample_rate) || 0)),
        resolver_mode: draft.resolver_mode,
        forwarders: draft.forwarders,
        forward_zones: (draft.forward_zones || []).map((z) => ({
          zone: z.zone,
          forwarders: z.forwarders || [],
        })),
        allow_query: linesToList(draft.allow_query),
        deny_query: linesToList(draft.deny_query),
      }
      const s = await api.updateSettings(payload)
      setSaved(s)
      setDraft(toDraft(s))
      setFwdInput('')
      setFwdEditIdx(-1)
      setFzZone('')
      setFzFwd('')
      setFzEditIdx(-1)
      setRlWlInput('')
      setRlWlEditIdx(-1)
      setOk('Saved — live now')
      setRpz(await api.rpz())
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  const addOrUpdateForwarder = () => {
    const v = fwdInput.trim()
    if (!v) return
    setOk('')
    setErr('')
    setDraft((d) => {
      const list = [...(d.forwarders || [])]
      if (fwdEditIdx >= 0 && fwdEditIdx < list.length) list[fwdEditIdx] = v
      else if (!list.includes(v)) list.push(v)
      return { ...d, forwarders: list }
    })
    setFwdInput('')
    setFwdEditIdx(-1)
  }

  const editForwarder = (idx) => {
    setFwdInput((draft.forwarders || [])[idx] || '')
    setFwdEditIdx(idx)
    setOk('')
    setErr('')
  }

  const removeForwarder = (idx) => {
    setOk('')
    setErr('')
    setDraft((d) => ({ ...d, forwarders: (d.forwarders || []).filter((_, i) => i !== idx) }))
    if (fwdEditIdx === idx) {
      setFwdInput('')
      setFwdEditIdx(-1)
    } else if (fwdEditIdx > idx) setFwdEditIdx((i) => i - 1)
  }

  const addOrUpdateForwardZone = () => {
    const zone = fzZone.trim()
    const fwd = linesToList(fzFwd)
    if (!zone || fwd.length === 0) return
    setOk('')
    setErr('')
    setDraft((d) => {
      const list = [...(d.forward_zones || [])]
      const entry = { zone, forwarders: fwd }
      if (fzEditIdx >= 0 && fzEditIdx < list.length) list[fzEditIdx] = entry
      else {
        const i = list.findIndex((z) => z.zone.toLowerCase() === zone.toLowerCase())
        if (i >= 0) list[i] = entry
        else list.push(entry)
      }
      return { ...d, forward_zones: list }
    })
    setFzZone('')
    setFzFwd('')
    setFzEditIdx(-1)
  }

  const editForwardZone = (idx) => {
    const z = (draft.forward_zones || [])[idx]
    if (!z) return
    setFzZone(z.zone || '')
    setFzFwd((z.forwarders || []).join(', '))
    setFzEditIdx(idx)
    setOk('')
    setErr('')
  }

  const removeForwardZone = (idx) => {
    setOk('')
    setErr('')
    setDraft((d) => ({ ...d, forward_zones: (d.forward_zones || []).filter((_, i) => i !== idx) }))
    if (fzEditIdx === idx) {
      setFzZone('')
      setFzFwd('')
      setFzEditIdx(-1)
    } else if (fzEditIdx > idx) setFzEditIdx((i) => i - 1)
  }

  const addOrUpdateRlWl = () => {
    const v = rlWlInput.trim()
    if (!v) return
    setOk('')
    setErr('')
    setDraft((d) => {
      const list = [...(d.rate_limit_whitelist || [])]
      if (rlWlEditIdx >= 0 && rlWlEditIdx < list.length) list[rlWlEditIdx] = v
      else list.push(v)
      return { ...d, rate_limit_whitelist: list }
    })
    setRlWlInput('')
    setRlWlEditIdx(-1)
  }

  const editRlWl = (idx) => {
    setRlWlInput((draft.rate_limit_whitelist || [])[idx] || '')
    setRlWlEditIdx(idx)
  }

  const removeRlWl = (idx) => {
    setOk('')
    setErr('')
    setDraft((d) => ({
      ...d,
      rate_limit_whitelist: (d.rate_limit_whitelist || []).filter((_, i) => i !== idx),
    }))
    if (rlWlEditIdx === idx) {
      setRlWlInput('')
      setRlWlEditIdx(-1)
    } else if (rlWlEditIdx > idx) setRlWlEditIdx((i) => i - 1)
  }

  const copyAclToRlWhitelist = () => {
    const fromAcl = linesToList(draft.allow_query)
    setDraft((d) => {
      const merged = [...(d.rate_limit_whitelist || [])]
      for (const c of fromAcl) {
        if (!merged.includes(c)) merged.push(c)
      }
      return { ...d, rate_limit_whitelist: merged }
    })
    setOk('')
    setErr('')
  }

  const clearRlBlocks = async () => {
    setBusy(true)
    setErr('')
    setOk('')
    try {
      const s = await api.updateSettings({ clear_rate_limit_blocks: true })
      setSaved(s)
      setDraft(toDraft(s))
      setOk('Cleared temporary rate-limit blocks')
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  const tpDirty =
    tproxy &&
    tpDraft &&
    (!!tpDraft.tproxy_listen !== !!tproxy.tproxy_listen ||
      !!tpDraft.tproxy_intercept !== !!tproxy.tproxy_intercept ||
      (tpDraft.tproxy_iface || '') !== (tproxy.tproxy_iface || '') ||
      (tpDraft.tproxy_mode || 'public') !== (tproxy.tproxy_mode || 'public') ||
      !sameList(tpDraft.tproxy_resolvers, tproxy.tproxy_resolvers || []))

  const saveTProxy = async (extra = {}) => {
    if (!tpDraft) return
    setTpBusy(true)
    setErr('')
    setOk('')
    try {
      const body = {
        tproxy_listen: !!tpDraft.tproxy_listen,
        tproxy_intercept: !!tpDraft.tproxy_intercept,
        tproxy_iface: (tpDraft.tproxy_iface || '').trim(),
        tproxy_mode: tpDraft.tproxy_mode || 'public',
        tproxy_resolvers: linesToList(tpDraft.tproxy_resolvers),
        apply_now: true,
        ...extra,
      }
      const t = await api.updateTProxy(body)
      setTproxy(t)
      setTpDraft(toTpDraft(t))
      if (t.apply_error) {
        setErr(t.apply_error)
        setOk('Saved settings, but intercept apply failed')
      } else {
        setOk(
          t.tproxy_listen_needs_restart
            ? 'Saved — restart service to apply transparent sockets'
            : 'Saved — intercept applied live',
        )
      }
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setTpBusy(false)
    }
  }

  const applyTProxyNow = async () => {
    setTpBusy(true)
    setErr('')
    setOk('')
    try {
      const t = await api.applyTProxy()
      setTproxy(t)
      setTpDraft(toTpDraft(t))
      if (t.apply_error) setErr(t.apply_error)
      else setOk('Intercept applied')
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setTpBusy(false)
    }
  }

  const disableTProxyNow = async () => {
    setTpBusy(true)
    setErr('')
    setOk('')
    try {
      const t = await api.disableTProxy()
      setTproxy(t)
      setTpDraft(toTpDraft(t))
      if (t.apply_error) setErr(t.apply_error)
      else setOk('Intercept disabled')
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setTpBusy(false)
    }
  }

  const restartForTProxy = async () => {
    if (!window.confirm('Restart PowerSVX to apply transparent socket (tproxy_listen)?')) return
    setTpBusy(true)
    setErr('')
    setOk('')
    try {
      await api.restartTProxy()
      setOk('Restarting… reload this page in a few seconds')
    } catch (ex) {
      setErr(ex.message)
      setTpBusy(false)
    }
  }

  const ctDirty =
    conntrack &&
    ctDraft &&
    (!!ctDraft.conntrack_managed !== !!conntrack.conntrack_managed ||
      Number(ctDraft.conntrack_max) !== Number(conntrack.conntrack_max || 0) ||
      Number(ctDraft.conntrack_hashsize) !== Number(conntrack.conntrack_hashsize || 0) ||
      !!ctDraft.conntrack_persist !== (conntrack.conntrack_persist !== false))

  const saveConntrack = async () => {
    if (!ctDraft) return
    setCtBusy(true)
    setErr('')
    setOk('')
    try {
      const body = {
        conntrack_managed: !!ctDraft.conntrack_managed,
        conntrack_max: Number(ctDraft.conntrack_max) || 0,
        conntrack_hashsize: Number(ctDraft.conntrack_hashsize) || 0,
        conntrack_persist: !!ctDraft.conntrack_persist,
        apply_now: true,
      }
      const c = await api.updateConntrack(body)
      setConntrack(c)
      setCtDraft(toCtDraft(c))
      if (c.apply_error) {
        setErr(c.apply_error)
        setOk('Saved settings, but live apply had issues')
      } else {
        setOk(ctDraft.conntrack_managed ? 'Saved — conntrack applied' : 'Saved — management off (kernel left as-is)')
      }
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setCtBusy(false)
    }
  }

  const applyConntrackNow = async () => {
    setCtBusy(true)
    setErr('')
    setOk('')
    try {
      const c = await api.applyConntrack()
      setConntrack(c)
      setCtDraft(toCtDraft(c))
      if (c.apply_error) setErr(c.apply_error)
      else setOk('Conntrack limits applied')
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setCtBusy(false)
    }
  }

  const refreshConntrack = async () => {
    setCtBusy(true)
    setErr('')
    try {
      const c = await api.conntrack()
      setConntrack(c)
      if (!ctDirty) setCtDraft(toCtDraft(c))
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setCtBusy(false)
    }
  }

  const goSection = (id) => {
    setSection(id)
    setOk('')
  }

  if (err && !saved) return <ErrorBox msg={err} />
  if (!saved || !draft) return <LoadingBlock label="Loading settings" />

  const categories = [
    { id: 'dns', label: 'DNS', hint: 'Lookup path', Icon: Stack, dirty: dirtyFlags.dns },
    { id: 'access', label: 'Access', hint: 'Who may query', Icon: LockSimple, dirty: dirtyFlags.access },
    { id: 'rate-limit', label: 'Rate limit', hint: 'Per-IP caps', Icon: Gauge, dirty: dirtyFlags['rate-limit'] },
    { id: 'engines', label: 'Engines', hint: 'Optional features', Icon: GearSix, dirty: dirtyFlags.engines },
    { id: 'logging', label: 'Logging', hint: 'Query history', Icon: ClipboardText, dirty: dirtyFlags.logging },
    { id: 'tproxy', label: 'TPROXY', hint: 'Transparent DNS', Icon: Network, dirty: !!tpDirty },
    { id: 'conntrack', label: 'OS', hint: 'Conntrack / kernel', Icon: Cpu, dirty: !!ctDirty },
    { id: 'status', label: 'Status', hint: 'Read-only', Icon: ChartLine, dirty: false },
    { id: 'tools', label: 'Tools', hint: 'AXFR, ACME…', Icon: HardDrives, dirty: false },
  ]

  const toolTabs = [
    { id: 'axfr', label: 'AXFR' },
    { id: 'acme', label: 'ACME' },
    { id: 'backup', label: 'Backup' },
    { id: 'users', label: 'Users' },
    { id: 'rpz', label: 'RPZ' },
  ]

  const sectionMeta = categories.find((c) => c.id === section)
  const toolMeta = toolTabs.find((t) => t.id === tool)
  const allowEmpty = linesToList(draft.allow_query).length === 0
  const needsForwarders =
    draft.resolver_mode === 'forward' || (draft.resolver_mode === 'recursive' && draft.forward_on_fail)
  const noForwarders = (draft.forwarders || []).length === 0

  const saveBar = (
    <div className="flex gap-2">
      <button
        type="button"
        disabled={!dirty || busy || !isAdmin}
        onClick={discard}
        className="btn btn-secondary min-h-[44px] disabled:opacity-40"
      >
        Discard
      </button>
      <button
        type="button"
        disabled={!dirty || busy || !isAdmin}
        onClick={save}
        className="btn btn-primary min-h-[44px] disabled:opacity-40"
      >
        {busy ? 'Saving…' : dirtyCount > 0 ? `Save · ${dirtyCount}` : 'Save'}
      </button>
    </div>
  )

  const editableSection = ['dns', 'access', 'rate-limit', 'engines', 'logging'].includes(section)
  const ToolAxfr = tools.axfr
  const ToolAcme = tools.acme
  const ToolBackup = tools.backup
  const ToolUsers = tools.users
  const ToolRpz = tools.rpz

  return (
    <div className="settings-page space-y-5 max-w-5xl pb-28">
      <PageHeader
        eyebrow="Configure"
        title="Settings"
        sub={
          section === 'tools'
            ? `Tools · ${toolMeta?.label || 'AXFR'}`
            : `${sectionMeta?.label || 'DNS'} · ${sectionMeta?.hint || ''}`
        }
        actions={
          editableSection && isAdmin
            ? saveBar
            : section === 'tproxy' && isAdmin
              ? (
                  <div className="flex gap-2">
                    <button
                      type="button"
                      disabled={!tpDirty || tpBusy}
                      onClick={() => {
                        if (tproxy) setTpDraft(toTpDraft(tproxy))
                        setOk('')
                        setErr('')
                      }}
                      className="btn btn-secondary min-h-[44px] disabled:opacity-40"
                    >
                      Discard
                    </button>
                    <button
                      type="button"
                      disabled={!tpDirty || tpBusy}
                      onClick={() => saveTProxy()}
                      className="btn btn-primary min-h-[44px] disabled:opacity-40"
                    >
                      {tpBusy ? 'Saving…' : 'Save & apply'}
                    </button>
                  </div>
                )
              : section === 'conntrack' && isAdmin
                ? (
                    <div className="flex gap-2">
                      <button
                        type="button"
                        disabled={!ctDirty || ctBusy}
                        onClick={() => {
                          if (conntrack) setCtDraft(toCtDraft(conntrack))
                          setOk('')
                          setErr('')
                        }}
                        className="btn btn-secondary min-h-[44px] disabled:opacity-40"
                      >
                        Discard
                      </button>
                      <button
                        type="button"
                        disabled={!ctDirty || ctBusy}
                        onClick={saveConntrack}
                        className="btn btn-primary min-h-[44px] disabled:opacity-40"
                      >
                        {ctBusy ? 'Saving…' : 'Save & apply'}
                      </button>
                    </div>
                  )
                : null
        }
      />

      {!isAdmin ? (
        <p className="text-xs text-[var(--muted)]">View only — your role cannot change settings.</p>
      ) : null}
      {err ? <ErrorBox msg={err} /> : null}
      {ok ? (
        <div className="flash-ok" role="status">
          {ok}
        </div>
      ) : null}

      <div className="settings-layout">
        <nav className="settings-rail panel" aria-label="Settings categories">
          {categories.map((c) => {
            const Icon = c.Icon
            const active = section === c.id
            return (
              <button
                key={c.id}
                type="button"
                onClick={() => goSection(c.id)}
                aria-current={active ? 'page' : undefined}
                className={`settings-rail-item ${active ? 'is-active' : ''}`}
              >
                <Icon weight={ICON} className="settings-rail-icon" aria-hidden />
                <span className="settings-rail-text">
                  <span className="settings-rail-label">
                    {c.label}
                    {c.dirty ? <span className="settings-dirty-dot" title="Unsaved" aria-label="Unsaved" /> : null}
                  </span>
                  <span className="settings-rail-hint">{c.hint}</span>
                </span>
              </button>
            )
          })}
        </nav>

        <div key={section} className="settings-main reveal space-y-4">
          {section === 'dns' ? (
            <>
              {needsForwarders && noForwarders ? (
                <SettingCallout tone="warn">
                  No forwarders configured — add at least one for forward mode or recursive fallback.
                </SettingCallout>
              ) : null}
              <SettingSection id="settings-dns-heading" title="Lookup mode" hint="Pick one path. Save to apply.">
                <div className="settings-mode-grid">
                  {[
                    ['forward', 'Forward', 'Send queries to upstream resolvers only'],
                    ['recursive', 'Recursive', 'Ask the DNS root servers directly'],
                  ].map(([mode, title, desc]) => (
                    <button
                      key={mode}
                      type="button"
                      disabled={busy || !isAdmin}
                      onClick={() => {
                        setOk('')
                        setErr('')
                        setDraft((d) => ({ ...d, resolver_mode: mode }))
                      }}
                      className={`settings-mode-card ${draft.resolver_mode === mode ? 'is-selected' : ''}`}
                      aria-pressed={draft.resolver_mode === mode}
                    >
                      <div className="text-sm font-medium flex items-center gap-2">
                        {title}
                        {draft.resolver_mode === mode ? (
                          <span className="settings-chip">selected</span>
                        ) : null}
                      </div>
                      <div className="text-xs text-[var(--muted)] mt-1 leading-relaxed">{desc}</div>
                    </button>
                  ))}
                </div>
                <SettingToggle
                  label="Fallback to forwarders"
                  hint={
                    draft.resolver_mode !== 'recursive'
                      ? 'Only available in recursive mode'
                      : 'If recursive fails, try configured forwarders'
                  }
                  pressed={!!draft.forward_on_fail}
                  disabled={busy || !isAdmin || draft.resolver_mode !== 'recursive'}
                  dirty={!!draft.forward_on_fail !== (saved.forward_on_fail !== false)}
                  onToggle={() => toggle('forward_on_fail')}
                />
              </SettingSection>

              <SettingSection
                id="settings-fwd-heading"
                title="Forwarders"
                hint="Upstream for forward mode and recursive fallback. UDP 1.1.1.1:53, DoT tls://…, or DoH https://…"
              >
                {(draft.forwarders || []).length === 0 ? (
                  <p className="text-xs text-[var(--warn)]">None yet.</p>
                ) : (
                  <ul className="settings-list">
                    {(draft.forwarders || []).map((addr, idx) => (
                      <li key={`${addr}-${idx}`} className="settings-list-item">
                        <span className="mono text-sm flex-1 min-w-[8rem]">{addr}</span>
                        <button type="button" disabled={busy || !isAdmin} onClick={() => editForwarder(idx)} className="btn btn-secondary text-xs min-h-[36px] disabled:opacity-50">
                          Edit
                        </button>
                        <button type="button" disabled={busy || !isAdmin} onClick={() => removeForwarder(idx)} className="btn btn-secondary text-xs min-h-[36px] text-[var(--danger)] disabled:opacity-50">
                          Delete
                        </button>
                      </li>
                    ))}
                  </ul>
                )}
                <form
                  className="settings-inline-form"
                  onSubmit={(e) => {
                    e.preventDefault()
                    addOrUpdateForwarder()
                  }}
                >
                  <label className="flex-1 min-w-[12rem] text-xs text-[var(--muted)] space-y-1">
                    {fwdEditIdx >= 0 ? 'Edit forwarder' : 'Add forwarder'}
                    <input
                      value={fwdInput}
                      disabled={busy || !isAdmin}
                      onChange={(e) => setFwdInput(e.target.value)}
                      placeholder="1.1.1.1:53 or tls://…"
                      className="input mono w-full min-h-[44px]"
                    />
                  </label>
                  <button type="submit" disabled={busy || !isAdmin || !fwdInput.trim()} className="btn btn-primary min-h-[44px] disabled:opacity-50">
                    {fwdEditIdx >= 0 ? 'Update' : 'Add'}
                  </button>
                  {fwdEditIdx >= 0 ? (
                    <button type="button" disabled={busy} onClick={() => { setFwdInput(''); setFwdEditIdx(-1) }} className="btn btn-secondary min-h-[44px]">
                      Cancel
                    </button>
                  ) : null}
                </form>
              </SettingSection>

              <SettingSection
                id="settings-fzone-heading"
                title="Conditional forward zones"
                hint="Longest-suffix match routes a domain to specific upstreams before recursion / global forwarders."
              >
                {(draft.forward_zones || []).length === 0 ? (
                  <p className="text-xs text-[var(--muted)]">None configured.</p>
                ) : (
                  <ul className="settings-list">
                    {(draft.forward_zones || []).map((z, idx) => (
                      <li key={`${z.zone}-${idx}`} className="settings-list-item">
                        <div className="flex-1 min-w-[10rem]">
                          <div className="mono text-sm">{z.zone}</div>
                          <div className="text-xs text-[var(--muted)] mono">{(z.forwarders || []).join(', ')}</div>
                        </div>
                        <button type="button" disabled={busy || !isAdmin} onClick={() => editForwardZone(idx)} className="btn btn-secondary text-xs min-h-[36px] disabled:opacity-50">
                          Edit
                        </button>
                        <button type="button" disabled={busy || !isAdmin} onClick={() => removeForwardZone(idx)} className="btn btn-secondary text-xs min-h-[36px] text-[var(--danger)] disabled:opacity-50">
                          Delete
                        </button>
                      </li>
                    ))}
                  </ul>
                )}
                <form
                  className="settings-inline-form"
                  onSubmit={(e) => {
                    e.preventDefault()
                    addOrUpdateForwardZone()
                  }}
                >
                  <label className="min-w-[10rem] flex-1 text-xs text-[var(--muted)] space-y-1">
                    Zone
                    <input value={fzZone} disabled={busy || !isAdmin} onChange={(e) => setFzZone(e.target.value)} placeholder="corp.local" className="input mono w-full min-h-[44px]" />
                  </label>
                  <label className="min-w-[14rem] flex-[2] text-xs text-[var(--muted)] space-y-1">
                    Forwarders (comma or newline)
                    <input value={fzFwd} disabled={busy || !isAdmin} onChange={(e) => setFzFwd(e.target.value)} placeholder="10.0.0.1:53, 10.0.0.2:53" className="input mono w-full min-h-[44px]" />
                  </label>
                  <button type="submit" disabled={busy || !isAdmin || !fzZone.trim() || !fzFwd.trim()} className="btn btn-primary min-h-[44px] disabled:opacity-50">
                    {fzEditIdx >= 0 ? 'Update' : 'Add'}
                  </button>
                  {fzEditIdx >= 0 ? (
                    <button type="button" disabled={busy} onClick={() => { setFzZone(''); setFzFwd(''); setFzEditIdx(-1) }} className="btn btn-secondary min-h-[44px]">
                      Cancel
                    </button>
                  ) : null}
                </form>
              </SettingSection>
            </>
          ) : null}

          {section === 'access' ? (
            <>
              {allowEmpty ? (
                <SettingCallout tone="warn">
                  Open resolver: Allow is empty — any client may query. Restrict to customer CIDRs in production.
                </SettingCallout>
              ) : null}
              <SettingSection
                id="settings-access-heading"
                title="Who can query"
                hint="Leave Allow empty for everyone. Deny always wins. One IP or CIDR per line."
              >
                <label className="block text-xs text-[var(--muted)] space-y-1">
                  Allow
                  <textarea
                    rows={6}
                    disabled={busy || !isAdmin}
                    value={draft.allow_query}
                    onChange={(e) => {
                      setOk('')
                      setErr('')
                      setDraft((d) => ({ ...d, allow_query: e.target.value }))
                    }}
                    placeholder={'10.0.0.0/8\n192.168.0.0/16\n127.0.0.1'}
                    className="input mono w-full min-h-[8rem]"
                  />
                </label>
                <label className="block text-xs text-[var(--muted)] space-y-1 mt-4">
                  Deny
                  <textarea
                    rows={3}
                    disabled={busy || !isAdmin}
                    value={draft.deny_query}
                    onChange={(e) => {
                      setOk('')
                      setErr('')
                      setDraft((d) => ({ ...d, deny_query: e.target.value }))
                    }}
                    placeholder="optional"
                    className="input mono w-full"
                  />
                </label>
              </SettingSection>
            </>
          ) : null}

          {section === 'rate-limit' ? (
            <>
              {allowEmpty && !draft.rate_limit ? (
                <SettingCallout tone="muted">
                  ACL is open and rate limit is off — consider enabling rate limit for abuse protection.
                </SettingCallout>
              ) : null}
              <SettingSection id="settings-rl-heading" title="Rate limit" hint="Cap queries per client IP. Whitelist skips the limiter (separate from Access ACL).">
                <div className="flex justify-end mb-1">
                  <button type="button" disabled={busy || !isAdmin} onClick={clearRlBlocks} className="btn btn-secondary text-xs min-h-[36px] disabled:opacity-40">
                    Clear active blocks
                  </button>
                </div>
                <SettingToggle
                  label="Enable rate limit"
                  hint="Refuse excess queries from a single client IP"
                  pressed={!!draft.rate_limit}
                  disabled={busy || !isAdmin}
                  dirty={!!draft.rate_limit !== !!saved.rate_limit}
                  onToggle={() => toggle('rate_limit')}
                />
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mt-4">
                  {[
                    ['rate_limit_qps', 'QPS', 1],
                    ['rate_limit_burst', 'Burst', 1],
                    ['rate_limit_block_duration', 'Block duration (sec)', 1],
                  ].map(([key, label, min]) => (
                    <label key={key} className="text-xs text-[var(--muted)] space-y-1 block">
                      {label}
                      <input
                        type="number"
                        min={min}
                        disabled={busy || !isAdmin}
                        className="input mono w-full"
                        value={draft[key]}
                        onChange={(e) => {
                          setOk('')
                          setErr('')
                          setDraft((d) => ({ ...d, [key]: e.target.value }))
                        }}
                      />
                    </label>
                  ))}
                </div>
                <div className="mt-5 space-y-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h3 className="text-xs text-[var(--muted)] flex items-center gap-1.5">
                      <ShieldCheck weight={ICON} className="h-3.5 w-3.5" aria-hidden />
                      Whitelist
                    </h3>
                    <button type="button" disabled={busy || !isAdmin} onClick={copyAclToRlWhitelist} className="text-xs text-[var(--accent)] underline disabled:opacity-40">
                      Copy from Access ACL
                    </button>
                  </div>
                  {(draft.rate_limit_whitelist || []).length === 0 ? (
                    <p className="text-xs text-[var(--warn)]">No whitelist — allowed clients are still rate-limited.</p>
                  ) : (
                    <ul className="settings-list">
                      {(draft.rate_limit_whitelist || []).map((addr, idx) => (
                        <li key={`${addr}-${idx}`} className="settings-list-item">
                          <span className="mono text-sm truncate flex-1">{addr}</span>
                          <button type="button" disabled={busy || !isAdmin} onClick={() => editRlWl(idx)} className="text-xs text-[var(--accent)] disabled:opacity-40">
                            Edit
                          </button>
                          <button type="button" disabled={busy || !isAdmin} onClick={() => removeRlWl(idx)} className="text-xs text-[var(--warn)] disabled:opacity-40">
                            Delete
                          </button>
                        </li>
                      ))}
                    </ul>
                  )}
                  <form
                    onSubmit={(e) => {
                      e.preventDefault()
                      addOrUpdateRlWl()
                    }}
                    className="settings-inline-form"
                  >
                    <input
                      className="input mono flex-1 min-w-[10rem]"
                      placeholder="103.172.70.0/23"
                      disabled={busy || !isAdmin}
                      value={rlWlInput}
                      onChange={(e) => setRlWlInput(e.target.value)}
                    />
                    <button type="submit" disabled={busy || !isAdmin || !rlWlInput.trim()} className="btn btn-primary text-sm disabled:opacity-40">
                      {rlWlEditIdx >= 0 ? 'Update' : 'Add'}
                    </button>
                    {rlWlEditIdx >= 0 ? (
                      <button type="button" onClick={() => { setRlWlInput(''); setRlWlEditIdx(-1) }} className="btn btn-secondary text-sm">
                        Cancel
                      </button>
                    ) : null}
                  </form>
                </div>
              </SettingSection>
            </>
          ) : null}

          {section === 'engines' ? (
            <SettingSection id="settings-engines-heading" title="Engines" hint="Optional resolution features. Save to apply.">
              {[
                ['geodns', 'GeoDNS', 'Route by client country'],
                ['rpz_enabled', 'Blocklist (RPZ)', 'Block domains from feeds'],
                ['ecs_enabled', 'Client subnet (ECS)', 'Send subnet to upstream'],
                ['split_horizon', 'Split horizon', 'Different answers by network'],
              ].map(([key, label, hint]) => (
                <SettingToggle
                  key={key}
                  label={label}
                  hint={hint}
                  pressed={!!draft[key]}
                  disabled={busy || !isAdmin}
                  dirty={!!draft[key] !== !!saved[key]}
                  onToggle={() => toggle(key)}
                  extra={
                    key === 'geodns' && saved.geodns_db ? (
                      <div className="text-xs mono text-[var(--muted)] mt-1 space-y-1">
                        <div>{saved.geodns_db}</div>
                        <div>
                          IP geolocation by{' '}
                          <a href="https://db-ip.com" target="_blank" rel="noreferrer" className="text-[var(--accent)] hover:underline">
                            DB-IP
                          </a>{' '}
                          (Country Lite, CC BY 4.0).
                        </div>
                      </div>
                    ) : null
                  }
                />
              ))}
            </SettingSection>
          ) : null}

          {section === 'logging' ? (
            <SettingSection id="settings-logging-heading" title="Query log" hint="Save queries to the database. Cap growth with size and retention guards.">
              <SettingToggle
                label="Enable query log"
                hint="Record queries for the Logs view"
                pressed={!!draft.query_log_enabled}
                disabled={busy || !isAdmin}
                dirty={!!draft.query_log_enabled !== !!saved.query_log_enabled}
                onToggle={() => toggle('query_log_enabled')}
              />
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-4">
                <label className="text-xs text-[var(--muted)] space-y-1 block">
                  Max size (MB)
                  <input
                    type="number"
                    min={0}
                    max={102400}
                    disabled={busy || !isAdmin}
                    className="input mono w-full"
                    value={draft.query_log_max_size_mb}
                    onChange={(e) => {
                      setOk('')
                      setErr('')
                      setDraft((d) => ({ ...d, query_log_max_size_mb: e.target.value }))
                    }}
                  />
                </label>
                <label className="text-xs text-[var(--muted)] space-y-1 block">
                  Retention (days)
                  <input
                    type="number"
                    min={0}
                    max={3650}
                    disabled={busy || !isAdmin}
                    className="input mono w-full"
                    value={draft.query_log_retention_days}
                    onChange={(e) => {
                      setOk('')
                      setErr('')
                      setDraft((d) => ({ ...d, query_log_retention_days: e.target.value }))
                    }}
                  />
                </label>
                <label className="text-xs text-[var(--muted)] space-y-1 block">
                  Sample rate (0–1)
                  <input
                    type="number"
                    min={0}
                    max={1}
                    step={0.01}
                    disabled={busy || !isAdmin}
                    className="input mono w-full"
                    value={draft.query_log_sample_rate}
                    onChange={(e) => {
                      setOk('')
                      setErr('')
                      setDraft((d) => ({ ...d, query_log_sample_rate: e.target.value }))
                    }}
                  />
                </label>
              </div>
              <p className="text-[11px] text-[var(--muted)] mt-3 leading-relaxed">
                Oldest rows are deleted first when over the size limit. 0 disables that guard. Default size cap is 5 GB (5120 MB). Sample rate 0.05 = log ~5%; under high load sampling tightens further.
              </p>
            </SettingSection>
          ) : null}

          {section === 'tproxy' ? (
            !tproxy || !tpDraft ? (
              <SettingCallout tone="warn">TPROXY status unavailable (API not ready or not Linux).</SettingCallout>
            ) : (
              <>
                {!tproxy.supported ? (
                  <SettingCallout tone="warn">
                    OS intercept control requires Linux (nftables + iproute2). Socket listen flag can still be saved for Linux hosts.
                  </SettingCallout>
                ) : null}
                {tproxy.status?.warning ? <SettingCallout tone="warn">{tproxy.status.warning}</SettingCallout> : null}
                {tpDraft.tproxy_mode === 'all' ? (
                  <SettingCallout tone="warn">
                    Mode <span className="mono">all</span> intercepts every DNS packet on the interface — dangerous on BGP/transit. Prefer{' '}
                    <span className="mono">public</span>.
                  </SettingCallout>
                ) : null}
                {tproxy.tproxy_listen_needs_restart ? (
                  <SettingCallout tone="warn">
                    Transparent socket setting differs from the running process — click Restart service after save.
                  </SettingCallout>
                ) : null}

                <SettingSection
                  id="settings-tproxy-socket-heading"
                  title="Transparent sockets"
                  hint="IP_TRANSPARENT + SO_REUSEPORT. Needs process restart (compose unless-stopped)."
                >
                  <SettingToggle
                    label="tproxy_listen"
                    hint={
                      tproxy.tproxy_listen_active
                        ? 'Active in this process'
                        : 'Not active until restart'
                    }
                    pressed={!!tpDraft.tproxy_listen}
                    disabled={tpBusy || !isAdmin}
                    dirty={!!tpDraft.tproxy_listen !== !!tproxy.tproxy_listen}
                    onToggle={() => {
                      setOk('')
                      setErr('')
                      setTpDraft((d) => ({ ...d, tproxy_listen: !d.tproxy_listen }))
                    }}
                  />
                  <div className="flex flex-wrap gap-2 mt-3">
                    <button
                      type="button"
                      disabled={tpBusy || !isAdmin || !tproxy.tproxy_listen_needs_restart}
                      onClick={restartForTProxy}
                      className="btn btn-secondary min-h-[40px] disabled:opacity-40"
                    >
                      Restart service
                    </button>
                  </div>
                </SettingSection>

                <SettingSection
                  id="settings-tproxy-intercept-heading"
                  title="Packet intercept"
                  hint="nftables TPROXY + ip rule (live). Does not flush the host ruleset."
                >
                  <SettingToggle
                    label="Intercept DNS"
                    hint="Install/remove powersvx_tproxy nft table and fwmark routing"
                    pressed={!!tpDraft.tproxy_intercept}
                    disabled={tpBusy || !isAdmin}
                    dirty={!!tpDraft.tproxy_intercept !== !!tproxy.tproxy_intercept}
                    onToggle={() => {
                      setOk('')
                      setErr('')
                      setTpDraft((d) => ({ ...d, tproxy_intercept: !d.tproxy_intercept }))
                    }}
                  />

                  <div className="grid gap-3 sm:grid-cols-2 mt-4">
                    <label className="block text-xs space-y-1">
                      <span className="text-[var(--muted)]">Interface</span>
                      <select
                        className="input w-full"
                        disabled={tpBusy || !isAdmin}
                        value={tpDraft.tproxy_iface || ''}
                        onChange={(e) => {
                          setOk('')
                          setErr('')
                          setTpDraft((d) => ({ ...d, tproxy_iface: e.target.value }))
                        }}
                      >
                        <option value="">Auto ({tproxy.tproxy_iface || 'detect'})</option>
                        {(tproxy.ifaces || []).map((i) => (
                          <option key={i.name} value={i.name}>
                            {i.name}
                            {i.up ? '' : ' (down)'}
                            {i.addrs?.length ? ` · ${i.addrs[0]}` : ''}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label className="block text-xs space-y-1">
                      <span className="text-[var(--muted)]">Mode</span>
                      <select
                        className="input w-full"
                        disabled={tpBusy || !isAdmin}
                        value={tpDraft.tproxy_mode || 'public'}
                        onChange={(e) => {
                          setOk('')
                          setErr('')
                          setTpDraft((d) => ({ ...d, tproxy_mode: e.target.value }))
                        }}
                      >
                        <option value="public">public — known resolvers only</option>
                        <option value="custom">custom — your resolver list</option>
                        <option value="all">all — every DNS on iface (danger)</option>
                      </select>
                    </label>
                  </div>

                  {tpDraft.tproxy_mode === 'custom' || tpDraft.tproxy_mode === 'public' ? (
                    <label className="block text-xs space-y-1 mt-3">
                      <span className="text-[var(--muted)]">
                        Resolver IPs {tpDraft.tproxy_mode === 'public' ? '(optional override)' : '(required)'}
                      </span>
                      <textarea
                        className="input mono w-full min-h-[96px]"
                        disabled={tpBusy || !isAdmin}
                        placeholder={(tproxy.default_resolvers || []).join('\n')}
                        value={tpDraft.tproxy_resolvers}
                        onChange={(e) => {
                          setOk('')
                          setErr('')
                          setTpDraft((d) => ({ ...d, tproxy_resolvers: e.target.value }))
                        }}
                      />
                    </label>
                  ) : null}

                  <div className="flex flex-wrap gap-2 mt-4">
                    <button
                      type="button"
                      disabled={tpBusy || !isAdmin}
                      onClick={applyTProxyNow}
                      className="btn btn-primary min-h-[40px] disabled:opacity-40"
                    >
                      Apply intercept
                    </button>
                    <button
                      type="button"
                      disabled={tpBusy || !isAdmin}
                      onClick={disableTProxyNow}
                      className="btn btn-secondary min-h-[40px] disabled:opacity-40"
                    >
                      Disable intercept
                    </button>
                  </div>
                </SettingSection>

                <SettingSection id="settings-tproxy-status-heading" title="Live counters" hint="From nftables table inet powersvx_tproxy.">
                  <dl className="settings-status-dl">
                    {[
                      ['Applied', tproxy.status?.applied ? 'yes' : 'no'],
                      ['Route (fwmark→100)', tproxy.status?.route_ok ? 'yes' : 'no'],
                      ['Iface', tproxy.status?.iface || '—'],
                      ['Mode', tproxy.status?.mode || '—'],
                      ['UDP packets', tproxy.status?.udp_packets ?? 0],
                      ['TCP packets', tproxy.status?.tcp_packets ?? 0],
                      ['UDP bytes', tproxy.status?.udp_bytes ?? 0],
                      ['TCP bytes', tproxy.status?.tcp_bytes ?? 0],
                      ['Last error', tproxy.status?.last_error || '—'],
                    ].map(([k, v]) => (
                      <div key={k} className="settings-status-row">
                        <dt>{k}</dt>
                        <dd className="mono">{String(v)}</dd>
                      </div>
                    ))}
                  </dl>
                  <p className="text-[11px] text-[var(--muted)] mt-3 leading-relaxed">
                    {tproxy.note}
                  </p>
                </SettingSection>
              </>
            )
          ) : null}

          {section === 'conntrack' ? (
            !conntrack || !ctDraft ? (
              <SettingCallout tone="warn">Conntrack status unavailable.</SettingCallout>
            ) : (
              <>
                {!conntrack.supported ? (
                  <SettingCallout tone="warn">Kernel conntrack tuning requires Linux.</SettingCallout>
                ) : null}
                {conntrack.status && !conntrack.status.available ? (
                  <SettingCallout tone="warn">
                    {conntrack.status.warning || 'nf_conntrack not loaded on this host.'}
                  </SettingCallout>
                ) : null}
                {conntrack.status?.warning && conntrack.status?.available ? (
                  <SettingCallout tone="warn">{conntrack.status.warning}</SettingCallout>
                ) : null}

                <SettingSection
                  id="settings-ct-live-heading"
                  title="Live status"
                  hint="Kernel nf_conntrack table — fills under high DNS/TPROXY churn."
                >
                  <dl className="settings-status-dl">
                    {[
                      ['Count', conntrack.status?.count ?? '—'],
                      ['Max', conntrack.status?.max ?? '—'],
                      ['Usage', conntrack.status?.usage_pct != null ? `${Number(conntrack.status.usage_pct).toFixed(1)}%` : '—'],
                      ['Hashsize', conntrack.status?.hashsize ?? '—'],
                      ['Writable', conntrack.status?.writable ? 'yes' : 'no'],
                      ['Hash writable', conntrack.status?.hash_writable ? 'yes' : 'no'],
                      ['Last error', conntrack.status?.last_error || '—'],
                    ].map(([k, v]) => (
                      <div key={k} className="settings-status-row">
                        <dt>{k}</dt>
                        <dd className="mono">{String(v)}</dd>
                      </div>
                    ))}
                  </dl>
                  <div className="mt-3">
                    <button
                      type="button"
                      disabled={ctBusy}
                      onClick={refreshConntrack}
                      className="btn btn-secondary min-h-[40px] disabled:opacity-40"
                    >
                      Refresh
                    </button>
                  </div>
                </SettingSection>

                <SettingSection
                  id="settings-ct-tune-heading"
                  title="Tuning"
                  hint="Apply live (sysctl). Optional persist to /etc/sysctl.d + modprobe.d when the host FS is writable; also re-applied on PowerSVX startup."
                >
                  <SettingToggle
                    label="Manage from PowerSVX"
                    hint="When on, Save applies limits and re-applies them after restart"
                    pressed={!!ctDraft.conntrack_managed}
                    disabled={ctBusy || !isAdmin}
                    dirty={!!ctDraft.conntrack_managed !== !!conntrack.conntrack_managed}
                    onToggle={() => {
                      setOk('')
                      setErr('')
                      setCtDraft((d) => ({ ...d, conntrack_managed: !d.conntrack_managed }))
                    }}
                  />
                  <SettingToggle
                    label="Persist drop-in files"
                    hint="Write /etc/sysctl.d/99-powersvx-conntrack.conf and modprobe.d (may only affect the container FS unless host paths are mounted)"
                    pressed={!!ctDraft.conntrack_persist}
                    disabled={ctBusy || !isAdmin}
                    dirty={!!ctDraft.conntrack_persist !== (conntrack.conntrack_persist !== false)}
                    onToggle={() => {
                      setOk('')
                      setErr('')
                      setCtDraft((d) => ({ ...d, conntrack_persist: !d.conntrack_persist }))
                    }}
                  />

                  <div className="flex flex-wrap gap-2 mt-4">
                    {(conntrack.presets || []).map((p) => (
                      <button
                        key={p.label}
                        type="button"
                        disabled={ctBusy || !isAdmin}
                        className="btn btn-secondary min-h-[36px] text-xs disabled:opacity-40"
                        onClick={() => {
                          setOk('')
                          setErr('')
                          const max = Number(p.max) || 0
                          setCtDraft((d) => ({
                            ...d,
                            conntrack_managed: true,
                            conntrack_max: max,
                            conntrack_hashsize: Math.max(16384, Math.floor(max / 4)),
                          }))
                        }}
                      >
                        {p.label}
                      </button>
                    ))}
                  </div>

                  <div className="grid gap-3 sm:grid-cols-2 mt-4">
                    <label className="block text-xs space-y-1">
                      <span className="text-[var(--muted)]">nf_conntrack_max</span>
                      <input
                        type="number"
                        min={conntrack.min_max || 65536}
                        max={conntrack.max_max || 16777216}
                        step={65536}
                        className="input mono w-full"
                        disabled={ctBusy || !isAdmin}
                        value={ctDraft.conntrack_max}
                        onChange={(e) => {
                          setOk('')
                          setErr('')
                          setCtDraft((d) => ({ ...d, conntrack_max: e.target.value }))
                        }}
                      />
                    </label>
                    <label className="block text-xs space-y-1">
                      <span className="text-[var(--muted)]">hashsize (0 = auto max/4)</span>
                      <input
                        type="number"
                        min={0}
                        step={4096}
                        className="input mono w-full"
                        disabled={ctBusy || !isAdmin}
                        value={ctDraft.conntrack_hashsize}
                        onChange={(e) => {
                          setOk('')
                          setErr('')
                          setCtDraft((d) => ({ ...d, conntrack_hashsize: e.target.value }))
                        }}
                      />
                    </label>
                  </div>

                  <div className="flex flex-wrap gap-2 mt-4">
                    <button
                      type="button"
                      disabled={ctBusy || !isAdmin}
                      onClick={applyConntrackNow}
                      className="btn btn-primary min-h-[40px] disabled:opacity-40"
                    >
                      Apply now
                    </button>
                  </div>
                  <p className="text-[11px] text-[var(--muted)] mt-3 leading-relaxed">{conntrack.note}</p>
                </SettingSection>
              </>
            )
          ) : null}

          {section === 'status' ? (
            <SettingSection id="settings-status-heading" title="Server status" hint="Read-only. Change these in the config file if needed.">
              <dl className="settings-status-dl">
                {[
                  ['DNSSEC mode', saved.dnssec_mode],
                  ['DNS listen', saved.udp_addr],
                  ['API auth', saved.auth_type],
                  ['Auth required', saved.auth_required ? 'yes' : 'no'],
                  ['Auth configured', saved.auth_configured ? 'yes' : 'no'],
                  ['TLS min', saved.tls_min_version],
                  ['Mask query IPs', saved.query_log_mask_ip ? 'yes' : 'no'],
                  ['Log retention (days)', saved.query_log_retention_days],
                  ['Log max size (MB)', saved.query_log_max_size_mb],
                  ['Log sample rate', saved.query_log_sample_rate],
                  ['AXFR allowed', saved.transfer?.allow_axfr ? 'yes' : 'no'],
                  ['AXFR requires TSIG', saved.transfer?.require_tsig ? 'yes' : 'no'],
                  ['NOTIFY targets', (saved.transfer?.notify || []).join(', ') || '—'],
                  ['AXFR allow from', (saved.transfer?.allow_from || []).join(', ') || '—'],
                  ['AXFR sync', saved.axfr_sync_enabled ?? saved.kominfo_sync_enabled ? 'on' : 'off'],
                ].map(([k, v]) => (
                  <div key={k} className="settings-status-row">
                    <dt>{k}</dt>
                    <dd className="mono">{String(v)}</dd>
                  </div>
                ))}
              </dl>
            </SettingSection>
          ) : null}

          {section === 'tools' ? (
            <div className="space-y-4 w-full" aria-label="Tools">
              <nav className="tool-tabs settings-tool-tabs" aria-label="Tool menus">
                {toolTabs.map((t) => (
                  <button
                    key={t.id}
                    type="button"
                    onClick={() => setTool(t.id)}
                    className={`tool-tab ${tool === t.id ? 'is-active' : ''}`}
                    aria-current={tool === t.id ? 'page' : undefined}
                  >
                    {t.label}
                  </button>
                ))}
              </nav>
              {tool === 'axfr' && ToolAxfr ? <ToolAxfr isAdmin={isAdmin} /> : null}
              {tool === 'acme' && ToolAcme ? <ToolAcme /> : null}
              {tool === 'backup' && ToolBackup ? <ToolBackup /> : null}
              {tool === 'users' && ToolUsers ? <ToolUsers /> : null}
              {tool === 'rpz' && ToolRpz ? <ToolRpz initial={rpz} onChange={setRpz} /> : null}
            </div>
          ) : null}
        </div>
      </div>

      {((dirty && isAdmin) ||
        (tpDirty && isAdmin && section === 'tproxy') ||
        (ctDirty && isAdmin && section === 'conntrack')) ? (
        <div className="settings-sticky-bar panel">
          <span className="text-sm text-[var(--warn)]">
            {section === 'tproxy' && tpDirty
              ? 'Unsaved TPROXY changes'
              : section === 'conntrack' && ctDirty
                ? 'Unsaved OS / conntrack changes'
                : `Unsaved · ${dirtyCount} section${dirtyCount === 1 ? '' : 's'}`}
          </span>
          {section === 'tproxy' ? (
            <div className="flex gap-2">
              <button
                type="button"
                disabled={!tpDirty || tpBusy}
                onClick={() => {
                  if (tproxy) setTpDraft(toTpDraft(tproxy))
                  setOk('')
                  setErr('')
                }}
                className="btn btn-secondary min-h-[44px] disabled:opacity-40"
              >
                Discard
              </button>
              <button
                type="button"
                disabled={!tpDirty || tpBusy}
                onClick={() => saveTProxy()}
                className="btn btn-primary min-h-[44px] disabled:opacity-40"
              >
                {tpBusy ? 'Saving…' : 'Save & apply'}
              </button>
            </div>
          ) : section === 'conntrack' ? (
            <div className="flex gap-2">
              <button
                type="button"
                disabled={!ctDirty || ctBusy}
                onClick={() => {
                  if (conntrack) setCtDraft(toCtDraft(conntrack))
                  setOk('')
                  setErr('')
                }}
                className="btn btn-secondary min-h-[44px] disabled:opacity-40"
              >
                Discard
              </button>
              <button
                type="button"
                disabled={!ctDirty || ctBusy}
                onClick={saveConntrack}
                className="btn btn-primary min-h-[44px] disabled:opacity-40"
              >
                {ctBusy ? 'Saving…' : 'Save & apply'}
              </button>
            </div>
          ) : (
            saveBar
          )}
        </div>
      ) : null}
    </div>
  )
}
