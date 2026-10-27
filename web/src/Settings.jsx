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
    resolver_mode: s.resolver_mode === 'recursive' ? 'recursive' : 'forward',
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
      typeof api.tproxy === 'function' ? api.tproxy().catch(() => null) : Promise.resolve(null),
      typeof api.conntrack === 'function' ? api.conntrack().catch(() => null) : Promise.resolve(null),
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

  const allowEmpty = linesToList(draft.allow_query).length === 0
  const needsForwarders =
    draft.resolver_mode === 'forward' || (draft.resolver_mode === 'recursive' && draft.forward_on_fail)
  const noForwarders = (draft.forwarders || []).length === 0
  const isUnboundBackend =
    draft.resolver_mode === 'forward' &&
    (draft.forwarders || []).length === 1 &&
    ['127.0.0.1:5353', '127.0.0.1', '[::1]:5353', '::1'].includes(String(draft.forwarders[0] || '').trim())

  const railGroups = [
    {
      group: 'Routing & Traffic',
      items: [
        {
          id: 'dns',
          label: 'DNS & Resolvers',
          hint: 'Lookup path & upstreams',
          Icon: Stack,
          dirty: dirtyFlags.dns,
          pill: isUnboundBackend ? '127.0.0.1:5353' : draft.resolver_mode === 'forward' ? 'Forward' : 'Recursive',
        },
        {
          id: 'access',
          label: 'Access Control',
          hint: 'Ingress ACL & CIDRs',
          Icon: LockSimple,
          dirty: dirtyFlags.access,
          pill: allowEmpty ? '0.0.0.0/0' : `${linesToList(draft.allow_query).length} CIDRs`,
        },
        {
          id: 'rate-limit',
          label: 'Rate Limiting',
          hint: 'Per-IP DDoS caps',
          Icon: Gauge,
          dirty: dirtyFlags['rate-limit'],
          pill: draft.rate_limit ? `${draft.rate_limit_qps} QPS` : 'off',
        },
      ],
    },
    {
      group: 'Core Engines',
      items: [
        {
          id: 'engines',
          label: 'Engines & GeoDNS',
          hint: 'RPZ, ECS & split-view',
          Icon: GearSix,
          dirty: dirtyFlags.engines,
          pill: draft.rpz_enabled ? 'RPZ On' : 'Core',
        },
        {
          id: 'logging',
          label: 'Query Logging',
          hint: 'Retention & sampling',
          Icon: ClipboardText,
          dirty: dirtyFlags.logging,
          pill: draft.query_log_enabled ? `${draft.query_log_retention_days}d` : 'off',
        },
      ],
    },
    {
      group: 'System & Dataplane',
      items: [
        {
          id: 'tproxy',
          label: 'TPROXY Intercept',
          hint: 'Transparent DNS routing',
          Icon: Network,
          dirty: !!tpDirty,
          pill: tproxy?.status?.applied ? 'active' : 'idle',
        },
        {
          id: 'conntrack',
          label: 'Kernel Conntrack',
          hint: 'Netfilter table tuning',
          Icon: Cpu,
          dirty: !!ctDirty,
          pill: conntrack?.status?.count ? `${Math.round(conntrack.status.usage_pct || 0)}%` : 'Linux',
        },
        {
          id: 'status',
          label: 'Dataplane Status',
          hint: 'Engine & socket stats',
          Icon: ChartLine,
          dirty: false,
          pill: saved?.version || 'v1.6.3',
        },
        {
          id: 'tools',
          label: 'System Tools',
          hint: 'AXFR, ACME & Backup',
          Icon: HardDrives,
          dirty: false,
          pill: 'Tools',
        },
      ],
    },
  ]

  const categories = railGroups.flatMap((g) => g.items)

  const toolTabs = [
    { id: 'axfr', label: 'AXFR' },
    { id: 'acme', label: 'ACME' },
    { id: 'backup', label: 'Backup' },
    { id: 'users', label: 'Users' },
    { id: 'rpz', label: 'RPZ' },
  ]

  const sectionMeta = categories.find((c) => c.id === section)
  const toolMeta = toolTabs.find((t) => t.id === tool)

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
        eyebrow="System & Routing"
        title="Routing & Dataplane Architecture"
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
          {railGroups.map((g) => (
            <div key={g.group} className="flex flex-col gap-1 w-full">
              <div className="settings-rail-group">{g.group}</div>
              {g.items.map((c) => {
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
                    {c.pill ? <span className="settings-rail-pill">{c.pill}</span> : null}
                  </button>
                )
              })}
            </div>
          ))}
        </nav>

        <div key={section} className="settings-main reveal space-y-4">
          {section === 'dns' ? (
            <>
              {/* Route 53 & Cloudflare Dataplane Flow Pipeline */}
              <div className="routing-flow-wrap">
                <div className="routing-flow-step">
                  <span className="routing-flow-title">1. Client Ingress</span>
                  <span className="routing-flow-val">0.0.0.0:53</span>
                  <span className="routing-flow-sub">UDP · TCP · DoH Sockets</span>
                </div>
                <span className="routing-flow-arrow">➔</span>
                <div className="routing-flow-step">
                  <span className="routing-flow-title">2. Edge Filter</span>
                  <span className="routing-flow-val">{draft.rate_limit ? `${draft.rate_limit_qps} QPS` : 'Open Ingress'}</span>
                  <span className="routing-flow-sub">{allowEmpty ? 'ACL 0.0.0.0/0' : `${linesToList(draft.allow_query).length} Allowed CIDRs`}</span>
                </div>
                <span className="routing-flow-arrow">➔</span>
                <div className="routing-flow-step is-active">
                  <span className="routing-flow-title">3. RPZ Policy</span>
                  <span className="routing-flow-val">{draft.rpz_enabled ? 'CDB 9.95M' : 'Disabled'}</span>
                  <span className="routing-flow-sub">{draft.rpz_enabled ? 'Kominfo Fast Spoof' : 'Pass-through'}</span>
                </div>
                <span className="routing-flow-arrow">➔</span>
                <div className="routing-flow-step">
                  <span className="routing-flow-title">4. Resolver Target</span>
                  <span className="routing-flow-val">{isUnboundBackend ? 'Unbound :5353' : draft.resolver_mode}</span>
                  <span className="routing-flow-sub">{isUnboundBackend ? 'Local Root Recurse' : `${(draft.forwarders || []).length} Upstreams`}</span>
                </div>
              </div>

              {needsForwarders && noForwarders ? (
                <SettingCallout tone="warn">
                  No forwarders configured — add at least one for forward mode, Unbound backend, or recursive fallback.
                </SettingCallout>
              ) : null}
              {isUnboundBackend ? (
                <SettingCallout tone="muted">
                  Unbound backend active: cache misses go to <span className="mono font-semibold">127.0.0.1:5353</span>. Conditional forward
                  zones still win for matching domains (evaluated first).
                </SettingCallout>
              ) : null}

              <SettingSection
                id="settings-dns-heading"
                title="Lookup Mode & Engine Strategy"
                hint="Pick how PowerSVX resolves cache misses. Conditional forward zones always override this for matching domains."
              >
                <div className="settings-mode-grid">
                  {[
                    ['unbound', 'Unbound backend', 'Default ISP — misses → local Unbound on 127.0.0.1:5353 with DNSSEC', '< 1ms local'],
                    ['forward', 'Forward Proxy', 'Send all misses to the forwarders list (Cloudflare, Google, or any upstream)', '~15-30ms'],
                    ['recursive', 'Recursive (Go Native)', 'Lab only — ask the DNS root nameservers directly from PowerSVX', '~80-150ms'],
                  ].map(([mode, title, desc, lat]) => {
                    const selected =
                      mode === 'unbound' ? isUnboundBackend : draft.resolver_mode === mode && !isUnboundBackend
                    return (
                      <button
                        key={mode}
                        type="button"
                        disabled={busy || !isAdmin}
                        onClick={() => {
                          setOk('')
                          setErr('')
                          if (mode === 'unbound') {
                            setDraft((d) => ({
                              ...d,
                              resolver_mode: 'forward',
                              forward_on_fail: false,
                              forwarders: ['127.0.0.1:5353'],
                            }))
                            return
                          }
                          setDraft((d) => ({ ...d, resolver_mode: mode }))
                        }}
                        className={`settings-mode-card ${selected ? 'is-selected' : ''}`}
                        aria-pressed={selected}
                      >
                        <div className="text-sm font-medium flex items-center justify-between gap-2">
                          <span className="flex items-center gap-1.5">
                            {selected ? <span className="text-[var(--accent)] font-bold">●</span> : null}
                            {title}
                          </span>
                          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--bg-elevated)] text-[var(--muted)]">{lat}</span>
                        </div>
                        <div className="text-xs text-[var(--muted)] mt-1.5 leading-relaxed">{desc}</div>
                        {selected ? (
                          <div className="mt-2 pt-2 border-t border-[var(--border)] text-[10px] uppercase font-semibold tracking-wider text-[var(--accent)]">
                            Active Routing Profile
                          </div>
                        ) : null}
                      </button>
                    )
                  })}
                </div>
                <SettingToggle
                  label="Fallback to forwarders"
                  hint={
                    draft.resolver_mode !== 'recursive'
                      ? 'Only available in recursive (Go) mode'
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
                title="Upstream Resolvers (Route 53 Outbound Endpoints)"
                hint={
                  isUnboundBackend
                    ? 'Unbound backend uses 127.0.0.1:5353. Keep this loopback — do not point at public resolvers unless you intend to.'
                    : 'Upstream for forward mode and recursive fallback. UDP 1.1.1.1:53, DoT tls://…, or DoH https://…'
                }
              >
                {/* Route 53 Quick Presets */}
                <div className="flex flex-wrap items-center gap-2 mb-3">
                  <span className="text-xs text-[var(--muted)] font-medium">Quick Presets:</span>
                  <button
                    type="button"
                    disabled={busy || !isAdmin}
                    className="preset-chip-btn"
                    onClick={() => {
                      setDraft((d) => ({
                        ...d,
                        forwarders: ['127.0.0.1:5353'],
                      }))
                      setOk('Preset applied: Local Unbound (127.0.0.1:5353)')
                    }}
                  >
                    + Local Unbound (127.0.0.1:5353)
                  </button>
                  <button
                    type="button"
                    disabled={busy || !isAdmin}
                    className="preset-chip-btn"
                    onClick={() => {
                      if (!draft.forwarders?.includes('1.1.1.1:53')) {
                        setDraft((d) => ({
                          ...d,
                          forwarders: [...(d.forwarders || []), '1.1.1.1:53', '1.0.0.1:53'],
                        }))
                        setOk('Preset added: Cloudflare 1.1.1.1')
                      }
                    }}
                  >
                    + Cloudflare (1.1.1.1 / 1.0.0.1)
                  </button>
                  <button
                    type="button"
                    disabled={busy || !isAdmin}
                    className="preset-chip-btn"
                    onClick={() => {
                      if (!draft.forwarders?.includes('8.8.8.8:53')) {
                        setDraft((d) => ({
                          ...d,
                          forwarders: [...(d.forwarders || []), '8.8.8.8:53', '8.8.4.4:53'],
                        }))
                        setOk('Preset added: Google DNS 8.8.8.8')
                      }
                    }}
                  >
                    + Google DNS (8.8.8.8)
                  </button>
                  <button
                    type="button"
                    disabled={busy || !isAdmin}
                    className="preset-chip-btn"
                    onClick={() => {
                      if (!draft.forwarders?.includes('9.9.9.9:53')) {
                        setDraft((d) => ({
                          ...d,
                          forwarders: [...(d.forwarders || []), '9.9.9.9:53'],
                        }))
                        setOk('Preset added: Quad9 (9.9.9.9)')
                      }
                    }}
                  >
                    + Quad9 (9.9.9.9)
                  </button>
                </div>

                {(draft.forwarders || []).length === 0 ? (
                  <p className="text-xs text-[var(--warn)]">No forwarders configured yet.</p>
                ) : (
                  <div className="cf-table-wrap mb-3">
                    <table className="cf-table">
                      <thead>
                        <tr>
                          <th>Resolver Address</th>
                          <th>Target Type</th>
                          <th>Protocol</th>
                          <th>Status</th>
                          <th className="text-right">Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(draft.forwarders || []).map((addr, idx) => {
                          const isLoopback = addr.includes('127.0.0.1') || addr.includes('::1')
                          return (
                            <tr key={`${addr}-${idx}`}>
                              <td>
                                <span className="mono font-semibold text-sm">{addr}</span>
                              </td>
                              <td>
                                <span className={`text-xs px-2 py-0.5 rounded font-mono ${isLoopback ? 'bg-[var(--accent-soft)] text-[var(--accent)] font-medium' : 'bg-[var(--bg-elevated)] text-[var(--muted)]'}`}>
                                  {isLoopback ? 'Core Loopback (Unbound)' : 'External Upstream'}
                                </span>
                              </td>
                              <td className="text-xs font-mono text-[var(--muted)]">
                                {addr.startsWith('tls://') ? 'DoT (TCP 853)' : addr.startsWith('https://') ? 'DoH (TCP 443)' : 'DNS (UDP/TCP 53)'}
                              </td>
                              <td>
                                <span className="inline-flex items-center gap-1.5 text-xs text-[var(--ok)] font-medium">
                                  <span className="w-1.5 h-1.5 rounded-full bg-[var(--ok)]" />
                                  Active Target
                                </span>
                              </td>
                              <td className="text-right space-x-1">
                                <button type="button" disabled={busy || !isAdmin} onClick={() => editForwarder(idx)} className="btn btn-secondary text-xs min-h-[32px] px-2.5 disabled:opacity-50">
                                  Edit
                                </button>
                                <button type="button" disabled={busy || !isAdmin} onClick={() => removeForwarder(idx)} className="btn btn-secondary text-xs min-h-[32px] px-2.5 text-[var(--danger)] disabled:opacity-50">
                                  Delete
                                </button>
                              </td>
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
                <form
                  className="settings-inline-form"
                  onSubmit={(e) => {
                    e.preventDefault()
                    addOrUpdateForwarder()
                  }}
                >
                  <label className="flex-1 min-w-[12rem] text-xs text-[var(--muted)] space-y-1">
                    {fwdEditIdx >= 0 ? 'Edit forwarder' : 'Add custom forwarder address'}
                    <input
                      value={fwdInput}
                      disabled={busy || !isAdmin}
                      onChange={(e) => setFwdInput(e.target.value)}
                      placeholder="1.1.1.1:53, tls://dns.example, or https://…"
                      className="input mono w-full min-h-[44px]"
                    />
                  </label>
                  <button type="submit" disabled={busy || !isAdmin || !fwdInput.trim()} className="btn btn-primary min-h-[44px] disabled:opacity-50">
                    {fwdEditIdx >= 0 ? 'Update' : 'Add Forwarder'}
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
                title="Conditional Forward Zones (Route 53 Resolver Rules)"
                hint="Longest-suffix match rules evaluated before general recursor. Forwards internal corporate or AD domains to private servers."
              >
                {(draft.forward_zones || []).length === 0 ? (
                  <p className="text-xs text-[var(--muted)]">No conditional forward zones configured. Queries follow default resolution strategy.</p>
                ) : (
                  <div className="cf-table-wrap mb-3">
                    <table className="cf-table">
                      <thead>
                        <tr>
                          <th>Zone Domain</th>
                          <th>Forwarder Endpoints</th>
                          <th>Rule Match</th>
                          <th className="text-right">Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(draft.forward_zones || []).map((z, idx) => (
                          <tr key={`${z.zone}-${idx}`}>
                            <td>
                              <span className="mono font-semibold text-sm text-[var(--accent)]">{z.zone}</span>
                            </td>
                            <td>
                              <span className="mono text-xs text-[var(--muted)]">{(z.forwarders || []).join(', ')}</span>
                            </td>
                            <td>
                              <span className="text-xs px-2 py-0.5 rounded bg-[var(--bg-elevated)] font-mono text-[var(--text)]">
                                Longest-Suffix
                              </span>
                            </td>
                            <td className="text-right space-x-1">
                              <button type="button" disabled={busy || !isAdmin} onClick={() => editForwardZone(idx)} className="btn btn-secondary text-xs min-h-[32px] px-2.5 disabled:opacity-50">
                                Edit
                              </button>
                              <button type="button" disabled={busy || !isAdmin} onClick={() => removeForwardZone(idx)} className="btn btn-secondary text-xs min-h-[32px] px-2.5 text-[var(--danger)] disabled:opacity-50">
                                Delete
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
                <form
                  className="settings-inline-form"
                  onSubmit={(e) => {
                    e.preventDefault()
                    addOrUpdateForwardZone()
                  }}
                >
                  <label className="min-w-[10rem] flex-1 text-xs text-[var(--muted)] space-y-1">
                    Zone Domain
                    <input value={fzZone} disabled={busy || !isAdmin} onChange={(e) => setFzZone(e.target.value)} placeholder="corp.local or internal.lan" className="input mono w-full min-h-[44px]" />
                  </label>
                  <label className="min-w-[14rem] flex-[2] text-xs text-[var(--muted)] space-y-1">
                    Forwarder Endpoints (comma or newline separated)
                    <input value={fzFwd} disabled={busy || !isAdmin} onChange={(e) => setFzFwd(e.target.value)} placeholder="10.0.0.1:53, 10.0.0.2:53" className="input mono w-full min-h-[44px]" />
                  </label>
                  <button type="submit" disabled={busy || !isAdmin || !fzZone.trim() || !fzFwd.trim()} className="btn btn-primary min-h-[44px] disabled:opacity-50">
                    {fzEditIdx >= 0 ? 'Update Rule' : 'Add Rule'}
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
                  Open resolver: Allow list is empty — any client on the network may query. Restrict to authorized client CIDRs in production.
                </SettingCallout>
              ) : null}
              <SettingSection
                id="settings-access-heading"
                title="Client Access Control List (Cloudflare IP Access)"
                hint="Specify which IP ranges are permitted to query this resolver. Deny list always takes precedence over Allow list."
              >
                <div className="flex flex-wrap items-center gap-2 mb-3">
                  <span className="text-xs text-[var(--muted)] font-medium">Quick Presets:</span>
                  <button
                    type="button"
                    disabled={busy || !isAdmin}
                    className="preset-chip-btn"
                    onClick={() => {
                      setDraft((d) => ({ ...d, allow_query: '' }))
                      setOk('Set Allow to open (empty = all allowed)')
                    }}
                  >
                    Open Resolver (0.0.0.0/0)
                  </button>
                  <button
                    type="button"
                    disabled={busy || !isAdmin}
                    className="preset-chip-btn"
                    onClick={() => {
                      setDraft((d) => ({ ...d, allow_query: '10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16' }))
                      setOk('Added RFC1918 private subnets')
                    }}
                  >
                    RFC1918 Private Subnets
                  </button>
                  <button
                    type="button"
                    disabled={busy || !isAdmin}
                    className="preset-chip-btn"
                    onClick={() => {
                      setDraft((d) => ({ ...d, allow_query: '127.0.0.1/32\n::1/128' }))
                      setOk('Added Loopback only')
                    }}
                  >
                    Localhost Loopback
                  </button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <label className="block text-xs text-[var(--muted)] space-y-1">
                    <span className="font-semibold text-[var(--ok)] flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-[var(--ok)]" />
                      Allow Query CIDRs (one per line)
                    </span>
                    <textarea
                      rows={6}
                      disabled={busy || !isAdmin}
                      value={draft.allow_query}
                      onChange={(e) => {
                        setOk('')
                        setErr('')
                        setDraft((d) => ({ ...d, allow_query: e.target.value }))
                      }}
                      placeholder={'# Leave empty to allow any client\n10.0.0.0/8\n192.168.0.0/16\n103.162.17.0/24'}
                      className="input mono w-full min-h-[9rem]"
                    />
                    <span className="text-[10px] text-[var(--muted)] block">Empty = open to all client IPs.</span>
                  </label>

                  <label className="block text-xs text-[var(--muted)] space-y-1">
                    <span className="font-semibold text-[var(--danger)] flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-[var(--danger)]" />
                      Deny Query CIDRs (drops unconditionally)
                    </span>
                    <textarea
                      rows={6}
                      disabled={busy || !isAdmin}
                      value={draft.deny_query}
                      onChange={(e) => {
                        setOk('')
                        setErr('')
                        setDraft((d) => ({ ...d, deny_query: e.target.value }))
                      }}
                      placeholder={'# Abusive or scanner CIDRs\n198.51.100.0/24\n203.0.113.5/32'}
                      className="input mono w-full min-h-[9rem]"
                    />
                    <span className="text-[10px] text-[var(--muted)] block">Deny entries always override Allow entries.</span>
                  </label>
                </div>
              </SettingSection>
            </>
          ) : null}

          {section === 'rate-limit' ? (
            <>
              {allowEmpty && !draft.rate_limit ? (
                <SettingCallout tone="muted">
                  ACL is open and rate limiting is disabled — we recommend enabling rate limiting to protect against DNS amplification and DoS.
                </SettingCallout>
              ) : null}
              <SettingSection id="settings-rl-heading" title="Rate Limiting (Cloudflare WAF Grammar)" hint="Limit query bursts per client IP. Whitelist bypasses rate limits.">
                <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs text-[var(--muted)] font-medium">Quick Profiles:</span>
                    <button
                      type="button"
                      disabled={busy || !isAdmin}
                      className="preset-chip-btn"
                      onClick={() => {
                        setDraft((d) => ({
                          ...d,
                          rate_limit: true,
                          rate_limit_qps: 10000,
                          rate_limit_burst: 2000,
                          rate_limit_block_duration: 300,
                        }))
                        setOk('Preset: ISP High-Throughput (10k QPS)')
                      }}
                    >
                      ISP High-Throughput (10,000 QPS)
                    </button>
                    <button
                      type="button"
                      disabled={busy || !isAdmin}
                      className="preset-chip-btn"
                      onClick={() => {
                        setDraft((d) => ({
                          ...d,
                          rate_limit: true,
                          rate_limit_qps: 2000,
                          rate_limit_burst: 400,
                          rate_limit_block_duration: 300,
                        }))
                        setOk('Preset: Enterprise Balanced (2,000 QPS)')
                      }}
                    >
                      Enterprise (2,000 QPS)
                    </button>
                    <button
                      type="button"
                      disabled={busy || !isAdmin}
                      className="preset-chip-btn"
                      onClick={() => {
                        setDraft((d) => ({
                          ...d,
                          rate_limit: true,
                          rate_limit_qps: 500,
                          rate_limit_burst: 100,
                          rate_limit_block_duration: 600,
                        }))
                        setOk('Preset: Strict Mitigation (500 QPS)')
                      }}
                    >
                      Strict (500 QPS)
                    </button>
                  </div>
                  <button type="button" disabled={busy || !isAdmin} onClick={clearRlBlocks} className="btn btn-secondary text-xs min-h-[32px] disabled:opacity-40">
                    Clear active IP blocks
                  </button>
                </div>

                <SettingToggle
                  label="Enable Rate Limiting"
                  hint="Refuse excess queries from an abusive client IP"
                  pressed={!!draft.rate_limit}
                  disabled={busy || !isAdmin}
                  dirty={!!draft.rate_limit !== !!saved.rate_limit}
                  onToggle={() => toggle('rate_limit')}
                />
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mt-4">
                  {[
                    ['rate_limit_qps', 'Query Rate Limit', 'queries / sec', 1],
                    ['rate_limit_burst', 'Allowed Burst', 'instant peak', 1],
                    ['rate_limit_block_duration', 'Block Duration', 'seconds', 1],
                  ].map(([key, label, unit, min]) => (
                    <div key={key} className="panel p-3 space-y-1">
                      <div className="flex items-center justify-between text-xs text-[var(--muted)]">
                        <span>{label}</span>
                        <span className="font-mono text-[10px] text-[var(--accent)]">{unit}</span>
                      </div>
                      <input
                        type="number"
                        min={min}
                        disabled={busy || !isAdmin}
                        className="input mono w-full text-base font-semibold"
                        value={draft[key]}
                        onChange={(e) => {
                          setOk('')
                          setErr('')
                          setDraft((d) => ({ ...d, [key]: e.target.value }))
                        }}
                      />
                    </div>
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
                  ['Version', saved.version || '—'],
                  ['Git', saved.git || '—'],
                  ['Build', saved.build_id || '—'],
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
