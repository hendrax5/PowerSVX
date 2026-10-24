/* eslint-disable react-refresh/only-export-components */
function friendlyApiError(raw) {
  const m = String(raw || '').toLowerCase()
  if (m.includes('unauthorized') || m.includes('401')) {
    return { summary: 'Not authorized', next: 'Sign in again with your username and password.' }
  }
  if (m.includes('forbidden') || m.includes('403')) {
    return { summary: 'Permission denied', next: 'Your role cannot perform this action.' }
  }
  if (m.includes('failed to fetch') || m.includes('network')) {
    return { summary: 'Server unreachable', next: 'Confirm PowerSVX is running and reachable.' }
  }
  return { summary: raw, next: '' }
}

export function PageHeader({ eyebrow, title, sub, actions, className = '' }) {
  return (
    <header className={`page-head reveal ${className}`.trim()}>
      <div>
        {eyebrow ? <p className="eyebrow">{eyebrow}</p> : null}
        <h1 className="page-title">{title}</h1>
        {sub ? <p className="page-sub">{sub}</p> : null}
      </div>
      {actions ? <div className="page-head-actions">{actions}</div> : null}
    </header>
  )
}

export function LoadingBlock({ label = 'Loading' }) {
  return (
    <div className="space-y-3" role="status" aria-busy="true" aria-label={label}>
      <div className="h-8 w-48 rounded-[var(--radius)] bg-[var(--bg-panel)] animate-pulse" />
      <div className="h-32 rounded-[var(--radius-lg)] bg-[var(--bg-panel)] animate-pulse" />
      <div className="h-24 rounded-[var(--radius-lg)] bg-[var(--bg-panel)] animate-pulse reveal-delay-1" />
    </div>
  )
}

export function ErrorBox({ msg, detail, hint }) {
  const mapped = friendlyApiError(msg)
  return (
    <div
      className="rounded-[var(--radius)] border border-[var(--danger)]/35 bg-[var(--danger)]/10 text-[var(--danger)] text-sm px-3 py-2.5 space-y-1"
      role="alert"
      title={detail || undefined}
    >
      <p>{mapped.summary || msg}</p>
      {mapped.next || hint ? <p className="text-xs opacity-90">{mapped.next || hint}</p> : null}
      {detail && detail !== msg && detail !== mapped.summary ? (
        <p className="text-[11px] text-[var(--muted)] mono break-all">{detail}</p>
      ) : null}
    </div>
  )
}

export const ICON_WEIGHT = 'regular'

export const chartTip = {
  background: 'var(--bg-elevated)',
  border: '1px solid var(--border)',
  borderRadius: 6,
  color: 'var(--text)',
  fontSize: 12,
}

export function releaseLabel(h) {
  const v = h?.version || ''
  const g = String(h?.git || '').replace(/^unknown$/i, '')
  if (v && g) return `v${v} · ${g}`
  if (v) return `v${v}`
  return ''
}

export function formatUptime(sec) {
  const s = Number(sec) || 0
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  return `${h}h ${m}m`
}

export function EmptyState({ title, hint, action }) {
  return (
    <div className="px-1 py-8 text-left" role="status">
      <p className="text-base font-semibold tracking-tight">{title}</p>
      {hint ? <p className="text-sm text-[var(--muted)] mt-2 max-w-[52ch] leading-relaxed">{hint}</p> : null}
      {action ? <div className="mt-5">{action}</div> : null}
    </div>
  )
}

export function Stat({ label, value, sub }) {
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

export function Metric({ label, value, sub }) {
  return (
    <div className="metric-cell">
      <div className="metric-label">{label}</div>
      <div className="metric-value">{value}</div>
      {sub ? <div className="metric-sub">{sub}</div> : null}
    </div>
  )
}

export function Badge({ on, label }) {
  return (
    <span className={`badge-chip ${on ? 'on' : 'off'}`}>
      <span className="badge-dot" aria-hidden />
      {label}
    </span>
  )
}
