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
