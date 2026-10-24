import { useState } from 'react'
import { PageHeader } from '../../ui'

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

export default function Analytics() {
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
            Grafana + Prometheus: dnsdist edge QPS, Unbound backend, and host CPU / MemAvailable / disk via
            node-exporter. Live ops:{' '}
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

      <div className="panel px-4 py-3 text-sm text-[var(--muted)] reveal">
        <strong className="text-[var(--text)]">Panels:</strong> dnsdist QPS / packet-cache / CDB spoof, Unbound recurse
        latency, host CPU · MemAvailable · disk %, control-plane RSS. Query-log UI is off in production — use these
        charts instead.
      </div>
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
