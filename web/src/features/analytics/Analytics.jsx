import { useState, useEffect, useCallback } from 'react'
import { PageHeader } from '../../ui'

function getInitialGrafanaURL() {
  const { protocol, hostname } = window.location
  const defaultURL = `${protocol}//${hostname}:3000`
  try {
    const stored = localStorage.getItem('powersvx_grafana_url')
    if (stored) {
      const clean = stored.replace(/\/$/, '')
      // Auto-correct: if stored URL was saved as localhost/127.0.0.1 but user is now on remote host,
      // switch to the current hostname so the browser doesn't try to query client's local PC.
      if (
        (clean.includes('127.0.0.1') || clean.includes('localhost')) &&
        hostname !== '127.0.0.1' &&
        hostname !== 'localhost'
      ) {
        return defaultURL
      }
      return clean
    }
  } catch {
    /* ignore */
  }
  return defaultURL
}

function buildGrafanaURL(base, { kiosk = true } = {}) {
  const root = (base || getInitialGrafanaURL()).replace(/\/$/, '')
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
  const [base, setBase] = useState(() => getInitialGrafanaURL())
  const [draft, setDraft] = useState(() => getInitialGrafanaURL())
  const [status, setStatus] = useState('checking') // 'checking' | 'online' | 'offline'
  const [forceShow, setForceShow] = useState(false)

  const src = buildGrafanaURL(base, { kiosk: true })
  const openURL = buildGrafanaURL(base, { kiosk: false })

  const checkConnectivity = useCallback(async (targetBase) => {
    setStatus('checking')
    try {
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), 3500)
      // no-cors fetch will resolve (opaque) if port 3000 responds, and reject if connection refused
      await fetch(`${targetBase}/api/health`, { mode: 'no-cors', signal: controller.signal })
      clearTimeout(timer)
      setStatus('online')
    } catch {
      setStatus('offline')
    }
  }, [])

  useEffect(() => {
    checkConnectivity(base)
  }, [base, checkConnectivity])

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
    setForceShow(false)
  }

  const resetToCurrentHost = () => {
    const { protocol, hostname } = window.location
    const defaultURL = `${protocol}//${hostname}:3000`
    setDraft(defaultURL)
    try {
      localStorage.setItem('powersvx_grafana_url', defaultURL)
    } catch {
      /* ignore */
    }
    setBase(defaultURL)
    setForceShow(false)
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
        <button type="button" onClick={resetToCurrentHost} className="btn btn-ghost text-xs">
          Reset to Current Host
        </button>
        <div className="flex items-center gap-2 self-center ml-auto text-xs mono">
          <span className="text-[var(--muted)]">Status:</span>
          {status === 'checking' && <span className="badge badge-warning">Checking...</span>}
          {status === 'online' && <span className="badge badge-success">Online (Port 3000)</span>}
          {status === 'offline' && <span className="badge badge-danger">Offline / Unreachable</span>}
        </div>
      </form>

      {status === 'offline' && !forceShow ? (
        <section className="panel p-6 reveal text-center flex flex-col items-center justify-center gap-4" style={{ minHeight: 480 }}>
          <div className="w-14 h-14 rounded-full bg-[var(--danger-bg,rgba(239,68,68,0.1))] text-[var(--danger,#ef4444)] flex items-center justify-center text-2xl">
            ⚠️
          </div>
          <div className="max-w-md space-y-1">
            <h3 className="text-base font-semibold text-[var(--text)]">Grafana Tidak Terdeteksi di Port 3000</h3>
            <p className="text-xs text-[var(--muted)]">
              Browser tidak dapat terhubung ke <code className="mono text-[var(--accent)]">{base}</code>.
              Jika server ini di-install dengan mode standalone binary, container Grafana belum terpasang.
            </p>
          </div>

          <div className="bg-black/20 dark:bg-black/40 border border-[var(--border)] rounded-lg p-3 text-left w-full max-w-xl text-xs space-y-2">
            <div className="font-semibold text-[var(--text)]">Solusi untuk mengaktifkan Grafana:</div>
            <p className="text-[var(--muted)]">1. Jalankan turnkey bootstrap di server untuk full stack (dnsdist + unbound + grafana + prometheus):</p>
            <pre className="p-2 bg-black/40 rounded mono text-[var(--accent)] select-all overflow-x-auto">
sudo bash deploy/linux/bootstrap-node.sh
            </pre>
            <p className="text-[var(--muted)]">2. Atau jika Docker sudah ada, nyalakan Grafana dan Prometheus:</p>
            <pre className="p-2 bg-black/40 rounded mono text-[var(--muted)] select-all overflow-x-auto">
docker compose up -d grafana prometheus
            </pre>
          </div>

          <div className="flex gap-2">
            <button type="button" onClick={() => checkConnectivity(base)} className="btn btn-secondary text-xs">
              Cek Ulang Koneksi
            </button>
            <button type="button" onClick={() => setForceShow(true)} className="btn btn-ghost text-xs">
              Tetap Tampilkan Frame
            </button>
          </div>
        </section>
      ) : (
        <section className="panel overflow-hidden reveal reveal-delay-1" style={{ minHeight: '70vh' }}>
          <iframe
            title="PowerSVX Grafana"
            src={src}
            className="w-full border-0 bg-[var(--bg)]"
            style={{ height: '70vh', minHeight: 520 }}
            referrerPolicy="no-referrer"
          />
        </section>
      )}

      <p className="text-xs text-[var(--muted)]">
        If the frame shows a login wall, sign in once in Grafana (Open in Grafana) or set anonymous viewer.
        Embedding needs <span className="mono">GF_SECURITY_ALLOW_EMBEDDING=true</span>.
      </p>
    </div>
  )
}

