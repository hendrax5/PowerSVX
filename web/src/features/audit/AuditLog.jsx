import { useEffect, useState } from 'react'
import { api } from '../../api'
import { ErrorBox, PageHeader } from '../../ui'

export default function AuditLog() {
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
