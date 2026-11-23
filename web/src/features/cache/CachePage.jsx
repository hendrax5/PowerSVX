import { useCallback, useEffect, useState } from 'react'
import { ArrowsClockwise, Database, MagnifyingGlass, Trash } from '@phosphor-icons/react'
import { api } from '../../api'
import { useAuth } from '../../auth'
import { useI18n } from '../../i18n'
import { EmptyState, ErrorBox, LoadingBlock, PageHeader, Stat } from '../../ui'

function fmtRatio(hits, total) {
  if (!total || total <= 0) return '—'
  return `${((hits / total) * 100).toFixed(1)}%`
}

function fmtBytes(n) {
  const b = Number(n) || 0
  if (b <= 0) return '0 B'
  if (b < 1024) return `${b} B`
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KiB`
  return `${(b / (1024 * 1024)).toFixed(1)} MiB`
}

export default function CachePage() {
  const { canWrite } = useAuth()
  const { lang } = useI18n()
  const isID = lang === 'id'

  const [stats, setStats] = useState(null)
  const [inspectQ, setInspectQ] = useState('')
  const [entries, setEntries] = useState([])
  const [inspectErr, setInspectErr] = useState('')
  const [err, setErr] = useState('')
  const [ok, setOk] = useState('')
  const [busy, setBusy] = useState(false)

  const [flushDomain, setFlushDomain] = useState('')
  const [flushType, setFlushType] = useState('A')
  const [flushScope, setFlushScope] = useState('domain')

  const loadStats = useCallback(async () => {
    try {
      const s = await api.cacheStats()
      setStats(s)
    } catch (ex) {
      setErr(ex.message)
    }
  }, [])

  const runInspect = useCallback(async (q) => {
    try {
      const res = await api.cacheInspect(q ?? '', 120)
      setEntries(res?.entries || [])
      setInspectErr(res?.error || '')
    } catch (ex) {
      setInspectErr(ex.message)
    }
  }, [])

  useEffect(() => {
    loadStats()
    runInspect('')
  }, [loadStats, runInspect])

  const handleFlush = async (scope, domain = '', type = '') => {
    if (scope === 'all' && !window.confirm(isID ? 'Hapus seluruh cache di dnsdist dan Unbound?' : 'Flush all caches across dnsdist and Unbound?')) {
      return
    }
    setBusy(true)
    setErr('')
    setOk('')
    try {
      const res = await api.cacheFlush({ scope, domain, type })
      setOk(
        `Flushed (${scope}): ` +
          Object.entries(res?.results || {})
            .map(([k, v]) => `${k}=${v}`)
            .join(' · '),
      )
      await loadStats()
      await runInspect(inspectQ)
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  if (!stats && !err) {
    return <LoadingBlock label="Loading cache metrics" />
  }

  const dd = stats?.dnsdist || {}
  const ub = stats?.unbound || {}
  const ddTot = (Number(dd.cache_hits) || 0) + (Number(dd.cache_misses) || 0)

  return (
    <div className="space-y-6 max-w-[1360px]">
      <PageHeader
        eyebrow="DATAPLANE CACHES"
        title={isID ? 'Cache Explorer & Selective Purge' : 'Cache Explorer & Selective Purge'}
        sub={
          isID
            ? 'Pantau dan bersihkan packet cache Edge (dnsdist) dan cache RRset Resolver (Unbound).'
            : 'Inspect and selectively purge the dnsdist packet cache and the Unbound RRset/message cache.'
        }
        actions={
          <button
            type="button"
            onClick={() => {
              loadStats()
              runInspect(inspectQ)
            }}
            className="btn btn-secondary text-xs"
          >
            <ArrowsClockwise size={14} />
            <span>{isID ? 'Muat Ulang' : 'Refresh'}</span>
          </button>
        }
      />

      {err ? <ErrorBox msg={err} /> : null}
      {ok ? (
        <div className="px-4 py-2.5 rounded-[var(--radius)] bg-[var(--ok)]/10 border border-[var(--ok)]/30 text-[var(--ok)] text-xs mono">
          {ok}
        </div>
      ) : null}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 reveal">
        <Stat
          label="dnsdist Edge Cache"
          value={dd.status === 'ok' ? Number(dd.entries || 0).toLocaleString() : 'N/A'}
          sub={
            dd.status === 'ok'
              ? `Hit ratio ${fmtRatio(Number(dd.cache_hits), ddTot)} · ${Number(dd.cache_hits || 0).toLocaleString()} hits`
              : dd.err || 'dnsdist metrics unavailable'
          }
        />
        <Stat
          label="Unbound RRset Cache"
          value={ub.status === 'ok' ? fmtBytes(ub.mem_rrset) : 'N/A'}
          sub={
            ub.status === 'ok'
              ? `Hit ratio ${fmtRatio(Number(ub.cache_hits), Number(ub.queries))} · Msg ${fmtBytes(ub.mem_msg)} · Bogus ${Number(ub.bogus || 0)}`
              : ub.err || 'Unbound control unavailable'
          }
        />
      </div>

      {canWrite && (
        <section className="panel p-5 space-y-4 reveal">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--border)] pb-3">
            <div>
              <h2 className="text-sm font-semibold">{isID ? 'Pembersihan Cache Selektif' : 'Selective Purge'}</h2>
              <p className="text-xs text-[var(--muted)] mt-0.5">
                {isID
                  ? 'Sinkron menghapus cache pada dnsdist dan Unbound sekaligus.'
                  : 'Purges matching entries across the dnsdist packet cache and Unbound together.'}
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                disabled={busy}
                onClick={() => handleFlush('negative')}
                className="btn btn-secondary text-xs"
              >
                {isID ? 'Hapus Negative Cache' : 'Flush Negative Cache'}
              </button>
              <button
                type="button"
                disabled={busy}
                onClick={() => handleFlush('all')}
                className="btn btn-secondary text-xs text-[var(--danger)] border-[var(--danger)]/40"
              >
                <Trash size={14} />
                <span>{isID ? 'Hapus Semua Cache (Flush All)' : 'Flush All Caches'}</span>
              </button>
            </div>
          </div>

          <form
            onSubmit={(e) => {
              e.preventDefault()
              handleFlush(flushScope, flushDomain.trim(), flushType)
            }}
            className="flex flex-wrap gap-2 items-end"
          >
            <label className="field">
              <span className="label-quiet">Scope</span>
              <select
                className="input text-xs"
                value={flushScope}
                onChange={(e) => setFlushScope(e.target.value)}
              >
                <option value="domain">Single Domain</option>
                <option value="zone">Entire Zone Subtree</option>
                <option value="type">Domain + RR Type</option>
              </select>
            </label>
            <label className="field flex-1 min-w-[14rem]">
              <span className="label-quiet">Domain / Zone FQDN</span>
              <input
                className="input mono text-xs"
                placeholder="api.example.com"
                value={flushDomain}
                onChange={(e) => setFlushDomain(e.target.value)}
                required
              />
            </label>
            {flushScope === 'type' && (
              <label className="field w-28">
                <span className="label-quiet">Type</span>
                <select
                  className="input mono text-xs"
                  value={flushType}
                  onChange={(e) => setFlushType(e.target.value)}
                >
                  {['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV', 'SOA', 'PTR', 'DS'].map((t) => (
                    <option key={t} value={t}>{t}</option>
                  ))}
                </select>
              </label>
            )}
            <button type="submit" disabled={busy || !flushDomain.trim()} className="btn btn-primary text-xs">
              {isID ? 'Purge Sekarang' : 'Purge Selected'}
            </button>
          </form>
        </section>
      )}

      <section className="panel p-5 space-y-4 reveal">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Database size={18} className="text-[var(--accent)]" />
            <h2 className="text-sm font-semibold">
              {isID ? 'Inspektor Cache Unbound' : 'Unbound Live Cache Inspector'} ({entries.length})
            </h2>
          </div>
          <form
            onSubmit={(e) => {
              e.preventDefault()
              runInspect(inspectQ)
            }}
            className="flex gap-2"
          >
            <div className="relative">
              <MagnifyingGlass size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-[var(--muted)]" />
              <input
                className="input pl-8 py-1.5 text-xs mono min-w-[220px]"
                placeholder="Filter cached domain / RR..."
                value={inspectQ}
                onChange={(e) => setInspectQ(e.target.value)}
              />
            </div>
            <button type="submit" className="btn btn-secondary text-xs">
              Filter
            </button>
          </form>
        </div>

        {inspectErr ? (
          <div className="text-xs text-[var(--muted)] mono p-3 rounded bg-[var(--bg-elevated)] border border-[var(--border)]">
            {inspectErr}
          </div>
        ) : entries.length > 0 ? (
          <div className="max-h-[420px] overflow-auto space-y-1.5 pr-1">
            {entries.map((line, i) => {
              const firstTok = String(line).split(/\s+/)[0]?.replace(/\.$/, '') || ''
              return (
                <div
                  key={`${i}-${firstTok}`}
                  className="flex items-center justify-between gap-3 px-3 py-1.5 rounded bg-[var(--bg-elevated)] border border-[var(--border)] text-xs mono"
                >
                  <span className="truncate text-[var(--text)]" title={line}>
                    {line}
                  </span>
                  {canWrite && firstTok && (
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => handleFlush('domain', firstTok)}
                      className="text-[11px] text-[var(--danger)] hover:underline shrink-0"
                    >
                      Evict
                    </button>
                  )}
                </div>
              )
            })}
          </div>
        ) : (
          <EmptyState
            title={isID ? 'Tidak ada entri cache cocok' : 'No matching Unbound cache entries'}
            hint={isID ? 'Cache kosong atau belum ada query rekursif untuk filter ini.' : 'Cache is empty or no recursive entries match the filter.'}
          />
        )}
      </section>
    </div>
  )
}
