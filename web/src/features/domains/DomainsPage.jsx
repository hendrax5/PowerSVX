import { useEffect, useState } from 'react'
import { api } from '../../api'
import { useAuth } from '../../auth'
import { EmptyState, ErrorBox, PageHeader } from '../../ui'

export default function DomainsPage() {
  const { canWrite } = useAuth()
  const [q, setQ] = useState('')
  const [result, setResult] = useState(null)
  const [whitelist, setWhitelist] = useState([])
  const [blacklist, setBlacklist] = useState([])
  const [wlDraft, setWlDraft] = useState('')
  const [blDraft, setBlDraft] = useState('')
  const [err, setErr] = useState('')
  const [ok, setOk] = useState('')
  const [busy, setBusy] = useState(false)

  const loadLists = () => {
    api
      .whitelist()
      .then((r) => setWhitelist(r.domains || []))
      .catch((e) => setErr(e.message))
    api
      .blacklist()
      .then((r) => setBlacklist(r.domains || []))
      .catch((e) => setErr(e.message))
  }

  useEffect(() => {
    loadLists()
  }, [])

  const search = async (e) => {
    e?.preventDefault?.()
    setErr('')
    setOk('')
    setResult(null)
    const name = q.trim()
    if (!name) {
      setErr('Enter a domain to search')
      return
    }
    setBusy(true)
    try {
      setResult(await api.domainLookup(name))
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  const refreshLookup = async () => {
    if (q.trim()) setResult(await api.domainLookup(q.trim()))
  }

  const addWhitelist = async (e) => {
    e?.preventDefault?.()
    setErr('')
    setOk('')
    const name = wlDraft.trim() || q.trim()
    if (!name) {
      setErr('Domain required')
      return
    }
    setBusy(true)
    try {
      const r = await api.addWhitelist(name)
      setWhitelist(r.domains || [])
      setWlDraft('')
      setOk(`Whitelisted ${r.domain}`)
      await refreshLookup()
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  const removeWhitelist = async (name) => {
    setErr('')
    setOk('')
    setBusy(true)
    try {
      const r = await api.removeWhitelist(name)
      setWhitelist(r.domains || [])
      setOk(`Removed ${name} from whitelist`)
      await refreshLookup()
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  const addBlacklist = async (e) => {
    e?.preventDefault?.()
    setErr('')
    setOk('')
    const name = blDraft.trim() || q.trim()
    if (!name) {
      setErr('Domain required')
      return
    }
    setBusy(true)
    try {
      const r = await api.addBlacklist(name)
      setBlacklist(r.domains || [])
      setBlDraft('')
      setOk(`Blacklisted ${r.domain}`)
      await refreshLookup()
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  const removeBlacklist = async (name) => {
    setErr('')
    setOk('')
    setBusy(true)
    try {
      const r = await api.removeBlacklist(name)
      setBlacklist(r.domains || [])
      setOk(`Removed ${name} from blacklist`)
      await refreshLookup()
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  const statusLabel = (r) => {
    if (!r) return ''
    if (r.whitelisted) return 'whitelisted (allowed)'
    if (r.blacklisted) return 'manual blacklist (nxdomain)'
    if (r.blocked) return `blocked (${r.action || 'nxdomain'}${r.block_source ? ` · ${r.block_source}` : ''})`
    if (r.in_rpz) return `in RPZ (${r.action})`
    return 'not blocked'
  }

  return (
    <div className="space-y-6 max-w-4xl">
      <PageHeader
        eyebrow="Operate"
        title="Domains"
        sub="Lookup RPZ status and manage manual whitelist / blacklist. Whitelist always wins."
      />

      {err ? <ErrorBox msg={err} /> : null}
      {ok ? <div className="flash-ok" role="status">{ok}</div> : null}

      <section className="panel p-4 space-y-3">
        <h2 className="text-sm font-medium">Domain lookup</h2>
        <form onSubmit={search} className="flex flex-wrap gap-2">
          <input
            className="input flex-1 min-w-[12rem] mono"
            placeholder="ads.example.com"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
          <button type="submit" disabled={busy} className="btn btn-primary">
            Search
          </button>
          {canWrite ? (
            <>
              <button
                type="button"
                disabled={busy || !q.trim()}
                onClick={addWhitelist}
                className="btn btn-secondary"
              >
                Add to whitelist
              </button>
              <button
                type="button"
                disabled={busy || !q.trim()}
                onClick={addBlacklist}
                className="btn btn-secondary"
              >
                Add to blacklist
              </button>
            </>
          ) : null}
        </form>
        {result ? (
          <div className="border border-[var(--border)] px-3 py-3 text-sm space-y-1">
            <div className="mono font-medium">{result.name}</div>
            <div>
              Status:{' '}
              <span className={result.blocked ? 'text-[var(--warn)]' : 'text-[var(--ok)]'}>
                {statusLabel(result)}
              </span>
            </div>
            {result.target ? <div className="text-xs text-[var(--muted)]">Target: {result.target}</div> : null}
          </div>
        ) : null}
      </section>

      <section className="panel p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-sm font-medium">Manual blacklist ({blacklist.length})</h2>
          <span className="text-xs text-[var(--muted)]">NXDOMAIN · parent / *.wild match</span>
        </div>
        {canWrite ? (
          <form onSubmit={addBlacklist} className="flex flex-wrap gap-2">
            <input
              className="input flex-1 min-w-[12rem] mono"
              placeholder="evil.example or *.cdn.bad"
              value={blDraft}
              onChange={(e) => setBlDraft(e.target.value)}
            />
            <button type="submit" disabled={busy} className="btn btn-primary">
              Add
            </button>
          </form>
        ) : null}
        {blacklist.length ? (
          <ul className="space-y-1 text-sm mono max-h-96 overflow-auto">
            {blacklist.map((d) => (
              <li
                key={d}
                className="flex justify-between gap-3 border-b border-[var(--border)]/50 py-1.5 items-center"
              >
                <span className="truncate">{d}</span>
                {canWrite ? (
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => removeBlacklist(d)}
                    className="text-xs text-[var(--warn)] cursor-pointer disabled:opacity-40"
                  >
                    Remove
                  </button>
                ) : null}
              </li>
            ))}
          </ul>
        ) : (
          <EmptyState title="Blacklist empty" hint="Add domains to block immediately (independent of RPZ feeds)." />
        )}
      </section>

      <section className="panel p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-sm font-medium">Whitelist ({whitelist.length})</h2>
          <a href="/settings" className="text-xs text-[var(--accent)] underline">
            RPZ feeds
          </a>
        </div>
        {canWrite ? (
          <form onSubmit={addWhitelist} className="flex flex-wrap gap-2">
            <input
              className="input flex-1 min-w-[12rem] mono"
              placeholder="example.com or *.cdn.example"
              value={wlDraft}
              onChange={(e) => setWlDraft(e.target.value)}
            />
            <button type="submit" disabled={busy} className="btn btn-primary">
              Add
            </button>
          </form>
        ) : null}
        {whitelist.length ? (
          <ul className="space-y-1 text-sm mono max-h-96 overflow-auto">
            {whitelist.map((d) => (
              <li
                key={d}
                className="flex justify-between gap-3 border-b border-[var(--border)]/50 py-1.5 items-center"
              >
                <span className="truncate">{d}</span>
                {canWrite ? (
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => removeWhitelist(d)}
                    className="text-xs text-[var(--warn)] cursor-pointer disabled:opacity-40"
                  >
                    Remove
                  </button>
                ) : null}
              </li>
            ))}
          </ul>
        ) : (
          <EmptyState title="Whitelist empty" hint="Add domains that should never be blocked by RPZ or manual blacklist." />
        )}
      </section>
    </div>
  )
}
