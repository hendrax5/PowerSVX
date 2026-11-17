import { useState } from 'react'
import { api } from '../../api'
import { useI18n } from '../../i18n'
import { ErrorBox, PageHeader } from '../../ui'

const QUERY_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'PTR', 'SRV', 'SOA', 'CAA', 'DS', 'DNSKEY', 'HTTPS', 'SVCB', 'NAPTR', 'ANY']

export default function Lookup() {
  const { lang } = useI18n()
  const isID = lang === 'id'

  const [mode, setMode] = useState('lookup') // 'lookup' | 'trace'
  const [name, setName] = useState('example.com')
  const [type, setType] = useState('A')
  const [target, setTarget] = useState('local')
  const [customTarget, setCustomTarget] = useState('')
  const [protocol, setProtocol] = useState('udp')
  const [doFlag, setDoFlag] = useState(true)
  const [cdFlag, setCdFlag] = useState(false)
  const [rdFlag, setRdFlag] = useState(true)

  const [result, setResult] = useState(null)
  const [traceRes, setTraceRes] = useState(null)
  const [sectionTab, setSectionTab] = useState('answer')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  const run = async (e) => {
    e.preventDefault()
    setBusy(true)
    setErr('')
    try {
      if (mode === 'trace') {
        const res = await api.trace(name.trim(), type)
        setTraceRes(res)
        setResult(null)
      } else {
        const effectiveTarget = target === 'custom' ? customTarget.trim() : target
        const res = await api.lookup({
          name: name.trim(),
          type,
          target: effectiveTarget,
          protocol,
          do: doFlag,
          cd: cdFlag,
          rd: rdFlag,
        })
        setResult(res)
        setTraceRes(null)
        setSectionTab('answer')
      }
    } catch (ex) {
      setErr(ex.message)
      setResult(null)
      setTraceRes(null)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-6 max-w-4xl">
      <PageHeader
        eyebrow="DNS CLIENT TOOLS"
        title={isID ? 'Klien DNS & Trace Rekursif' : 'Technitium-Style DNS Client & Trace'}
        sub={
          isID
            ? 'Kirim query dig via UDP/TCP/DoT/DoH ke edge, Unbound, authoritative, atau lakukan trace langsung dari Root server.'
            : 'Query any endpoint over UDP/TCP/DoT/DoH with DNSSEC flags or run an iterative Root → Authoritative trace.'
        }
      />

      <div className="cf-tabs">
        <button
          type="button"
          className={`cf-tab-btn ${mode === 'lookup' ? 'is-active' : ''}`}
          onClick={() => setMode('lookup')}
        >
          Standard DNS Query (dig)
        </button>
        <button
          type="button"
          className={`cf-tab-btn ${mode === 'trace' ? 'is-active' : ''}`}
          onClick={() => setMode('trace')}
        >
          Iterative Trace (+trace)
        </button>
      </div>

      <form onSubmit={run} className="panel p-4 space-y-3 reveal">
        <div className="flex flex-wrap gap-2 items-center">
          <input
            className="input flex-1 min-w-[14rem] mono"
            placeholder="domain.example"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
          />
          <select className="input mono w-28" value={type} onChange={(e) => setType(e.target.value)}>
            {QUERY_TYPES.map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
          <button type="submit" disabled={busy} className="btn btn-primary disabled:opacity-50">
            {busy ? 'Querying…' : mode === 'trace' ? 'Trace Root' : 'Resolve'}
          </button>
        </div>

        {mode === 'lookup' && (
          <div className="flex flex-wrap gap-3 items-center pt-2 border-t border-[var(--border)] text-xs">
            <label className="flex items-center gap-1.5">
              <span className="text-[var(--muted)]">Server:</span>
              <select className="input py-1 text-xs mono" value={target} onChange={(e) => setTarget(e.target.value)}>
                <option value="local">Go Pipeline (Internal)</option>
                <option value="dnsdist">dnsdist Edge (127.0.0.1:53)</option>
                <option value="unbound">Unbound (127.0.0.1:5353)</option>
                <option value="auth">Authoritative (127.0.0.1:5354)</option>
                <option value="custom">Custom IP / DoT / DoH…</option>
              </select>
            </label>
            {target === 'custom' && (
              <input
                className="input py-1 text-xs mono min-w-[13rem]"
                placeholder="1.1.1.1 or https://dns.google/dns-query"
                value={customTarget}
                onChange={(e) => setCustomTarget(e.target.value)}
                required
              />
            )}
            <label className="flex items-center gap-1.5">
              <span className="text-[var(--muted)]">Proto:</span>
              <select className="input py-1 text-xs mono" value={protocol} onChange={(e) => setProtocol(e.target.value)}>
                <option value="udp">UDP</option>
                <option value="tcp">TCP</option>
                <option value="dot">DoT (:853)</option>
                <option value="doh">DoH (HTTPS)</option>
              </select>
            </label>
            <label className="inline-flex items-center gap-1 cursor-pointer">
              <input type="checkbox" checked={doFlag} onChange={(e) => setDoFlag(e.target.checked)} />
              <span className="mono">DO</span>
            </label>
            <label className="inline-flex items-center gap-1 cursor-pointer">
              <input type="checkbox" checked={cdFlag} onChange={(e) => setCdFlag(e.target.checked)} />
              <span className="mono">CD</span>
            </label>
            <label className="inline-flex items-center gap-1 cursor-pointer">
              <input type="checkbox" checked={rdFlag} onChange={(e) => setRdFlag(e.target.checked)} />
              <span className="mono">RD</span>
            </label>
          </div>
        )}
      </form>

      {err ? <ErrorBox msg={err} /> : null}

      {result ? (
        <div className="panel p-4 space-y-3 reveal">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--border)] pb-2.5 text-xs">
            <div className="flex flex-wrap items-center gap-2 mono">
              <span>RCODE <strong className="text-[var(--accent)]">{result.rcode}</strong></span>
              <span>· {Number(result.latency_ms || 0).toFixed(2)} ms</span>
              <span className="text-[var(--muted)]">· {result.target}</span>
            </div>
            <div className="flex flex-wrap gap-1.5 mono text-[10px]">
              {Object.entries(result.flags || {}).map(([k, v]) =>
                v ? (
                  <span key={k} className="px-1.5 py-0.5 rounded bg-[var(--accent-soft)] text-[var(--accent)] border border-[var(--accent)]/30 uppercase">
                    {k}
                  </span>
                ) : null,
              )}
            </div>
          </div>

          <div className="cf-tabs">
            {[
              ['answer', `Answer (${(result.answers || []).length})`],
              ['authority', `Authority (${(result.authority || []).length})`],
              ['additional', `Additional (${(result.additional || []).length})`],
            ].map(([id, label]) => (
              <button
                key={id}
                type="button"
                className={`cf-tab-btn ${sectionTab === id ? 'is-active' : ''}`}
                onClick={() => setSectionTab(id)}
              >
                {label}
              </button>
            ))}
          </div>

          <pre className="mono text-xs whitespace-pre-wrap text-[var(--text)] bg-[var(--bg-elevated)] p-3 rounded border border-[var(--border)] overflow-x-auto">
            {sectionTab === 'answer' && ((result.answers || []).join('\n') || '(no answer records)')}
            {sectionTab === 'authority' && ((result.authority || []).join('\n') || '(no authority records)')}
            {sectionTab === 'additional' && ((result.additional || []).join('\n') || '(no additional records)')}
          </pre>
        </div>
      ) : null}

      {traceRes ? (
        <div className="panel p-4 space-y-3 reveal">
          <div className="text-xs mono text-[var(--muted)] border-b border-[var(--border)] pb-2">
            Trace for <strong className="text-[var(--text)]">{traceRes.question}</strong> ({(traceRes.hops || []).length} hops)
          </div>
          <div className="space-y-2.5">
            {(traceRes.hops || []).map((h) => (
              <div key={`${h.depth}-${h.ip}`} className="p-3 rounded bg-[var(--bg-elevated)] border border-[var(--border)] text-xs space-y-1.5">
                <div className="flex flex-wrap items-center justify-between gap-2 mono">
                  <div>
                    <span className="text-[var(--accent)] font-semibold">Hop #{h.depth + 1}</span>
                    <span className="ml-2 font-semibold">{h.zone}</span>
                    <span className="ml-2 text-[var(--muted)]">via {h.server} ({h.ip})</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {h.authoritative && <span className="badge badge-success">AA</span>}
                    <span className="text-[var(--accent)]">{h.rcode || 'ERR'}</span>
                    <span className="text-[var(--muted)]">{Number(h.latency_ms || 0).toFixed(1)} ms</span>
                  </div>
                </div>
                {h.error && <div className="text-[var(--danger)] mono">{h.error}</div>}
                {h.referral_ns?.length > 0 && (
                  <div className="text-[11px] text-[var(--muted)] mono">
                    Referrals: {h.referral_ns.slice(0, 4).join(', ')}
                  </div>
                )}
                {h.answers?.length > 0 && (
                  <pre className="mono text-[11px] text-[var(--ok)] bg-black/20 p-2 rounded overflow-x-auto">
                    {h.answers.join('\n')}
                  </pre>
                )}
              </div>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  )
}
