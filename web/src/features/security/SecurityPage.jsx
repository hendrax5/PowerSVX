import { useCallback, useEffect, useState } from 'react'
import { ArrowsClockwise, LockSimple, Plus, ShieldWarning, Trash } from '@phosphor-icons/react'
import { api } from '../../api'
import { useAuth } from '../../auth'
import { useI18n } from '../../i18n'
import { EmptyState, ErrorBox, LoadingBlock, PageHeader, Stat } from '../../ui'

export default function SecurityPage() {
  const { canWrite } = useAuth()
  const { lang } = useI18n()
  const isID = lang === 'id'

  const [data, setData] = useState(null)
  const [err, setErr] = useState('')
  const [ok, setOk] = useState('')
  const [busy, setBusy] = useState(false)

  const [banPrefix, setBanPrefix] = useState('')
  const [banReason, setBanReason] = useState('')
  const [banTTL, setBanTTL] = useState(0)

  const load = useCallback(async () => {
    try {
      const res = await api.securityBlocks()
      setData(res)
    } catch (ex) {
      setErr(ex.message)
    }
  }, [])

  useEffect(() => {
    load()
    const t = setInterval(load, 8000)
    return () => clearInterval(t)
  }, [load])

  const handleBan = async (e) => {
    e.preventDefault()
    if (!banPrefix.trim()) return
    setBusy(true)
    setErr('')
    setOk('')
    try {
      await api.securityBan({
        prefix: banPrefix.trim(),
        reason: banReason.trim() || 'manual block',
        ttl_sec: Number(banTTL) || 0,
      })
      setOk(`Banned ${banPrefix.trim()} across edge dataplane`)
      setBanPrefix('')
      setBanReason('')
      await load()
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  const handleUnban = async (prefix) => {
    setBusy(true)
    setErr('')
    setOk('')
    try {
      await api.securityUnban(prefix)
      setOk(`Unbanned ${prefix}`)
      await load()
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  const handleClearDyn = async () => {
    setBusy(true)
    setErr('')
    setOk('')
    try {
      const res = await api.securityClearDynBlocks()
      setOk(res?.ok ? 'Cleared dnsdist dynamic blocks' : res?.dnsdist_error || 'Clear failed')
      await load()
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  if (!data && !err) {
    return <LoadingBlock label="Loading security & IP blocks" />
  }

  const manualBans = data?.manual_bans || []
  const dynBlocks = data?.dnsdist_dynblocks || []
  const counters = data?.dnsdist_counters
  const fmt = (n) => Number(n || 0).toLocaleString()
  const rlCfg = data?.ratelimit_config || {}

  return (
    <div className="space-y-6 max-w-[1360px]">
      <PageHeader
        eyebrow={isID ? 'KEAMANAN & RRL' : 'SECURITY & RRL'}
        title={isID ? 'Perlindungan DDoS, AutoBan & Blokir IP' : 'RRL, Dynamic Abuse & IP Ban Console'}
        sub={
          isID
            ? 'Kelola daftar pemblokiran dinamis dnsdist, Rate-Limit IP, dan pemblokiran CIDR permanen pada edge.'
            : 'Manage dnsdist dynamic abuse blocks, per-IP rate limits, and persistent edge bans.'
        }
        actions={
          <div className="flex gap-2">
            {canWrite && (
              <button type="button" disabled={busy} onClick={handleClearDyn} className="btn btn-secondary text-xs">
                {isID ? 'Bersihkan Dynamic Blocks' : 'Clear Dynamic Blocks'}
              </button>
            )}
            <button type="button" onClick={load} className="btn btn-secondary text-xs">
              <ArrowsClockwise size={14} />
              <span>{isID ? 'Refresh' : 'Refresh'}</span>
            </button>
          </div>
        }
      />

      {err ? <ErrorBox msg={err} /> : null}
      {ok ? (
        <div className="px-4 py-2.5 rounded-[var(--radius)] bg-[var(--ok)]/10 border border-[var(--ok)]/30 text-[var(--ok)] text-xs">
          {ok}
        </div>
      ) : null}

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 reveal">
        <Stat
          label="dnsdist Dynamic Blocks"
          value={dynBlocks.length}
          sub={data?.dnsdist_error ? 'dnsdist API offline' : 'Active DDoS / NXDOMAIN / ANY drops'}
        />
        <Stat
          label="Manual Persistent Bans"
          value={manualBans.length}
          sub={isID ? 'Ditulis ke daftar yang dibaca dnsdist' : 'Written to the ban list dnsdist loads'}
        />
        <Stat
          label={isID ? 'Query dibuang dnsdist' : 'Queries dropped by dnsdist'}
          value={counters ? fmt(counters.dyn_blocked) : 'N/A'}
          sub={
            counters
              ? `Dynamic blocks · rule drops ${fmt(counters.rule_drop)} · refused ${fmt(counters.rule_refused)}`
              : 'dnsdist statistics unavailable'
          }
        />
        <Stat
          label="Edge RRL Policy"
          value={rlCfg.enabled ? `${rlCfg.qps || 0} QPS` : 'OFF'}
          sub={`Burst ${rlCfg.burst || 0} · Block ${rlCfg.block_duration || 0}s · Whitelist ${(rlCfg.whitelist || []).length}`}
        />
      </div>

      {canWrite && (
        <section className="panel p-5 space-y-3 reveal">
          <div className="flex items-center justify-between border-b border-[var(--border)] pb-2.5">
            <h2 className="text-sm font-semibold flex items-center gap-2">
              <LockSimple size={16} className="text-[var(--danger)]" />
              {isID ? 'Tambah Blokir IP / CIDR Manual' : 'Add Manual IP / CIDR Ban'}
            </h2>
            <a href="/settings#rate-limit" className="text-xs text-[var(--accent)] hover:underline">
              {isID ? 'Konfigurasi Threshold RRL →' : 'Configure RRL Thresholds →'}
            </a>
          </div>
          <form onSubmit={handleBan} className="flex flex-wrap gap-2 items-end">
            <label className="field flex-1 min-w-[12rem]">
              <span className="label-quiet">IP or CIDR</span>
              <input
                className="input mono text-xs"
                placeholder="203.0.113.45 or 198.51.100.0/24"
                value={banPrefix}
                onChange={(e) => setBanPrefix(e.target.value)}
                required
              />
            </label>
            <label className="field flex-1 min-w-[12rem]">
              <span className="label-quiet">Reason</span>
              <input
                className="input text-xs"
                placeholder="DNS amplification abuser"
                value={banReason}
                onChange={(e) => setBanReason(e.target.value)}
              />
            </label>
            <label className="field w-36">
              <span className="label-quiet">TTL (0 = perm)</span>
              <select
                className="input mono text-xs"
                value={banTTL}
                onChange={(e) => setBanTTL(Number(e.target.value))}
              >
                <option value={0}>Permanent</option>
                <option value={300}>5 minutes</option>
                <option value={3600}>1 hour</option>
                <option value={86400}>24 hours</option>
              </select>
            </label>
            <button type="submit" disabled={busy || !banPrefix.trim()} className="btn btn-primary text-xs">
              <Plus size={14} weight="bold" />
              <span>{isID ? 'Blokir IP' : 'Ban Prefix'}</span>
            </button>
          </form>
        </section>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <section className="panel p-4 space-y-3 reveal">
          <h3 className="text-sm font-semibold flex items-center gap-2 border-b border-[var(--border)] pb-2">
            <ShieldWarning size={16} className="text-[var(--warn)]" />
            dnsdist Dynamic Blocks ({dynBlocks.length})
          </h3>
          {dynBlocks.length > 0 ? (
            <div className="cf-table-wrap">
              <table className="cf-table text-xs">
                <thead>
                  <tr>
                    <th>Prefix</th>
                    <th>Reason</th>
                    <th>TTL</th>
                    <th>Dropped</th>
                  </tr>
                </thead>
                <tbody>
                  {dynBlocks.map((b) => (
                    <tr key={b.prefix}>
                      <td className="mono font-medium">{b.prefix}</td>
                      <td className="text-[var(--muted)]">{b.reason}</td>
                      <td className="mono">{b.seconds}s</td>
                      <td className="mono text-[var(--danger)]">{Number(b.blocks || 0).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState title="No active dynamic blocks" hint="dnsdist automatic flood / NXDOMAIN / ANY abusers appear here live." />
          )}
        </section>

        <section className="panel p-4 space-y-3 reveal">
          <h3 className="text-sm font-semibold flex items-center gap-2 border-b border-[var(--border)] pb-2">
            <LockSimple size={16} className="text-[var(--danger)]" />
            Manual Persistent Bans ({manualBans.length})
          </h3>
          {manualBans.length > 0 ? (
            <div className="cf-table-wrap">
              <table className="cf-table text-xs">
                <thead>
                  <tr>
                    <th>Prefix</th>
                    <th>Reason</th>
                    <th>Expires</th>
                    <th className="text-right">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {manualBans.map((b) => (
                    <tr key={b.prefix}>
                      <td className="mono font-medium">{b.prefix}</td>
                      <td className="text-[var(--muted)]">{b.reason}</td>
                      <td className="mono text-[11px]">{b.expires_at ? new Date(b.expires_at).toLocaleString() : 'Never'}</td>
                      <td className="text-right">
                        {canWrite && (
                          <button
                            type="button"
                            disabled={busy}
                            onClick={() => handleUnban(b.prefix)}
                            className="text-[var(--danger)] hover:underline inline-flex items-center gap-1"
                          >
                            <Trash size={12} /> Unban
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState title="No manual bans" hint="Manually banned client IPs or CIDR prefixes appear here." />
          )}
        </section>
      </div>
    </div>
  )
}
