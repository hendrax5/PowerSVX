import { useEffect, useMemo, useState } from 'react'
import {
  Check,
  CheckCircle,
  CloudArrowDown,
  CloudArrowUp,
  Copy,
  Globe,
  Key,
  MagnifyingGlass,
  PencilSimple,
  Plus,
  ShieldCheck,
  ShieldWarning,
  Trash,
  XCircle,
} from '@phosphor-icons/react'
import { api } from '../../api'
import { useAuth } from '../../auth'
import { EmptyState, ErrorBox, ICON_WEIGHT, PageHeader } from '../../ui'

const RECORD_TYPES = [
  'A',
  'AAAA',
  'CNAME',
  'MX',
  'TXT',
  'NS',
  'PTR',
  'SRV',
  'SOA',
  'CAA',
  'DS',
  'HTTPS',
  'SVCB',
  'TLSA',
  'SSHFP',
  'NAPTR',
]

function typeBadgeClass(t) {
  switch ((t || '').toUpperCase()) {
    case 'A':
      return 'cf-badge-a'
    case 'AAAA':
      return 'cf-badge-aaaa'
    case 'CNAME':
      return 'cf-badge-cname'
    case 'TXT':
      return 'cf-badge-txt'
    case 'MX':
      return 'cf-badge-mx'
    case 'NS':
      return 'cf-badge-ns'
    default:
      return 'cf-badge-soa'
  }
}

export default function DomainsPage() {
  const { canWrite } = useAuth()
  const [activeTab, setActiveTab] = useState('zones') // 'zones' | 'filtering'

  // Zones & Records State (Cloudflare & Route 53 & Technitium)
  const [zones, setZones] = useState([])
  const [secondaryZones, setSecondaryZones] = useState([])
  const [selectedZone, setSelectedZone] = useState('')
  const [zoneDetail, setZoneDetail] = useState(null)
  const [records, setRecords] = useState([])
  const [typeFilter, setTypeFilter] = useState('ALL')
  const [recordSearch, setRecordSearch] = useState('')
  const [dnssecStatus, setDnssecStatus] = useState(null)
  const [isAddingRecord, setIsAddingRecord] = useState(false)
  const [editingRec, setEditingRec] = useState(null)
  const [isCreatingZone, setIsCreatingZone] = useState(false)
  const [newZoneName, setNewZoneName] = useState('')
  const [copiedKey, setCopiedKey] = useState('')

  // BIND Import / Export & DNSSEC / SOA Panels
  const [showBindPanel, setShowBindPanel] = useState(false)
  const [exportContent, setExportContent] = useState('')
  const [importZoneName, setImportZoneName] = useState('')
  const [importContent, setImportContent] = useState('')
  const [showDnssecPanel, setShowDnssecPanel] = useState(false)
  const [dnssecAlgo, setDnssecAlgo] = useState('ECDSAP256SHA256')
  const [dnssecNsec3, setDnssecNsec3] = useState(false)
  const [soaRefresh, setSoaRefresh] = useState(3600)
  const [soaRetry, setSoaRetry] = useState(600)
  const [soaExpire, setSoaExpire] = useState(86400)
  const [soaMinimum, setSoaMinimum] = useState(3600)

  // Add/Edit Record Form State
  const [recType, setRecType] = useState('A')
  const [recName, setRecName] = useState('@')
  const [recContent, setRecContent] = useState('')
  const [recTTL, setRecTTL] = useState(300)
  const [recPrio, setRecPrio] = useState(10)
  const [recView, setRecView] = useState('')
  const [recGeoTag, setRecGeoTag] = useState('')

  // Filtering & Overrides State (AdGuard Home)
  const [lookupDomain, setLookupDomain] = useState('')
  const [lookupResult, setLookupResult] = useState(null)
  const [whitelist, setWhitelist] = useState([])
  const [blacklist, setBlacklist] = useState([])
  const [rpzEntries, setRpzEntries] = useState(null)
  const [wlSearch, setWlSearch] = useState('')
  const [blSearch, setBlSearch] = useState('')
  const [wlDraft, setWlDraft] = useState('')
  const [blDraft, setBlDraft] = useState('')

  // Shared status & messages
  const [err, setErr] = useState('')
  const [ok, setOk] = useState('')
  const [busy, setBusy] = useState(false)

  // Load Zones List
  const loadZones = async () => {
    try {
      const [r, secRes] = await Promise.all([
        api.zones(),
        api.secondary().catch(() => ({ zones: [] })),
      ])
      const list = r?.zones || []
      setZones(list)
      setSecondaryZones(secRes?.zones || [])
      if (list.length > 0 && !selectedZone) {
        setSelectedZone(list[0].name)
      }
    } catch {
      // database might not be configured or empty
    }
  }

  // Load Zone Details & Records
  const loadZoneDetail = async (zoneName) => {
    if (!zoneName) {
      setZoneDetail(null)
      setRecords([])
      return
    }
    setBusy(true)
    try {
      const z = await api.getZone(zoneName)
      setZoneDetail(z)
      setRecords(z?.records || [])
      if (z?.meta) {
        setSoaRefresh(Number(z.meta.soa_refresh) || 3600)
        setSoaRetry(Number(z.meta.soa_retry) || 600)
        setSoaExpire(Number(z.meta.soa_expire) || 86400)
        setSoaMinimum(Number(z.meta.soa_minimum) || 3600)
      }
      // Check DNSSEC
      api
        .zoneDNSSEC(zoneName)
        .then((sec) => {
          setDnssecStatus(sec)
          if (sec?.algorithm) setDnssecAlgo(sec.algorithm)
          if (typeof sec?.nsec3 === 'boolean') setDnssecNsec3(sec.nsec3)
        })
        .catch(() => setDnssecStatus(null))
    } catch (e) {
      setErr(`Failed loading zone ${zoneName}: ${e.message}`)
    } finally {
      setBusy(false)
    }
  }

  // Load Filter Lists
  const loadFilters = () => {
    api
      .whitelist()
      .then((r) => setWhitelist(r.domains || []))
      .catch((e) => setErr(e.message))
    api
      .blacklist()
      .then((r) => setBlacklist(r.domains || []))
      .catch((e) => setErr(e.message))
    api
      .status()
      .then((s) => setRpzEntries(Number(s?.rpz_entries ?? 0)))
      .catch(() => {})
  }

  useEffect(() => {
    loadZones()
    loadFilters()
  }, [])

  useEffect(() => {
    if (selectedZone) {
      loadZoneDetail(selectedZone)
      setExportContent('')
      setImportZoneName(selectedZone)
      setEditingRec(null)
    }
  }, [selectedZone])

  // Create Zone
  const handleCreateZone = async (e) => {
    e.preventDefault()
    const name = newZoneName.trim()
    if (!name) return
    setBusy(true)
    setErr('')
    setOk('')
    try {
      await api.createZone(name)
      setOk(`Hosted zone ${name} created successfully`)
      setNewZoneName('')
      setIsCreatingZone(false)
      await loadZones()
      setSelectedZone(name)
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  // Delete Zone
  const handleDeleteZone = async (name) => {
    if (!window.confirm(`Are you sure you want to delete zone ${name} and all its records?`)) return
    setBusy(true)
    setErr('')
    setOk('')
    try {
      await api.deleteZone(name)
      setOk(`Zone ${name} deleted`)
      setSelectedZone('')
      setZoneDetail(null)
      setRecords([])
      await loadZones()
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  const openAddRecord = () => {
    setEditingRec(null)
    setRecType('A')
    setRecName('@')
    setRecContent('')
    setRecTTL(300)
    setRecPrio(10)
    setRecView('')
    setRecGeoTag('')
    setIsAddingRecord(true)
  }

  const openEditRecord = (rec) => {
    setEditingRec(rec)
    setRecType((rec.type || 'A').toUpperCase())
    setRecName(rec.name || '@')
    setRecContent(rec.content || '')
    setRecTTL(Number(rec.ttl) || 300)
    setRecPrio(Number(rec.prio) || 10)
    setRecView(rec.view || '')
    setRecGeoTag(rec.geo_tag || '')
    setIsAddingRecord(true)
  }

  // Add or Update Record
  const handleSaveRecord = async (e) => {
    e.preventDefault()
    if (!selectedZone) return
    const content = recContent.trim()
    if (!content) {
      setErr('Record content/target IP is required')
      return
    }

    setBusy(true)
    setErr('')
    setOk('')

    // Normalize record name
    let fqdn = recName.trim()
    const cleanZone = selectedZone.replace(/\.$/, '')
    if (fqdn === '@' || fqdn === '') {
      fqdn = cleanZone
    } else if (!fqdn.endsWith('.' + cleanZone) && fqdn !== cleanZone) {
      fqdn = `${fqdn}.${cleanZone}`
    }

    const payload = {
      name: fqdn,
      type: recType,
      content,
      ttl: Number(recTTL) || 300,
      prio: recType === 'MX' || recType === 'SRV' ? Number(recPrio) || 10 : undefined,
      view: recView.trim() || undefined,
      geo_tag: recGeoTag.trim() || undefined,
    }

    try {
      if (editingRec) {
        await api.updateRecord(selectedZone, {
          old_name: editingRec.name,
          old_type: editingRec.type,
          ...payload,
        })
        setOk(`Updated ${recType} record for ${fqdn}`)
      } else {
        await api.addRecord(selectedZone, payload)
        setOk(`Added ${recType} record for ${fqdn}`)
      }
      setIsAddingRecord(false)
      setEditingRec(null)
      setRecContent('')
      await loadZoneDetail(selectedZone)
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  const handleExportZone = async () => {
    if (!selectedZone) return
    setBusy(true)
    setErr('')
    try {
      const r = await api.exportZone(selectedZone)
      setExportContent(r?.content || '')
      setShowBindPanel(true)
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  const handleDownloadZoneFile = () => {
    if (!exportContent || !selectedZone) return
    const blob = new Blob([exportContent], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${selectedZone.replace(/\.$/, '')}.zone`
    a.click()
    URL.revokeObjectURL(url)
  }

  const handleImportZone = async (e) => {
    e.preventDefault()
    const target = (importZoneName || selectedZone).trim()
    if (!target || !importContent.trim()) {
      setErr('Zone name and BIND master file content are required')
      return
    }
    setBusy(true)
    setErr('')
    setOk('')
    try {
      const res = await api.importZone(target, importContent)
      setOk(`Imported ${res?.imported ?? 0} record(s) into ${res?.zone || target}`)
      setImportContent('')
      await loadZones()
      setSelectedZone(res?.zone || target)
      await loadZoneDetail(res?.zone || target)
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  const handleEnableDNSSEC = async () => {
    if (!selectedZone) return
    setBusy(true)
    setErr('')
    setOk('')
    try {
      const res = await api.enableZoneDNSSEC(selectedZone, {
        algorithm: dnssecAlgo,
        nsec3: dnssecNsec3,
        action: 'enable',
      })
      setDnssecStatus(res)
      setOk(`DNSSEC enabled on ${selectedZone} (${res.algorithm}${res.nsec3 ? ' · NSEC3' : ''})`)
      await loadZoneDetail(selectedZone)
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  const handleRolloverZSK = async () => {
    if (!selectedZone) return
    if (!window.confirm(`Rollover ZSK key for ${selectedZone}?`)) return
    setBusy(true)
    setErr('')
    setOk('')
    try {
      const res = await api.enableZoneDNSSEC(selectedZone, { action: 'rollover' })
      setDnssecStatus(res)
      setOk(`ZSK rollover completed for ${selectedZone}`)
      await loadZoneDetail(selectedZone)
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  const handleSaveSOA = async (e) => {
    e.preventDefault()
    if (!selectedZone) return
    setBusy(true)
    setErr('')
    setOk('')
    try {
      await api.updateZoneMeta(selectedZone, {
        soa_refresh: Number(soaRefresh) || 3600,
        soa_retry: Number(soaRetry) || 600,
        soa_expire: Number(soaExpire) || 86400,
        soa_minimum: Number(soaMinimum) || 3600,
      })
      setOk(`Updated SOA timers for ${selectedZone}`)
      await loadZoneDetail(selectedZone)
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  // Delete Record
  const handleDeleteRecord = async (rec) => {
    if (!window.confirm(`Delete record ${rec.name} (${rec.type})?`)) return
    setBusy(true)
    setErr('')
    setOk('')
    try {
      await api.deleteRecord(selectedZone, rec.name, rec.type)
      setOk(`Record deleted`)
      await loadZoneDetail(selectedZone)
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  // Copy helper
  const handleCopy = (text, key) => {
    try {
      navigator.clipboard.writeText(text)
      setCopiedKey(key)
      setTimeout(() => setCopiedKey(''), 2000)
    } catch {
      /* ignore */
    }
  }

  // Filter records
  const filteredRecords = useMemo(() => {
    return records.filter((r) => {
      const matchType = typeFilter === 'ALL' || (r.type || '').toUpperCase() === typeFilter
      const q = recordSearch.toLowerCase().trim()
      const matchSearch =
        !q ||
        (r.name || '').toLowerCase().includes(q) ||
        (r.content || '').toLowerCase().includes(q) ||
        (r.type || '').toLowerCase().includes(q)
      return matchType && matchSearch
    })
  }, [records, typeFilter, recordSearch])

  // Filter evaluation search
  const handleDomainLookup = async (e) => {
    e?.preventDefault?.()
    const name = lookupDomain.trim()
    if (!name) return
    setBusy(true)
    setErr('')
    try {
      const res = await api.domainLookup(name)
      setLookupResult(res)
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  // Whitelist / Blacklist Handlers
  const handleAddWhitelist = async (name) => {
    const target = (name || wlDraft).trim()
    if (!target) return
    setBusy(true)
    setErr('')
    try {
      const r = await api.addWhitelist(target)
      setWhitelist(r.domains || [])
      setWlDraft('')
      setOk(`Added ${target} to whitelist`)
      if (lookupDomain.trim()) handleDomainLookup()
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  const handleRemoveWhitelist = async (name) => {
    setBusy(true)
    try {
      const r = await api.removeWhitelist(name)
      setWhitelist(r.domains || [])
      setOk(`Removed ${name} from whitelist`)
      if (lookupDomain.trim()) handleDomainLookup()
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  const handleAddBlacklist = async (name) => {
    const target = (name || blDraft).trim()
    if (!target) return
    setBusy(true)
    setErr('')
    try {
      const r = await api.addBlacklist(target)
      setBlacklist(r.domains || [])
      setBlDraft('')
      setOk(`Added ${target} to blacklist`)
      if (lookupDomain.trim()) handleDomainLookup()
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  const handleRemoveBlacklist = async (name) => {
    setBusy(true)
    try {
      const r = await api.removeBlacklist(name)
      setBlacklist(r.domains || [])
      setOk(`Removed ${name} from blacklist`)
      if (lookupDomain.trim()) handleDomainLookup()
    } catch (ex) {
      setErr(ex.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-6">
      {/* Cloudflare Header with Tab Switcher */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[var(--border)] pb-4">
        <div>
          <PageHeader
            eyebrow="DNS CONTROL PLANE"
            title="DNS & Protection Management"
            sub="Enterprise record routing (Cloudflare/Route53 grammar) and national RPZ filter policies (AdGuard Home grammar)."
            className="mb-0"
          />
        </div>

        {/* Cloudflare Style Tab Pills */}
        <div className="cf-tabs">
          <button
            type="button"
            className={`cf-tab-btn ${activeTab === 'zones' ? 'is-active' : ''}`}
            onClick={() => setActiveTab('zones')}
          >
            Authoritative DNS & Zones
          </button>
          <button
            type="button"
            className={`cf-tab-btn ${activeTab === 'filtering' ? 'is-active' : ''}`}
            onClick={() => setActiveTab('filtering')}
          >
            Protection & Filter Lists ({whitelist.length + blacklist.length})
          </button>
        </div>
      </div>

      {err ? <ErrorBox msg={err} /> : null}
      {ok ? (
        <div className="px-3.5 py-2.5 rounded-[var(--radius)] bg-[var(--ok)]/10 border border-[var(--ok)]/30 text-[var(--ok)] text-sm flex items-center justify-between">
          <span>{ok}</span>
          <button type="button" onClick={() => setOk('')} className="text-xs opacity-75 hover:opacity-100">
            Dismiss
          </button>
        </div>
      ) : null}

      {/* ========================================================================= */}
      {/* TAB 1: AUTHORITATIVE DNS & ZONES (CLOUDFLARE + ROUTE53 GRAMMAR) */}
      {/* ========================================================================= */}
      {activeTab === 'zones' && (
        <div className="space-y-6 reveal">
          {/* Hosted Zone Header Bar */}
          <section className="panel p-4 flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-3 flex-wrap">
              <div className="flex items-center gap-2">
                <Globe size={20} className="text-[var(--accent)]" weight={ICON_WEIGHT} />
                <span className="text-xs font-semibold uppercase text-[var(--muted)]">Hosted Zone:</span>
              </div>

              {zones.length > 0 ? (
                <select
                  value={selectedZone}
                  onChange={(e) => setSelectedZone(e.target.value)}
                  className="input py-1 px-3 text-sm font-semibold mono min-w-[200px]"
                >
                  {zones.map((z) => {
                    const isSlave = secondaryZones.some((sz) => sz.name === z.name)
                    return (
                      <option key={z.name} value={z.name}>
                        {z.name} {isSlave ? '[SLAVE]' : ''}
                      </option>
                    )
                  })}
                </select>
              ) : (
                <span className="text-sm text-[var(--muted)] mono">No hosted zones configured</span>
              )}

              {canWrite && (
                <button
                  type="button"
                  onClick={() => setIsCreatingZone((v) => !v)}
                  className="btn btn-secondary text-xs"
                >
                  <Plus size={14} weight="bold" />
                  <span>New Hosted Zone</span>
                </button>
              )}

              {canWrite && (
                <button
                  type="button"
                  onClick={() => setShowBindPanel((v) => !v)}
                  className={`btn text-xs ${showBindPanel ? 'btn-primary' : 'btn-secondary'}`}
                >
                  <CloudArrowUp size={14} weight="bold" />
                  <span>BIND Import / Export</span>
                </button>
              )}
            </div>

            {selectedZone && (() => {
              const activeSecondary = secondaryZones.find((sz) => sz.name === selectedZone)
              return (
                <div className="flex flex-wrap items-center gap-3 text-xs text-[var(--muted)] mono">
                  <span className="flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-[var(--ok)]" />
                    SOA Serial: <strong>{zoneDetail?.meta?.soa_serial || 1}</strong>
                  </span>
                  <span>
                    Type:{' '}
                    {activeSecondary ? (
                      <strong className="px-1.5 py-0.5 rounded bg-[var(--accent-soft)] text-[var(--accent)] border border-[var(--accent)]/30 uppercase">
                        SLAVE ({activeSecondary.last_mode || 'axfr'})
                      </strong>
                    ) : (
                      <strong>{zoneDetail?.meta?.type || 'native'}</strong>
                    )}
                  </span>
                  {activeSecondary ? (
                    <a
                      href="/settings#tools/axfr"
                      className="text-[var(--accent)] hover:underline font-medium"
                    >
                      Manage Slave ({(activeSecondary.masters || []).join(', ')})
                    </a>
                  ) : null}
                  <button
                    type="button"
                    onClick={() => setShowDnssecPanel((v) => !v)}
                    className={`px-2 py-0.5 rounded font-medium border flex items-center gap-1 transition-colors ${
                      dnssecStatus?.enabled
                        ? 'bg-[var(--ok)]/10 text-[var(--ok)] border-[var(--ok)]/30'
                        : 'bg-[var(--bg-elevated)] text-[var(--muted)] border-[var(--border)] hover:text-[var(--text)]'
                    }`}
                  >
                    <Key size={12} weight="bold" />
                    <span>
                      {dnssecStatus?.enabled
                        ? `DNSSEC ON (${dnssecStatus.algorithm || 'ECDSA'}${dnssecStatus.nsec3 ? ' · NSEC3' : ''})`
                        : 'DNSSEC & SOA'}
                    </span>
                  </button>
                  {canWrite && (
                    <button
                      type="button"
                      onClick={() => handleDeleteZone(selectedZone)}
                      className="text-xs text-[var(--danger)] hover:underline ml-2"
                    >
                      Delete Zone
                    </button>
                  )}
                </div>
              )
            })()}
          </section>

          {selectedZone && secondaryZones.some((sz) => sz.name === selectedZone) ? (
            <div className="px-3.5 py-2.5 rounded-[var(--radius)] border border-[var(--accent)]/30 bg-[var(--accent-soft)] text-xs text-[var(--text)] flex flex-wrap items-center justify-between gap-2">
              <span>
                <strong>Secondary (Slave) Zone:</strong> Records are replicated automatically from upstream primary via IXFR/AXFR. Local manual edits will be overwritten on the next sync.
              </span>
              <a href="/settings#tools/axfr" className="text-[var(--accent)] font-semibold hover:underline">
                Sync / Configure in Settings →
              </a>
            </div>
          ) : null}

          {/* Create Zone Inline Form */}
          {isCreatingZone && (
            <section className="panel p-4 bg-[var(--bg-elevated)] border border-[var(--accent)]/40 reveal">
              <h3 className="text-sm font-semibold mb-2">Create New Authoritative Zone</h3>
              <form onSubmit={handleCreateZone} className="flex flex-wrap gap-2 items-center">
                <input
                  className="input flex-1 min-w-[220px] mono text-sm"
                  placeholder="e.g. example.corp or sub.internal.id"
                  value={newZoneName}
                  onChange={(e) => setNewZoneName(e.target.value)}
                  required
                />
                <button type="submit" disabled={busy || !newZoneName.trim()} className="btn btn-primary text-xs">
                  Create Zone
                </button>
                <button
                  type="button"
                  onClick={() => setIsCreatingZone(false)}
                  className="btn btn-ghost text-xs"
                >
                  Cancel
                </button>
              </form>
            </section>
          )}

          {/* BIND Master File Import / Export Drawer */}
          {showBindPanel && (
            <section className="panel p-5 bg-[var(--bg-elevated)] border border-[var(--border-strong)] space-y-4 reveal">
              <div className="flex items-center justify-between border-b border-[var(--border)] pb-2.5">
                <h3 className="text-sm font-semibold">RFC 1035 BIND Zone Import &amp; Export</h3>
                <button
                  type="button"
                  onClick={() => setShowBindPanel(false)}
                  className="btn btn-ghost text-xs"
                >
                  Close
                </button>
              </div>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <form onSubmit={handleImportZone} className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-[var(--text)]">Import Master Zone File</span>
                  </div>
                  <input
                    className="input text-xs mono w-full"
                    placeholder="Target zone name (e.g. corp.local)"
                    value={importZoneName}
                    onChange={(e) => setImportZoneName(e.target.value)}
                    required
                  />
                  <textarea
                    rows={6}
                    className="input text-xs mono w-full"
                    placeholder={'$ORIGIN corp.local.\n$TTL 300\n@ IN A 10.10.10.5\nwww IN CNAME @'}
                    value={importContent}
                    onChange={(e) => setImportContent(e.target.value)}
                    required
                  />
                  <button type="submit" disabled={busy || !importContent.trim()} className="btn btn-primary text-xs">
                    <CloudArrowUp size={14} weight="bold" />
                    <span>Import BIND Records</span>
                  </button>
                </form>

                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-[var(--text)]">
                      Export Zone {selectedZone ? `(${selectedZone})` : ''}
                    </span>
                    <div className="flex gap-2">
                      <button
                        type="button"
                        disabled={busy || !selectedZone}
                        onClick={handleExportZone}
                        className="btn btn-secondary text-xs"
                      >
                        <CloudArrowDown size={14} weight="bold" />
                        <span>Fetch .zone</span>
                      </button>
                      {exportContent ? (
                        <>
                          <button
                            type="button"
                            onClick={() => handleCopy(exportContent, 'bind-export')}
                            className="btn btn-secondary text-xs"
                          >
                            {copiedKey === 'bind-export' ? 'Copied!' : 'Copy'}
                          </button>
                          <button
                            type="button"
                            onClick={handleDownloadZoneFile}
                            className="btn btn-primary text-xs"
                          >
                            Download .zone
                          </button>
                        </>
                      ) : null}
                    </div>
                  </div>
                  <textarea
                    rows={8}
                    readOnly
                    className="input text-xs mono w-full bg-[var(--bg)]"
                    placeholder="Click 'Fetch .zone' to generate RFC 1035 master zone output..."
                    value={exportContent}
                  />
                </div>
              </div>
            </section>
          )}

          {/* DNSSEC Signing & SOA Timers Drawer */}
          {showDnssecPanel && selectedZone && (
            <section className="panel p-5 bg-[var(--bg-elevated)] border border-[var(--border-strong)] space-y-4 reveal">
              <div className="flex items-center justify-between border-b border-[var(--border)] pb-2.5">
                <h3 className="text-sm font-semibold">DNSSEC &amp; SOA Policy · {selectedZone}</h3>
                <button
                  type="button"
                  onClick={() => setShowDnssecPanel(false)}
                  className="btn btn-ghost text-xs"
                >
                  Close
                </button>
              </div>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
                <div className="space-y-3">
                  <div className="text-xs font-semibold text-[var(--text)]">Authoritative DNSSEC Signing</div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div className="space-y-1">
                      <label className="label-quiet">Signing Algorithm</label>
                      <select
                        value={dnssecAlgo}
                        onChange={(e) => setDnssecAlgo(e.target.value)}
                        className="input text-xs mono"
                        disabled={!canWrite || busy}
                      >
                        <option value="ECDSAP256SHA256">ECDSAP256SHA256 (Algo 13)</option>
                        <option value="ED25519">ED25519 (Algo 15)</option>
                        <option value="ECDSAP384SHA384">ECDSAP384SHA384 (Algo 14)</option>
                        <option value="RSASHA256">RSASHA256 (Algo 8)</option>
                      </select>
                    </div>
                    <label className="flex items-center gap-2 text-xs pt-5 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={dnssecNsec3}
                        onChange={(e) => setDnssecNsec3(e.target.checked)}
                        disabled={!canWrite || busy}
                      />
                      <span>Enable NSEC3 Denial Hashing</span>
                    </label>
                  </div>
                  {canWrite && (
                    <div className="flex flex-wrap gap-2">
                      <button
                        type="button"
                        disabled={busy}
                        onClick={handleEnableDNSSEC}
                        className="btn btn-primary text-xs"
                      >
                        <ShieldCheck size={14} weight="bold" />
                        <span>{dnssecStatus?.enabled ? 'Apply / Re-sign Policy' : 'Enable DNSSEC'}</span>
                      </button>
                      {dnssecStatus?.enabled && (
                        <button
                          type="button"
                          disabled={busy}
                          onClick={handleRolloverZSK}
                          className="btn btn-secondary text-xs"
                        >
                          <Key size={14} weight="bold" />
                          <span>Rollover ZSK</span>
                        </button>
                      )}
                    </div>
                  )}
                  {dnssecStatus?.ds ? (
                    <div className="p-2.5 rounded bg-[var(--bg)] border border-[var(--border)] space-y-1">
                      <div className="flex items-center justify-between text-[11px] text-[var(--muted)]">
                        <span>Parent DS Record</span>
                        <button
                          type="button"
                          onClick={() => handleCopy(dnssecStatus.ds, 'ds-record')}
                          className="text-[var(--accent)] hover:underline"
                        >
                          {copiedKey === 'ds-record' ? 'Copied DS!' : 'Copy DS'}
                        </button>
                      </div>
                      <pre className="mono text-[11px] text-[var(--text)] whitespace-pre-wrap break-all">
                        {dnssecStatus.ds}
                      </pre>
                    </div>
                  ) : null}
                </div>

                <form onSubmit={handleSaveSOA} className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-[var(--text)]">SOA Timers (seconds)</span>
                    {!zoneDetail?.meta && (
                      <span className="text-[11px] text-[var(--muted)]">Requires PostgreSQL meta</span>
                    )}
                  </div>
                  <div className="grid grid-cols-2 gap-2.5">
                    <label className="space-y-1 text-xs">
                      <span className="label-quiet">Refresh</span>
                      <input
                        type="number"
                        className="input text-xs mono"
                        value={soaRefresh}
                        onChange={(e) => setSoaRefresh(Number(e.target.value))}
                        disabled={!canWrite || !zoneDetail?.meta}
                      />
                    </label>
                    <label className="space-y-1 text-xs">
                      <span className="label-quiet">Retry</span>
                      <input
                        type="number"
                        className="input text-xs mono"
                        value={soaRetry}
                        onChange={(e) => setSoaRetry(Number(e.target.value))}
                        disabled={!canWrite || !zoneDetail?.meta}
                      />
                    </label>
                    <label className="space-y-1 text-xs">
                      <span className="label-quiet">Expire</span>
                      <input
                        type="number"
                        className="input text-xs mono"
                        value={soaExpire}
                        onChange={(e) => setSoaExpire(Number(e.target.value))}
                        disabled={!canWrite || !zoneDetail?.meta}
                      />
                    </label>
                    <label className="space-y-1 text-xs">
                      <span className="label-quiet">Minimum / Neg TTL</span>
                      <input
                        type="number"
                        className="input text-xs mono"
                        value={soaMinimum}
                        onChange={(e) => setSoaMinimum(Number(e.target.value))}
                        disabled={!canWrite || !zoneDetail?.meta}
                      />
                    </label>
                  </div>
                  {canWrite && zoneDetail?.meta && (
                    <button type="submit" disabled={busy} className="btn btn-secondary text-xs">
                      Save SOA Timers
                    </button>
                  )}
                </form>
              </div>
            </section>
          )}

          {selectedZone ? (
            <div className="space-y-4">
              {/* Cloudflare Style Record Management Controls */}
              <div className="flex flex-wrap items-center justify-between gap-3">
                {/* Type Filter Tabs */}
                <div className="cf-tabs">
                  <button
                    type="button"
                    className={`cf-tab-btn ${typeFilter === 'ALL' ? 'is-active' : ''}`}
                    onClick={() => setTypeFilter('ALL')}
                  >
                    All Types ({records.length})
                  </button>
                  {RECORD_TYPES.map((t) => {
                    const count = records.filter((r) => (r.type || '').toUpperCase() === t).length
                    if (count === 0 && typeFilter !== t) return null
                    return (
                      <button
                        key={t}
                        type="button"
                        className={`cf-tab-btn ${typeFilter === t ? 'is-active' : ''}`}
                        onClick={() => setTypeFilter(t)}
                      >
                        {t} ({count})
                      </button>
                    )
                  })}
                </div>

                {/* Search & Add Record Trigger */}
                <div className="flex items-center gap-2 flex-wrap">
                  <div className="relative">
                    <MagnifyingGlass
                      size={14}
                      className="absolute left-2.5 top-1/2 -translate-y-1/2 text-[var(--muted)] pointer-events-none"
                    />
                    <input
                      className="input pl-8 py-1.5 text-xs min-w-[200px]"
                      placeholder="Search DNS records…"
                      value={recordSearch}
                      onChange={(e) => setRecordSearch(e.target.value)}
                    />
                  </div>

                  {canWrite && (
                    <button
                      type="button"
                      onClick={() => (isAddingRecord ? setIsAddingRecord(false) : openAddRecord())}
                      className="btn btn-primary text-xs"
                    >
                      <Plus size={14} weight="bold" />
                      <span>Add Record</span>
                    </button>
                  )}
                </div>
              </div>

              {/* Add / Edit Record Form */}
              {isAddingRecord && (
                <section className="panel p-5 bg-[var(--bg-elevated)] border border-[var(--border-strong)] space-y-4 reveal">
                  <div className="flex items-center justify-between border-b border-[var(--border)] pb-2.5">
                    <h3 className="text-sm font-semibold">
                      {editingRec ? `Edit ${editingRec.type} Record in ${selectedZone}` : `Add DNS Record to ${selectedZone}`}
                    </h3>
                    <button
                      type="button"
                      onClick={() => {
                        setIsAddingRecord(false)
                        setEditingRec(null)
                      }}
                      className="btn btn-ghost text-xs"
                    >
                      Close
                    </button>
                  </div>

                  <form onSubmit={handleSaveRecord} className="grid grid-cols-1 md:grid-cols-12 gap-3 items-end">
                    <div className="md:col-span-2 space-y-1">
                      <label className="label-quiet">Type</label>
                      <select
                        value={recType}
                        onChange={(e) => setRecType(e.target.value)}
                        className="input text-xs font-mono font-semibold"
                      >
                        {RECORD_TYPES.map((t) => (
                          <option key={t} value={t}>
                            {t}
                          </option>
                        ))}
                      </select>
                    </div>

                    <div className="md:col-span-4 space-y-1">
                      <label className="label-quiet">Name (@ for root)</label>
                      <input
                        className="input text-xs font-mono"
                        placeholder="@ or sub"
                        value={recName}
                        onChange={(e) => setRecName(e.target.value)}
                        required
                      />
                    </div>

                    <div className="md:col-span-4 space-y-1">
                      <label className="label-quiet">Content / Target</label>
                      <input
                        className="input text-xs font-mono"
                        placeholder={recType === 'A' ? '192.0.2.1' : recType === 'AAAA' ? '2001:db8::1' : 'target.example'}
                        value={recContent}
                        onChange={(e) => setRecContent(e.target.value)}
                        required
                      />
                    </div>

                    <div className="md:col-span-2 space-y-1">
                      <label className="label-quiet">TTL (seconds)</label>
                      <input
                        type="number"
                        min={1}
                        value={recTTL}
                        onChange={(e) => setRecTTL(Number(e.target.value))}
                        className="input text-xs font-mono"
                      />
                    </div>

                    {(recType === 'MX' || recType === 'SRV') && (
                      <div className="md:col-span-2 space-y-1">
                        <label className="label-quiet">Priority</label>
                        <input
                          type="number"
                          className="input text-xs font-mono"
                          value={recPrio}
                          onChange={(e) => setRecPrio(Number(e.target.value))}
                        />
                      </div>
                    )}

                    <div className="md:col-span-3 space-y-1">
                      <label className="label-quiet">Split-Horizon View (optional)</label>
                      <input
                        className="input text-xs font-mono"
                        placeholder="e.g. internal / external"
                        value={recView}
                        onChange={(e) => setRecView(e.target.value)}
                      />
                    </div>

                    <div className="md:col-span-3 space-y-1">
                      <label className="label-quiet">GeoDNS Tag (optional)</label>
                      <input
                        className="input text-xs font-mono"
                        placeholder="e.g. ID / SG / AS"
                        value={recGeoTag}
                        onChange={(e) => setRecGeoTag(e.target.value)}
                      />
                    </div>

                    <div className="md:col-span-12 flex justify-end gap-2 pt-2">
                      <button
                        type="button"
                        onClick={() => {
                          setIsAddingRecord(false)
                          setEditingRec(null)
                        }}
                        className="btn btn-secondary text-xs"
                      >
                        Cancel
                      </button>
                      <button type="submit" disabled={busy} className="btn btn-primary text-xs">
                        {editingRec ? 'Update Record' : 'Save Record'}
                      </button>
                    </div>
                  </form>
                </section>
              )}

              {/* Records Table */}
              <div className="cf-table-wrap">
                <table className="cf-table">
                  <thead>
                    <tr>
                      <th className="w-20">Type</th>
                      <th>Name</th>
                      <th>Content / Target</th>
                      <th className="w-24">TTL</th>
                      <th className="w-32">View / Geo</th>
                      <th className="w-24 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredRecords.length > 0 ? (
                      filteredRecords.map((r, i) => {
                        const copyKey = `${r.name}-${r.type}-${i}`
                        return (
                          <tr key={copyKey}>
                            <td>
                              <span className={`cf-badge ${typeBadgeClass(r.type)}`}>
                                {r.type}
                              </span>
                            </td>
                            <td className="mono font-medium text-[var(--text)]">
                              {r.name}
                            </td>
                            <td>
                              <div className="flex items-center gap-2 group">
                                <span className="mono text-xs text-[var(--muted)] group-hover:text-[var(--text)] transition-colors">
                                  {r.content}
                                </span>
                                <button
                                  type="button"
                                  onClick={() => handleCopy(r.content, copyKey)}
                                  className="text-[var(--muted)] hover:text-[var(--text)] opacity-0 group-hover:opacity-100 transition-opacity"
                                  title="Copy content"
                                >
                                  {copiedKey === copyKey ? (
                                    <Check size={13} className="text-[var(--ok)]" />
                                  ) : (
                                    <Copy size={13} />
                                  )}
                                </button>
                              </div>
                            </td>
                            <td className="mono text-xs text-[var(--muted)]">
                              {r.ttl === 300 ? 'Auto (300s)' : `${r.ttl}s`}
                            </td>
                            <td>
                              <div className="flex flex-wrap gap-1">
                                {r.view ? (
                                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--accent-soft)] text-[var(--accent)]">
                                    {r.view}
                                  </span>
                                ) : null}
                                {r.geo_tag ? (
                                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--ok-soft)] text-[var(--ok)]">
                                    {r.geo_tag}
                                  </span>
                                ) : null}
                                {!r.view && !r.geo_tag ? (
                                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[var(--bg-elevated)] border border-[var(--border)] text-[var(--muted)]">
                                    Default
                                  </span>
                                ) : null}
                              </div>
                            </td>
                            <td className="text-right whitespace-nowrap">
                              {canWrite && (
                                <>
                                  <button
                                    type="button"
                                    onClick={() => openEditRecord(r)}
                                    className="text-[var(--muted)] hover:text-[var(--accent)] transition-colors p-1 mr-1"
                                    title="Edit record"
                                  >
                                    <PencilSimple size={14} />
                                  </button>
                                  <button
                                    type="button"
                                    onClick={() => handleDeleteRecord(r)}
                                    className="text-[var(--muted)] hover:text-[var(--danger)] transition-colors p-1"
                                    title="Delete record"
                                  >
                                    <Trash size={14} />
                                  </button>
                                </>
                              )}
                            </td>
                          </tr>
                        )
                      })
                    ) : (
                      <tr>
                        <td colSpan={6} className="text-center py-8 text-[var(--muted)]">
                          {records.length === 0
                            ? 'No records in this zone yet. Click "Add Record" to configure DNS.'
                            : 'No records matching the filter criteria.'}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          ) : (
            <section className="panel p-8 text-center space-y-4">
              <Globe size={42} className="mx-auto text-[var(--accent)] opacity-80" />
              <div className="space-y-1">
                <h3 className="text-base font-semibold">No Authoritative Hosted Zone Selected</h3>
                <p className="text-xs text-[var(--muted)] max-w-md mx-auto">
                  Authoritative zones allow PowerSVX to serve local domain records directly with DNSSEC and fast lookups.
                </p>
              </div>
              {canWrite && (
                <button
                  type="button"
                  onClick={() => setIsCreatingZone(true)}
                  className="btn btn-primary text-xs"
                >
                  <Plus size={14} weight="bold" />
                  <span>Create Your First Hosted Zone</span>
                </button>
              )}
            </section>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 2: PROTECTION & FILTER RULES (ADGUARD HOME GRAMMAR) */}
      {/* ========================================================================= */}
      {activeTab === 'filtering' && (
        <div className="space-y-6 reveal">
          {/* AdGuard Active Rule Count Banner */}
          <section className="panel p-4 flex flex-wrap items-center justify-between gap-4 border-l-4 border-l-[var(--ok)]">
            <div className="flex items-center gap-3">
              <ShieldCheck size={28} className="text-[var(--ok)]" weight="fill" />
              <div>
                <h3 className="text-sm font-semibold text-[var(--text)]">
                  National RPZ & Custom Filtering Protection
                </h3>
                <p className="text-xs text-[var(--muted)] mt-0.5">
                  PowerSVX evaluates domains against: <strong>Whitelist (Overrides)</strong> →{' '}
                  <strong>Blacklist (Manual Blocks)</strong> →{' '}
                  <strong>
                    Kominfo AXFR Dataset ({rpzEntries != null ? `${rpzEntries.toLocaleString()} rules in CDB` : 'CDB synced'})
                  </strong>
                </p>
              </div>
            </div>
            <a href="/settings#tools/axfr" className="btn btn-secondary text-xs">
              View Kominfo AXFR Status →
            </a>
          </section>

          {/* Interactive Domain Rule Tester (AdGuard Home Style) */}
          <section className="panel p-5 space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-[var(--text)]">Live Domain Evaluation Tester</h3>
              <span className="text-xs text-[var(--muted)] mono">Test if a domain is blocked or allowed</span>
            </div>

            <form onSubmit={handleDomainLookup} className="flex flex-wrap gap-2">
              <input
                className="input flex-1 min-w-[240px] mono text-sm"
                placeholder="e.g. tracker.ads.example or bank.co.id"
                value={lookupDomain}
                onChange={(e) => setLookupDomain(e.target.value)}
              />
              <button type="submit" disabled={busy || !lookupDomain.trim()} className="btn btn-primary text-xs">
                Evaluate Domain
              </button>
            </form>

            {lookupResult && (
              <div className="mt-3 p-3.5 rounded-[var(--radius)] bg-[var(--bg-elevated)] border border-[var(--border)] flex flex-wrap items-center justify-between gap-3">
                <div className="space-y-1">
                  <div className="mono font-semibold text-sm text-[var(--text)] flex items-center gap-2">
                    {lookupResult.blocked ? (
                      <XCircle size={18} className="text-red-400" weight="fill" />
                    ) : (
                      <CheckCircle size={18} className="text-[var(--ok)]" weight="fill" />
                    )}
                    <span>{lookupResult.name}</span>
                  </div>
                  <div className="text-xs text-[var(--muted)]">
                    Decision:{' '}
                    <strong className={lookupResult.blocked ? 'text-red-400' : 'text-[var(--ok)]'}>
                      {lookupResult.whitelisted
                        ? 'Allowed by Whitelist Override'
                        : lookupResult.blacklisted
                          ? 'Blocked by Manual Blacklist'
                          : lookupResult.blocked
                            ? `Blocked by RPZ (${lookupResult.action || 'nxdomain'}${lookupResult.block_source ? ` · ${lookupResult.block_source}` : ''})`
                            : 'Allowed (Clean Domain)'}
                    </strong>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  {canWrite && !lookupResult.whitelisted && (
                    <button
                      type="button"
                      onClick={() => handleAddWhitelist(lookupResult.name)}
                      className="btn btn-secondary text-xs"
                    >
                      + Add to Whitelist
                    </button>
                  )}
                  {canWrite && !lookupResult.blacklisted && (
                    <button
                      type="button"
                      onClick={() => handleAddBlacklist(lookupResult.name)}
                      className="btn btn-secondary text-xs text-[var(--danger)]"
                    >
                      + Add to Blacklist
                    </button>
                  )}
                </div>
              </div>
            )}
          </section>

          {/* Whitelist and Blacklist Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            {/* Whitelist Manager */}
            <section className="panel p-4 space-y-3">
              <div className="flex items-center justify-between border-b border-[var(--border)] pb-2.5">
                <div>
                  <h3 className="text-sm font-semibold text-[var(--text)] flex items-center gap-2">
                    <ShieldCheck size={16} className="text-[var(--ok)]" />
                    Whitelist / Allowlist ({whitelist.length})
                  </h3>
                  <p className="text-xs text-[var(--muted)] mt-0.5">
                    Domains that bypass all RPZ blocklists and never get blocked
                  </p>
                </div>
              </div>

              {canWrite && (
                <form
                  onSubmit={(e) => {
                    e.preventDefault()
                    handleAddWhitelist(wlDraft)
                  }}
                  className="flex gap-2"
                >
                  <input
                    className="input text-xs mono flex-1"
                    placeholder="example.com or *.cdn.ok"
                    value={wlDraft}
                    onChange={(e) => setWlDraft(e.target.value)}
                  />
                  <button type="submit" disabled={busy || !wlDraft.trim()} className="btn btn-primary text-xs">
                    Allow
                  </button>
                </form>
              )}

              <input
                className="input text-xs py-1 px-2.5 w-full"
                placeholder="Filter whitelist domains…"
                value={wlSearch}
                onChange={(e) => setWlSearch(e.target.value)}
              />

              <div className="space-y-1.5 max-h-[320px] overflow-auto pr-1">
                {whitelist.filter((d) => !wlSearch || d.toLowerCase().includes(wlSearch.toLowerCase())).length > 0 ? (
                  whitelist
                    .filter((d) => !wlSearch || d.toLowerCase().includes(wlSearch.toLowerCase()))
                    .map((d) => (
                      <div key={d} className="ag-bar-row">
                        <div className="ag-bar-fill ag-bar-fill-ok" style={{ width: '100%' }} />
                        <div className="ag-bar-content">
                          <span className="mono text-xs font-medium text-[var(--text)] truncate">{d}</span>
                          {canWrite && (
                            <button
                              type="button"
                              onClick={() => handleRemoveWhitelist(d)}
                              className="text-[var(--muted)] hover:text-[var(--danger)] p-1 transition-colors"
                              title="Remove domain"
                            >
                              <Trash size={13} />
                            </button>
                          )}
                        </div>
                      </div>
                    ))
                ) : (
                  <EmptyState title="Whitelist empty" hint="Add trusted domains to protect them from false positives." />
                )}
              </div>
            </section>

            {/* Blacklist Manager */}
            <section className="panel p-4 space-y-3">
              <div className="flex items-center justify-between border-b border-[var(--border)] pb-2.5">
                <div>
                  <h3 className="text-sm font-semibold text-[var(--text)] flex items-center gap-2">
                    <ShieldWarning size={16} className="text-red-400" />
                    Custom Blacklist ({blacklist.length})
                  </h3>
                  <p className="text-xs text-[var(--muted)] mt-0.5">
                    Manual custom blocklist enforced locally with NXDOMAIN response
                  </p>
                </div>
              </div>

              {canWrite && (
                <form
                  onSubmit={(e) => {
                    e.preventDefault()
                    handleAddBlacklist(blDraft)
                  }}
                  className="flex gap-2"
                >
                  <input
                    className="input text-xs mono flex-1"
                    placeholder="bad.example or *.malware.net"
                    value={blDraft}
                    onChange={(e) => setBlDraft(e.target.value)}
                  />
                  <button type="submit" disabled={busy || !blDraft.trim()} className="btn btn-primary text-xs">
                    Block
                  </button>
                </form>
              )}

              <input
                className="input text-xs py-1 px-2.5 w-full"
                placeholder="Filter blacklist domains…"
                value={blSearch}
                onChange={(e) => setBlSearch(e.target.value)}
              />

              <div className="space-y-1.5 max-h-[320px] overflow-auto pr-1">
                {blacklist.filter((d) => !blSearch || d.toLowerCase().includes(blSearch.toLowerCase())).length > 0 ? (
                  blacklist
                    .filter((d) => !blSearch || d.toLowerCase().includes(blSearch.toLowerCase()))
                    .map((d) => (
                      <div key={d} className="ag-bar-row">
                        <div className="ag-bar-fill ag-bar-fill-danger" style={{ width: '100%' }} />
                        <div className="ag-bar-content">
                          <span className="mono text-xs font-medium text-[var(--text)] truncate">{d}</span>
                          {canWrite && (
                            <button
                              type="button"
                              onClick={() => handleRemoveBlacklist(d)}
                              className="text-[var(--muted)] hover:text-[var(--danger)] p-1 transition-colors"
                              title="Remove domain"
                            >
                              <Trash size={13} />
                            </button>
                          )}
                        </div>
                      </div>
                    ))
                ) : (
                  <EmptyState title="Blacklist empty" hint="Add custom malicious domains to block them immediately." />
                )}
              </div>
            </section>
          </div>
        </div>
      )}
    </div>
  )
}
