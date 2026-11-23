const TOKEN_KEY = 'powersvx_token'

export function getToken() {
  return localStorage.getItem(TOKEN_KEY) || ''
}

export function setToken(token) {
  if (token) localStorage.setItem(TOKEN_KEY, token)
  else localStorage.removeItem(TOKEN_KEY)
}

function redirectToLogin() {
  if (typeof window === 'undefined') return
  const path = window.location.pathname || ''
  if (path === '/login' || path.startsWith('/login')) return
  window.location.assign('/login')
}

async function request(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) }
  const token = getToken()
  if (token) headers.Authorization = `Bearer ${token}`

  const res = await fetch(path, { ...opts, headers, credentials: 'include' })
  if (res.status === 401 && !opts.skipAuthRedirect && path !== '/api/v1/auth/login') {
    redirectToLogin()
  }
  if (res.status === 204) return null
  const text = await res.text()
  let data = null
  try {
    data = text ? JSON.parse(text) : null
  } catch {
    data = { raw: text }
  }
  if (!res.ok) {
    const msg = typeof data === 'string' ? data : data?.error || data?.raw || res.statusText
    throw new Error(msg || `HTTP ${res.status}`)
  }
  return data
}

export const api = {
  health: () => request('/api/v1/health', { skipAuthRedirect: true }),
  me: () => request('/api/v1/auth/me', { skipAuthRedirect: true }),
  login: (username, password) =>
    request('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
      skipAuthRedirect: true,
    }),
  logout: () => request('/api/v1/auth/logout', { method: 'POST', skipAuthRedirect: true }),
  listUsers: () => request('/api/v1/auth/users'),
  upsertUser: (body) => request('/api/v1/auth/users', { method: 'POST', body: JSON.stringify(body) }),
  deleteUser: (name) =>
    request(`/api/v1/auth/users?name=${encodeURIComponent(name)}`, { method: 'DELETE' }),
  status: () => request('/api/v1/status'),
  dashboard: () => request('/api/v1/dashboard'),
  zones: () => request('/api/v1/zones'),
  createZone: (name) => request('/api/v1/zones', { method: 'POST', body: JSON.stringify({ name }) }),
  getZone: (name) => request(`/api/v1/zones/${encodeURIComponent(name)}`),
  deleteZone: (name) => request(`/api/v1/zones/${encodeURIComponent(name)}`, { method: 'DELETE' }),
  addRecord: (zone, rec) =>
    request(`/api/v1/zones/${encodeURIComponent(zone)}/records`, {
      method: 'POST',
      body: JSON.stringify(rec),
    }),
  deleteRecord: (zone, name, type) => {
    const q = new URLSearchParams({ name })
    if (type) q.set('type', type)
    return request(`/api/v1/zones/${encodeURIComponent(zone)}/records?${q}`, { method: 'DELETE' })
  },
  settings: () => request('/api/v1/settings'),
  updateSettings: (body) =>
    request('/api/v1/settings', { method: 'PUT', body: JSON.stringify(body) }),
  analytics: () => request('/api/v1/analytics'),
  backup: () => request('/api/v1/backup'),
  restoreBackup: (body) => request('/api/v1/backup', { method: 'POST', body: JSON.stringify(body) }),
  zoneDNSSEC: (name) => request(`/api/v1/zones/${encodeURIComponent(name)}/dnssec`),
  enableZoneDNSSEC: (name, opts = {}) =>
    request(`/api/v1/zones/${encodeURIComponent(name)}/dnssec`, {
      method: 'POST',
      body: JSON.stringify(opts),
    }),
  importZone: (zone, content) =>
    request('/api/v1/zones/import', {
      method: 'POST',
      body: JSON.stringify({ zone, content }),
    }),
  exportZone: (name) => request(`/api/v1/zones/${encodeURIComponent(name)}/export`),
  anomaly: () => request('/api/v1/anomaly'),
  updateZoneMeta: (name, body) =>
    request(`/api/v1/zones/${encodeURIComponent(name)}`, { method: 'PUT', body: JSON.stringify(body) }),
  updateRecord: (zone, body) =>
    request(`/api/v1/zones/${encodeURIComponent(zone)}/records`, {
      method: 'PUT',
      body: JSON.stringify(body),
    }),
  queryLogs: ({ client_ip = '', limit = 50, offset = 0 } = {}) => {
    const q = new URLSearchParams()
    if (client_ip) q.set('client_ip', client_ip)
    q.set('limit', String(limit))
    q.set('offset', String(offset))
    return request(`/api/v1/query-logs?${q}`)
  },
  liveQueries: ({ q = '', client = '', rcode = '', blocked = false, limit = 150 } = {}) => {
    const p = new URLSearchParams()
    if (q) p.set('q', q)
    if (client) p.set('client', client)
    if (rcode) p.set('rcode', rcode)
    if (blocked) p.set('blocked', '1')
    p.set('limit', String(limit))
    return request(`/api/v1/queries/live?${p}`)
  },
  liveQueriesStreamURL({ q = '', client = '', rcode = '', blocked = false } = {}) {
    const p = new URLSearchParams()
    if (q) p.set('q', q)
    if (client) p.set('client', client)
    if (rcode) p.set('rcode', rcode)
    if (blocked) p.set('blocked', '1')
    const token = getToken()
    if (token) p.set('token', token)
    const qs = p.toString()
    return `/api/v1/queries/stream${qs ? `?${qs}` : ''}`
  },
  audit: () => request('/api/v1/audit'),
  acme: () => request('/api/v1/acme'),
  acmeObtain: () => request('/api/v1/acme', { method: 'POST', body: '{}' }),
  rpz: () => request('/api/v1/rpz'),
  updateRPZ: (policies, sync = false, updateInterval, axfrUpdateInterval, axfrOnly = false, updateAt, force = false) =>
    request('/api/v1/rpz', {
      method: 'PUT',
      body: JSON.stringify({
        policies,
        sync,
        ...(updateInterval === undefined ? {} : { update_interval: updateInterval }),
        ...(updateAt === undefined ? {} : { update_at: updateAt }),
        ...(axfrUpdateInterval === undefined ? {} : { axfr_update_interval: axfrUpdateInterval }),
        ...(axfrOnly ? { axfr_only: true } : {}),
        ...(force ? { force: true } : {}),
      }),
    }),
  reloadRPZ: (axfrOnly = false, force = false) => {
    const q = new URLSearchParams()
    if (axfrOnly) q.set('axfr_only', '1')
    if (force) q.set('force', '1')
    const qs = q.toString()
    return request(`/api/v1/rpz${qs ? `?${qs}` : ''}`, { method: 'POST', body: '{}' })
  },
  domainLookup: (name) =>
    request(`/api/v1/domains/lookup?name=${encodeURIComponent(name)}`),
  whitelist: () => request('/api/v1/domains/whitelist'),
  addWhitelist: (domain) =>
    request('/api/v1/domains/whitelist', {
      method: 'POST',
      body: JSON.stringify({ domain }),
    }),
  removeWhitelist: (name) =>
    request(`/api/v1/domains/whitelist?name=${encodeURIComponent(name)}`, { method: 'DELETE' }),
  blacklist: () => request('/api/v1/domains/blacklist'),
  addBlacklist: (domain) =>
    request('/api/v1/domains/blacklist', {
      method: 'POST',
      body: JSON.stringify({ domain }),
    }),
  removeBlacklist: (name) =>
    request(`/api/v1/domains/blacklist?name=${encodeURIComponent(name)}`, { method: 'DELETE' }),
  lookup: (nameOrOpts, type) => {
    const payload = typeof nameOrOpts === 'object' ? nameOrOpts : { name: nameOrOpts, type }
    return request('/api/v1/tools/lookup', { method: 'POST', body: JSON.stringify(payload) })
  },
  trace: (name, type = 'A') =>
    request('/api/v1/tools/trace', { method: 'POST', body: JSON.stringify({ name, type }) }),
  cacheStats: () => request('/api/v1/cache/stats'),
  cacheInspect: (q = '', limit = 100) => {
    const p = new URLSearchParams()
    if (q) p.set('q', q)
    p.set('limit', String(limit))
    return request(`/api/v1/cache/inspect?${p}`)
  },
  cacheFlush: (body) =>
    request('/api/v1/cache/flush', { method: 'POST', body: JSON.stringify(body || { scope: 'all' }) }),
  securityBlocks: () => request('/api/v1/security/blocks'),
  securityBan: (body) =>
    request('/api/v1/security/ban', { method: 'POST', body: JSON.stringify(body || {}) }),
  securityUnban: (prefix) =>
    request(`/api/v1/security/ban?prefix=${encodeURIComponent(prefix)}`, { method: 'DELETE' }),
  securityClearDynBlocks: () =>
    request('/api/v1/security/dynblocks/clear', { method: 'POST', body: '{}' }),
  listTokens: () => request('/api/v1/auth/tokens'),
  createToken: (body) =>
    request('/api/v1/auth/tokens', { method: 'POST', body: JSON.stringify(body || {}) }),
  revokeToken: (id) =>
    request(`/api/v1/auth/tokens?id=${encodeURIComponent(id)}`, { method: 'DELETE' }),
  secondary: () => request('/api/v1/secondary'),
  upsertSecondary: (body) =>
    request('/api/v1/secondary', { method: 'POST', body: JSON.stringify(body) }),
  updateSecondary: (name, body) =>
    request(`/api/v1/secondary/${encodeURIComponent(name)}`, {
      method: 'PUT',
      body: JSON.stringify(body),
    }),
  deleteSecondary: (name) =>
    request(`/api/v1/secondary/${encodeURIComponent(name)}`, { method: 'DELETE' }),
  transferSecondary: (name) =>
    request(`/api/v1/secondary/${encodeURIComponent(name)}/transfer`, {
      method: 'POST',
      body: '{}',
    }),
  axfrSync: () => request('/api/v1/axfr-sync'),
  setAxfrSync: (body) =>
    request('/api/v1/axfr-sync', {
      method: 'PUT',
      body: JSON.stringify(body || {}),
    }),
  runAxfrSync: () =>
    request('/api/v1/axfr-sync', { method: 'POST', body: '{}' }),
  conntrack: () => request('/api/v1/conntrack'),
  updateConntrack: (body) =>
    request('/api/v1/conntrack', { method: 'PUT', body: JSON.stringify(body || {}) }),
  applyConntrack: () => request('/api/v1/conntrack/apply', { method: 'POST', body: '{}' }),
  hostNetwork: () => request('/api/v1/host/network'),
  applyHostNetwork: (body) =>
    request('/api/v1/host/network/apply', { method: 'POST', body: JSON.stringify(body || {}) }),
  removeHostIP: (body) =>
    request('/api/v1/host/network/remove-ip', { method: 'POST', body: JSON.stringify(body || {}) }),
  events: () => request('/api/v1/events'),
  eventsStreamURL() {
    const token = getToken()
    const q = token ? `?token=${encodeURIComponent(token)}` : ''
    return `/api/v1/events/stream${q}`
  },
}
