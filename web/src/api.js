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
  enableZoneDNSSEC: (name) =>
    request(`/api/v1/zones/${encodeURIComponent(name)}/dnssec`, { method: 'POST', body: '{}' }),
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
  audit: () => request('/api/v1/audit'),
  acme: () => request('/api/v1/acme'),
  acmeObtain: () => request('/api/v1/acme', { method: 'POST', body: '{}' }),
  rpz: () => request('/api/v1/rpz'),
  updateRPZ: (policies, sync = false, updateInterval, axfrUpdateInterval, axfrOnly = false, updateAt) =>
    request('/api/v1/rpz', {
      method: 'PUT',
      body: JSON.stringify({
        policies,
        sync,
        ...(updateInterval === undefined ? {} : { update_interval: updateInterval }),
        ...(updateAt === undefined ? {} : { update_at: updateAt }),
        ...(axfrUpdateInterval === undefined ? {} : { axfr_update_interval: axfrUpdateInterval }),
        ...(axfrOnly ? { axfr_only: true } : {}),
      }),
    }),
  reloadRPZ: (axfrOnly = false) =>
    request(`/api/v1/rpz${axfrOnly ? '?axfr_only=1' : ''}`, { method: 'POST', body: '{}' }),
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
  lookup: (name, type) =>
    request('/api/v1/tools/lookup', { method: 'POST', body: JSON.stringify({ name, type }) }),
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
  events: () => request('/api/v1/events'),
  eventsStreamURL() {
    const token = getToken()
    const q = token ? `?token=${encodeURIComponent(token)}` : ''
    return `/api/v1/events/stream${q}`
  },
}
