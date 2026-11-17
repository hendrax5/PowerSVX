import { lazy, Suspense, useEffect, useRef, useState } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'
import { api } from './api'
import { AuthCtx, useAuth } from './auth'
import Shell from './components/Shell'
import { ErrorBoundary } from './components/ErrorBoundary'
import { I18nProvider, useI18n } from './i18n'
import { ThemeProvider } from './theme'
import { LoadingBlock } from './ui'

const LoginPage = lazy(() => import('./features/auth/LoginPage'))
const Dashboard = lazy(() => import('./features/dashboard/Dashboard'))
const DomainsPage = lazy(() => import('./features/domains/DomainsPage'))
const Lookup = lazy(() => import('./features/lookup/Lookup'))
const CachePage = lazy(() => import('./features/cache/CachePage'))
const SecurityPage = lazy(() => import('./features/security/SecurityPage'))
const Analytics = lazy(() => import('./features/analytics/Analytics'))
const AuditLog = lazy(() => import('./features/audit/AuditLog'))
const SettingsPage = lazy(() => import('./features/settings/SettingsPage'))
const TerminalPage = lazy(() => import('./features/terminal/TerminalPage'))

function UpdateWatcher() {
  const { t } = useI18n()
  const [pending, setPending] = useState(false)
  const buildRef = useRef('')

  useEffect(() => {
    let alive = true
    const check = async () => {
      try {
        const h = await api.health()
        const id = h?.build_id || `${h?.version || ''}+${h?.started_at || ''}`
        if (!id) return
        if (!buildRef.current) {
          buildRef.current = id
          return
        }
        if (buildRef.current !== id && alive) {
          setPending(true)
        }
      } catch {
        /* offline / restarting */
      }
    }
    check()
    const tmr = setInterval(check, 45000)
    return () => {
      alive = false
      clearInterval(tmr)
    }
  }, [])

  if (!pending) return null
  return (
    <div
      className="fixed bottom-4 right-4 z-50 max-w-sm border border-[var(--accent)]/50 bg-[var(--bg-elevated)] shadow-lg px-4 py-3 text-sm"
      role="status"
    >
      <p className="font-medium">{t('update.title')}</p>
      <p className="text-[var(--muted)] text-xs mt-1">{t('update.sub')}</p>
      <div className="flex gap-2 mt-3">
        <button type="button" className="btn btn-primary text-xs" onClick={() => window.location.reload()}>
          {t('update.reload')}
        </button>
        <button type="button" className="btn btn-ghost text-xs" onClick={() => setPending(false)}>
          {t('update.later')}
        </button>
      </div>
    </div>
  )
}

function RequireAuth({ children }) {
  const { me, loading } = useAuth()
  if (loading) return <LoadingBlock label="Checking session" />
  if (me?.auth_required && (!me.name || me.name === 'anonymous')) {
    return <Navigate to="/login" replace />
  }
  return children
}

export default function App() {
  const [me, setMe] = useState(null)
  const [loading, setLoading] = useState(true)

  const refresh = async () => {
    try {
      const m = await api.me()
      setMe(m)
    } catch {
      setMe({ auth_required: true, name: '', role: '' })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    refresh()
  }, [])

  const role = (me?.role || '').toLowerCase()
  const value = {
    me,
    loading,
    refresh,
    canWrite: !me?.auth_required || role === 'admin' || role === 'operator',
    isAdmin: !me?.auth_required || role === 'admin',
  }

  return (
    <I18nProvider>
      <ThemeProvider>
        <AuthCtx.Provider value={value}>
          <UpdateWatcher />
          <ErrorBoundary>
            <Suspense fallback={<div className="p-8"><LoadingBlock label="Loading page" /></div>}>
              <Routes>
                <Route path="/login" element={<LoginPage />} />
                <Route
                  path="/*"
                  element={
                    <RequireAuth>
                      <Shell>
                        <Suspense fallback={<LoadingBlock label="Loading feature" />}>
                          <Routes>
                            <Route path="/" element={<Dashboard />} />
                            <Route path="/zones" element={<Navigate to="/" replace />} />
                            <Route path="/domains" element={<DomainsPage />} />
                            <Route path="/zones/:name" element={<Navigate to="/" replace />} />
                            <Route path="/lookup" element={<Lookup />} />
                            <Route path="/cache" element={<CachePage />} />
                            <Route path="/security" element={<SecurityPage />} />
                            <Route path="/logs" element={<Navigate to="/analytics" replace />} />
                            <Route path="/audit" element={<AuditLog />} />
                            <Route path="/settings" element={<SettingsPage />} />
                            <Route path="/terminal" element={<TerminalPage />} />
                            <Route path="/analytics" element={<Analytics />} />
                          </Routes>
                        </Suspense>
                      </Shell>
                    </RequireAuth>
                  }
                />
              </Routes>
            </Suspense>
          </ErrorBoundary>
        </AuthCtx.Provider>
      </ThemeProvider>
    </I18nProvider>
  )
}
