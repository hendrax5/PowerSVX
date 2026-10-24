import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Moon, Sun } from '@phosphor-icons/react'
import { api, setToken } from '../../api'
import { useAuth } from '../../auth'
import { useTheme } from '../../theme'
import { ErrorBox, releaseLabel } from '../../ui'

function friendlyAuthError(raw) {
  const m = String(raw || '').toLowerCase()
  if (m.includes('unauthorized') || m.includes('401') || m.includes('forbidden') || m.includes('invalid credentials')) {
    return 'Sign-in failed. Check username and password.'
  }
  if (m.includes('too many')) {
    return 'Too many login attempts. Wait a minute and try again.'
  }
  if (m.includes('network') || m.includes('failed to fetch')) {
    return 'Cannot reach the server. Check that PowerSVX is running.'
  }
  return raw || 'Sign-in failed'
}

export default function LoginPage() {
  const { me, refresh } = useAuth()
  const { theme, toggleTheme } = useTheme()
  const nav = useNavigate()
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [err, setErr] = useState('')
  const [errDetail, setErrDetail] = useState('')
  const [busy, setBusy] = useState(false)
  const [release, setRelease] = useState('')

  useEffect(() => {
    let alive = true
    api
      .health()
      .then((h) => {
        if (alive) setRelease(releaseLabel(h))
      })
      .catch(() => {})
    return () => {
      alive = false
    }
  }, [])

  useEffect(() => {
    if (me && !me.auth_required) nav('/', { replace: true })
    if (me?.auth_required && me.name && me.name !== 'anonymous') nav('/', { replace: true })
  }, [me, nav])

  const submit = async (e) => {
    e.preventDefault()
    setBusy(true)
    setErr('')
    setErrDetail('')
    try {
      setToken('')
      await api.login(username, password)
      await refresh()
      nav('/', { replace: true })
    } catch (ex) {
      const raw = ex.message || 'Login failed'
      setErr(friendlyAuthError(raw))
      setErrDetail(raw)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login-shell">
      <div className="login-brand-pane">
        <div>
          <div className="brand-mark text-4xl md:text-5xl tracking-tighter">
            <span>Power</span>
            <span className="svx">SVX</span>
          </div>
          <p className="text-sm text-[var(--muted)] mt-5 max-w-[36ch] leading-relaxed">
            DNS control plane for resolve, filter, zones, and live ops.
          </p>
        </div>
        <p className="text-xs text-[var(--muted)] mono">{release || 'recursive · rpz · axfr · observe'}</p>
      </div>
      <div className="login-form-pane">
        <form onSubmit={submit} className="login-card space-y-5 reveal">
          <div className="flex items-start justify-between">
            <div>
              <p className="eyebrow">Sign in</p>
              <h1 className="text-xl font-semibold tracking-tight">Local admin</h1>
              <p className="text-sm text-[var(--muted)] mt-2 leading-relaxed">
                Default user <span className="mono text-[var(--text)]">admin</span> — password from{' '}
                <span className="mono text-[var(--text)]">ADMIN_PASSWORD</span>.
              </p>
            </div>
            <button
              type="button"
              onClick={toggleTheme}
              className="btn btn-ghost text-xs p-1.5 shrink-0"
              title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
              aria-label="Toggle theme"
            >
              {theme === 'dark' ? <Sun size={17} weight="regular" /> : <Moon size={17} weight="regular" />}
            </button>
          </div>
          {err ? <ErrorBox msg={err} detail={errDetail !== err ? errDetail : undefined} /> : null}
          <label className="field label-quiet">
            Username
            <input
              className="input"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              required
            />
          </label>
          <label className="field label-quiet">
            Password
            <input
              type="password"
              className="input"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
            />
          </label>
          <button type="submit" disabled={busy} className="btn btn-primary w-full">
            {busy ? 'Signing in…' : 'Sign in'}
          </button>
        </form>
      </div>
    </div>
  )
}
