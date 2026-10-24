import { useEffect, useState } from 'react'
import { NavLink, useLocation, useNavigate } from 'react-router-dom'
import {
  ChartLine,
  ClipboardText,
  Gauge,
  GearSix,
  Globe,
  MagnifyingGlass,
  Moon,
  Sun,
} from '@phosphor-icons/react'
import { api, setToken } from '../api'
import { useAuth } from '../auth'
import { useTheme } from '../theme'
import { ICON_WEIGHT, releaseLabel } from '../ui'

export default function Shell({ children }) {
  const { me, refresh } = useAuth()
  const { theme, toggleTheme } = useTheme()
  const nav = useNavigate()
  const loc = useLocation()
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
    const handleKeyDown = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        nav('/lookup')
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [nav])

  const navGroups = [
    {
      label: 'Operate',
      links: [
        ['/', 'Dashboard', Gauge],
        ['/domains', 'Domains', Globe],
        ['/lookup', 'Lookup', MagnifyingGlass],
      ],
    },
    {
      label: 'Observe',
      links: [
        ['/analytics', 'Analytics', ChartLine],
        ['/audit', 'Audit', ClipboardText],
      ],
    },
    {
      label: 'Configure',
      links: [['/settings', 'Settings', GearSix]],
    },
  ]
  const hereLabel =
    navGroups.flatMap((g) => g.links).find(([to]) => (to === '/' ? loc.pathname === '/' : loc.pathname.startsWith(to)))?.[1] ||
    'Dashboard'

  const logout = async () => {
    try {
      await api.logout()
    } catch {
      /* ignore */
    }
    setToken('')
    await refresh()
    nav('/login')
  }

  return (
    <div className="shell">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:z-[60] focus:top-3 focus:left-3 focus:bg-[var(--accent)] focus:text-[#17140f] focus:px-3 focus:py-2.5 focus:rounded-[var(--radius)]"
      >
        Skip to content
      </a>
      <aside className="shell-aside" aria-label="Sidebar">
        <div className="shell-brand reveal">
          <div className="brand-mark text-[clamp(1.4rem,2vw,1.7rem)]" aria-label="PowerSVX">
            <span>Power</span>
            <span className="svx">SVX</span>
          </div>
          <div className="crumb-live" aria-current="page">
            <span className="pulse-dot on" aria-hidden />
            <span>dns</span>
            <span aria-hidden>/</span>
            <strong>{hereLabel}</strong>
          </div>
        </div>
        <nav className="shell-nav" aria-label="Primary">
          {navGroups.map((group) => (
            <div key={group.label} className="shell-nav-group">
              <div className="shell-nav-label">{group.label}</div>
              {group.links.map(([to, label, Icon]) => (
                <NavLink
                  key={to}
                  to={to}
                  end={to === '/'}
                  className={({ isActive }) => `nav-link ${isActive ? 'is-active' : ''}`}
                >
                  <Icon className="nav-ico" size={18} weight={ICON_WEIGHT} aria-hidden />
                  {label}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
        <div className="shell-user space-y-2 text-xs">
          <button
            type="button"
            onClick={toggleTheme}
            className="btn btn-secondary w-full flex items-center justify-center gap-2 text-xs"
            title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
            aria-label="Toggle theme"
          >
            {theme === 'dark' ? <Sun size={15} weight="regular" /> : <Moon size={15} weight="regular" />}
            <span>{theme === 'dark' ? 'Light mode' : 'Dark mode'}</span>
          </button>
          {release ? (
            <div className="text-[var(--muted)] px-1 mono" title="Deployed DNS build">
              {release}
            </div>
          ) : null}
          {me?.auth_required ? (
            <>
              <div className="text-[var(--muted)] px-1">
                <span className="text-[var(--text)] font-medium">{me.name}</span>
                <span className="mx-1.5 text-[var(--border-strong)]">·</span>
                <span className="text-[var(--accent)]">{me.role}</span>
              </div>
              <button type="button" onClick={logout} className="btn btn-secondary w-full">
                Log out
              </button>
            </>
          ) : (
            <div className="text-[var(--muted)] px-1">Open access</div>
          )}
        </div>
      </aside>
      <main id="main" tabIndex={-1} className="shell-main">
        <div className="shell-main-inner">{children}</div>
      </main>
    </div>
  )
}
