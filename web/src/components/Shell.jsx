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
  TerminalWindow,
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
      label: 'Control Plane',
      links: [
        ['/', 'Dashboard', Gauge],
        ['/domains', 'DNS & Filtering', Globe],
        ['/lookup', 'Query Lookup', MagnifyingGlass],
      ],
    },
    {
      label: 'Observability',
      links: [
        ['/analytics', 'Analytics', ChartLine],
        ['/audit', 'Audit Logs', ClipboardText],
      ],
    },
    {
      label: 'System & Routing',
      links: [
        ['/settings', 'Settings', GearSix],
        ['/terminal', 'Live Terminal', TerminalWindow],
      ],
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
          <div className="flex items-center justify-between">
            <div className="brand-mark text-[clamp(1.4rem,2vw,1.75rem)] flex items-center gap-1.5" aria-label="PowerSVX">
              <span>Power</span>
              <span className="svx">SVX</span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--accent-soft)] text-[var(--accent)] font-semibold border border-[var(--accent)]/30 ml-1">
                EDGE
              </span>
            </div>
          </div>
          <div className="crumb-live" aria-current="page">
            <span className="pulse-dot on" aria-hidden />
            <span>dns</span>
            <span aria-hidden>/</span>
            <strong>{hereLabel}</strong>
          </div>
        </div>

        <button
          type="button"
          onClick={() => nav('/lookup')}
          className="w-full flex items-center justify-between px-3 py-2 text-xs rounded-[var(--radius)] border border-[var(--border)] bg-[var(--bg-elevated)] text-[var(--muted)] hover:text-[var(--text)] hover:border-[var(--border-strong)] transition-all"
          title="Press Ctrl+K or Cmd+K to search"
        >
          <span className="flex items-center gap-2">
            <MagnifyingGlass size={14} weight="bold" />
            <span>Quick Lookup…</span>
          </span>
          <kbd className="px-1.5 py-0.5 text-[10px] font-mono rounded bg-[var(--bg-panel)] border border-[var(--border)] text-[var(--muted)]">
            ⌘K
          </kbd>
        </button>

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

        <div className="shell-user space-y-2.5 text-xs pt-3 border-t border-[var(--border)]">
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
            <div className="text-[var(--muted)] px-1 mono text-[11px]" title="Deployed DNS build">
              {release}
            </div>
          ) : null}
          {me?.auth_required ? (
            <div className="space-y-2">
              <div className="flex items-center gap-2 px-1 py-1 rounded bg-[var(--bg-panel)] border border-[var(--border)]">
                <div className="w-6 h-6 rounded-full bg-[var(--accent)] text-black font-semibold flex items-center justify-center text-xs">
                  {String(me.name || 'A').slice(0, 1).toUpperCase()}
                </div>
                <div className="truncate">
                  <div className="text-[var(--text)] font-medium leading-none truncate">{me.name}</div>
                  <div className="text-[10px] text-[var(--accent)] uppercase font-mono mt-0.5">{me.role}</div>
                </div>
              </div>
              <button type="button" onClick={logout} className="btn btn-secondary w-full text-xs">
                Log out
              </button>
            </div>
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
