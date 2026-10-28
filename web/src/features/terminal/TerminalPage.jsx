import { useEffect, useRef, useState, useCallback } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import '@xterm/xterm/css/xterm.css'
import {
  ArrowsIn,
  ArrowsOut,
  ArrowClockwise,
  Eraser,
  TerminalWindow,
  Play,
  CheckCircle,
  WarningCircle,
  XCircle,
  Cpu,
  HardDrives,
  Network,
} from '@phosphor-icons/react'
import { getToken } from '../../api'
import { useAuth } from '../../auth'
import { ICON_WEIGHT } from '../../ui'

const QUICK_COMMANDS = [
  { label: 'DNS Query (Local)', cmd: 'dig @127.0.0.1 -p 53 google.com +time=2 +tries=1\n', icon: Network },
  { label: 'IP Interfaces', cmd: 'ip -br a\n', icon: Network },
  { label: 'IP Route', cmd: 'ip route show\n', icon: Network },
  { label: 'DNS Services', cmd: "ps aux | grep -E 'powersvx|dnsdist|unbound' | grep -v grep\n", icon: Cpu },
  { label: 'Netplan Status', cmd: 'netplan status\n', icon: Network },
  { label: 'Resolv Conf', cmd: 'cat /etc/resolv.conf\n', icon: Network },
  { label: 'Disk Space', cmd: 'df -h /\n', icon: HardDrives },
  { label: 'System Uptime', cmd: 'uptime\n', icon: Cpu },
]

export default function TerminalPage() {
  const { me, isAdmin } = useAuth()
  const terminalRef = useRef(null)
  const termInstanceRef = useRef(null)
  const fitAddonRef = useRef(null)
  const wsRef = useRef(null)

  const [status, setStatus] = useState('connecting') // 'connecting' | 'connected' | 'disconnected' | 'error'
  const [errorMessage, setErrorMessage] = useState('')
  const [isFullscreen, setIsFullscreen] = useState(false)

  const sendResize = useCallback((cols, rows) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ type: 'resize', cols, rows }))
    }
  }, [])

  const connect = useCallback(() => {
    if (!terminalRef.current) return

    // Clean up previous socket if any
    if (wsRef.current) {
      wsRef.current.onclose = null
      wsRef.current.onerror = null
      wsRef.current.onmessage = null
      wsRef.current.close()
      wsRef.current = null
    }

    setStatus('connecting')
    setErrorMessage('')

    let term = termInstanceRef.current
    let fitAddon = fitAddonRef.current

    if (!term) {
      term = new Terminal({
        cursorBlink: true,
        cursorStyle: 'bar',
        cursorWidth: 2,
        fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', Menlo, Monaco, Consolas, monospace",
        fontSize: 13,
        lineHeight: 1.25,
        scrollback: 5000,
        theme: {
          background: '#0d1117',
          foreground: '#e6edf3',
          cursor: '#f0883e',
          cursorAccent: '#0d1117',
          selectionBackground: 'rgba(240, 136, 62, 0.35)',
          black: '#161b22',
          red: '#ff7b72',
          green: '#7ee787',
          yellow: '#ffa657',
          blue: '#79c0ff',
          magenta: '#d2a8ff',
          cyan: '#56d4dd',
          white: '#f0f6fc',
          brightBlack: '#484f58',
          brightRed: '#ffa198',
          brightGreen: '#56d364',
          brightYellow: '#e3b341',
          brightBlue: '#79c0ff',
          brightMagenta: '#d2a8ff',
          brightCyan: '#39c5cf',
          brightWhite: '#ffffff',
        },
      })

      fitAddon = new FitAddon()
      term.loadAddon(fitAddon)
      term.open(terminalRef.current)

      termInstanceRef.current = term
      fitAddonRef.current = fitAddon

      term.onData((data) => {
        if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
          wsRef.current.send(data)
        }
      })
    }

    try {
      fitAddon.fit()
    } catch {
      /* ignore initial layout measure */
    }

    const token = getToken()
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const wsUrl = `${proto}//${window.location.host}/api/v1/terminal/ws${token ? `?token=${encodeURIComponent(token)}` : ''}`

    const ws = new WebSocket(wsUrl)
    ws.binaryType = 'arraybuffer'
    wsRef.current = ws

    ws.onopen = () => {
      setStatus('connected')
      term.focus()
      try {
        fitAddon.fit()
        sendResize(term.cols, term.rows)
      } catch {
        /* ignore */
      }
    }

    ws.onmessage = (event) => {
      if (event.data instanceof ArrayBuffer) {
        term.write(new Uint8Array(event.data))
      } else {
        term.write(event.data)
      }
    }

    ws.onerror = () => {
      setStatus('error')
      setErrorMessage('WebSocket connection error')
    }

    ws.onclose = (event) => {
      setStatus('disconnected')
      if (event.code !== 1000) {
        setErrorMessage(event.reason || 'Koneksi terputus dari host server')
      }
    }
  }, [sendResize])

  // Handle ResizeObserver & window resize
  useEffect(() => {
    const handleResize = () => {
      if (fitAddonRef.current && termInstanceRef.current) {
        try {
          fitAddonRef.current.fit()
          sendResize(termInstanceRef.current.cols, termInstanceRef.current.rows)
        } catch {
          /* ignore */
        }
      }
    }

    const timer = setTimeout(handleResize, 100)
    window.addEventListener('resize', handleResize)

    let observer = null
    if (terminalRef.current && window.ResizeObserver) {
      observer = new ResizeObserver(() => {
        handleResize()
      })
      observer.observe(terminalRef.current)
    }

    return () => {
      clearTimeout(timer)
      window.removeEventListener('resize', handleResize)
      if (observer) observer.disconnect()
    }
  }, [sendResize, isFullscreen])

  // Initialize terminal on mount
  useEffect(() => {
    connect()

    return () => {
      if (wsRef.current) {
        wsRef.current.onclose = null
        wsRef.current.onerror = null
        wsRef.current.onmessage = null
        wsRef.current.close()
        wsRef.current = null
      }
      if (termInstanceRef.current) {
        termInstanceRef.current.dispose()
        termInstanceRef.current = null
      }
    }
  }, [connect])

  const sendCommand = (cmd) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(cmd)
      if (termInstanceRef.current) {
        termInstanceRef.current.focus()
      }
    }
  }

  const handleClear = () => {
    if (termInstanceRef.current) {
      termInstanceRef.current.clear()
      termInstanceRef.current.focus()
    }
  }

  const toggleFullscreen = () => {
    setIsFullscreen((prev) => !prev)
    setTimeout(() => {
      if (fitAddonRef.current && termInstanceRef.current) {
        try {
          fitAddonRef.current.fit()
          sendResize(termInstanceRef.current.cols, termInstanceRef.current.rows)
          termInstanceRef.current.focus()
        } catch {
          /* ignore */
        }
      }
    }, 150)
  }

  return (
    <div className={`space-y-4 ${isFullscreen ? 'fixed inset-0 z-50 bg-[var(--bg)] p-4 flex flex-col' : ''}`}>
      {/* Header bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[var(--bg-card)] border border-[var(--border)] rounded-xl p-4 shadow-sm">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-[var(--accent)]/10 text-[var(--accent)] flex items-center justify-center shrink-0">
            <TerminalWindow size={22} weight={ICON_WEIGHT} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-semibold text-[var(--fg)] tracking-tight">Live Web Terminal</h1>
              {status === 'connected' && (
                <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  Connected
                </span>
              )}
              {status === 'connecting' && (
                <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium bg-amber-500/10 text-amber-400 border border-amber-500/20">
                  <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-spin" />
                  Connecting...
                </span>
              )}
              {(status === 'disconnected' || status === 'error') && (
                <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium bg-rose-500/10 text-rose-400 border border-rose-500/20">
                  <span className="w-1.5 h-1.5 rounded-full bg-rose-400" />
                  Disconnected
                </span>
              )}
            </div>
            <p className="text-xs text-[var(--muted)]">
              Direct interactive PTY shell running in PowerSVX container runtime (Debian host / bash).
            </p>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2 self-end sm:self-auto">
          <button
            type="button"
            className="btn btn-ghost text-xs flex items-center gap-1.5 px-2.5 py-1.5"
            onClick={handleClear}
            title="Clear screen buffer"
          >
            <Eraser size={14} weight={ICON_WEIGHT} />
            <span>Clear</span>
          </button>

          <button
            type="button"
            className="btn btn-ghost text-xs flex items-center gap-1.5 px-2.5 py-1.5"
            onClick={connect}
            disabled={status === 'connecting'}
            title="Reconnect shell session"
          >
            <ArrowClockwise size={14} weight={ICON_WEIGHT} className={status === 'connecting' ? 'animate-spin' : ''} />
            <span>Reconnect</span>
          </button>

          <button
            type="button"
            className="btn btn-ghost text-xs flex items-center gap-1.5 px-2.5 py-1.5"
            onClick={toggleFullscreen}
            title={isFullscreen ? 'Exit fullscreen' : 'Enter fullscreen'}
          >
            {isFullscreen ? (
              <>
                <ArrowsIn size={14} weight={ICON_WEIGHT} />
                <span>Exit Fullscreen</span>
              </>
            ) : (
              <>
                <ArrowsOut size={14} weight={ICON_WEIGHT} />
                <span>Fullscreen</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Quick Snippets Bar */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-xl p-3 shadow-sm">
        <div className="text-xs font-medium text-[var(--muted)] mb-2 flex items-center justify-between">
          <span>Quick Diagnostics & Commands:</span>
          <span className="hidden sm:inline text-[11px] opacity-75 font-mono">Click snippet to execute</span>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {QUICK_COMMANDS.map((item, idx) => (
            <button
              key={idx}
              type="button"
              className="text-xs font-mono px-2.5 py-1 rounded-lg bg-[var(--bg-subtle)] hover:bg-[var(--accent)]/15 hover:text-[var(--accent)] border border-[var(--border)] hover:border-[var(--accent)]/40 transition-colors flex items-center gap-1.5"
              onClick={() => sendCommand(item.cmd)}
              disabled={status !== 'connected'}
            >
              <item.icon size={12} weight={ICON_WEIGHT} className="opacity-70" />
              <span>{item.label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Terminal Display Container */}
      <div
        className={`bg-[#0d1117] border border-[#30363d] rounded-xl overflow-hidden shadow-xl flex flex-col ${
          isFullscreen ? 'flex-1 min-h-0' : 'h-[620px]'
        }`}
      >
        {/* Terminal Title Bar */}
        <div className="h-8 bg-[#161b22] border-b border-[#30363d] px-3 flex items-center justify-between shrink-0 select-none">
          <div className="flex items-center gap-2">
            <span className="w-3 h-3 rounded-full bg-[#ff5f56]" />
            <span className="w-3 h-3 rounded-full bg-[#ffbd2e]" />
            <span className="w-3 h-3 rounded-full bg-[#27c93f]" />
            <span className="ml-2 font-mono text-xs text-[#8b949e]">powersvx@hostnet1:~#</span>
          </div>
          <div className="text-[11px] font-mono text-[#8b949e] flex items-center gap-3">
            <span>xterm-256color</span>
            <span>UTF-8</span>
          </div>
        </div>

        {/* Terminal Element */}
        <div
          ref={terminalRef}
          className="flex-1 w-full p-2 overflow-hidden focus:outline-none"
          tabIndex={0}
        />
      </div>

      {/* Status Bar / Footer */}
      {status === 'disconnected' && errorMessage && (
        <div className="p-3 bg-rose-500/10 border border-rose-500/20 text-rose-300 rounded-lg text-xs flex items-center gap-2">
          <XCircle size={16} weight={ICON_WEIGHT} className="shrink-0" />
          <span>{errorMessage}</span>
          <button
            type="button"
            className="ml-auto underline hover:text-white"
            onClick={connect}
          >
            Hubungkan ulang
          </button>
        </div>
      )}
    </div>
  )
}
