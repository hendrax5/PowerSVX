import React from 'react'

export class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error }
  }

  componentDidCatch(error, errorInfo) {
    console.error('PowerSVX UI Error:', error, errorInfo)
  }

  handleReload = () => {
    try {
      localStorage.removeItem('powersvx_token')
    } catch {
      /* ignore */
    }
    window.location.reload()
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen flex items-center justify-center p-6 bg-[var(--bg,#12110f)] text-[var(--text,#f5f4ef)]">
          <div className="panel max-w-md w-full p-6 text-center space-y-4 border border-[var(--border,#2b2823)]">
            <div className="w-12 h-12 mx-auto rounded-full bg-[var(--danger-bg,rgba(239,68,68,0.1))] text-[var(--danger,#ef4444)] flex items-center justify-center text-xl font-bold">
              !
            </div>
            <div className="space-y-1">
              <h2 className="text-base font-semibold">Tampilan UI Terkendala Cache / Sesi</h2>
              <p className="text-xs text-[var(--muted,#8c857b)]">
                Terjadi pembaruan versi atau chunk cache browser tidak sesuai.
              </p>
            </div>
            {this.state.error?.message && (
              <pre className="p-2.5 bg-black/40 rounded text-left text-xs mono text-[var(--danger,#ef4444)] overflow-x-auto">
                {this.state.error.message}
              </pre>
            )}
            <div className="flex gap-2 justify-center pt-2">
              <button
                type="button"
                className="btn btn-primary text-xs"
                onClick={this.handleReload}
              >
                Muat Ulang & Bersihkan Cache
              </button>
            </div>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}
