import { createContext, useContext, useState } from 'react'

const LANG_KEY = 'powersvx_lang'

const dict = {
  en: {
    'nav.control_plane': 'Control Plane',
    'nav.dashboard': 'Dashboard',
    'nav.domains': 'DNS & Filtering',
    'nav.lookup': 'DNS Client & Trace',
    'nav.cache': 'Cache & Purge',
    'nav.security': 'Security & Bans',
    'nav.observability': 'Observability',
    'nav.analytics': 'Live Stream & Grafana',
    'nav.audit': 'Audit Logs',
    'nav.system': 'System & Routing',
    'nav.settings': 'Settings & Tokens',
    'nav.terminal': 'Live Terminal',
    'shell.quick_lookup': 'Quick Lookup…',
    'shell.logout': 'Log out',
    'shell.open_access': 'Open access',
    'shell.light_mode': 'Light mode',
    'shell.dark_mode': 'Dark mode',
    'update.title': 'Update available',
    'update.sub': 'Server has been redeployed. Reload for the latest UI.',
    'update.reload': 'Reload now',
    'update.later': 'Later',
    'error.chunk_title': 'New version / cache update detected',
    'error.title': 'Interface render error',
    'error.chunk_sub': 'Your browser cached an older asset bundle. Reload to update.',
    'error.sub': 'A UI component encountered an unexpected error.',
    'error.reload': 'Reload Page',
    'error.reset': 'Reset Session & Cache',
  },
  id: {
    'nav.control_plane': 'Control Plane',
    'nav.dashboard': 'Dasbor Utama',
    'nav.domains': 'Zona DNS & Filter',
    'nav.lookup': 'Klien DNS & Trace',
    'nav.cache': 'Cache & Purge',
    'nav.security': 'Keamanan & Blokir IP',
    'nav.observability': 'Observabilitas',
    'nav.analytics': 'Live Stream & Grafana',
    'nav.audit': 'Log Audit',
    'nav.system': 'Sistem & Routing',
    'nav.settings': 'Pengaturan & Token',
    'nav.terminal': 'Terminal Langsung',
    'shell.quick_lookup': 'Cek Domain Cepat…',
    'shell.logout': 'Keluar',
    'shell.open_access': 'Akses Terbuka',
    'shell.light_mode': 'Mode Terang',
    'shell.dark_mode': 'Mode Gelap',
    'update.title': 'Pembaruan tersedia',
    'update.sub': 'Server baru saja di-deploy ulang. Muat ulang untuk UI terbaru.',
    'update.reload': 'Muat ulang',
    'update.later': 'Nanti',
    'error.chunk_title': 'Pembaruan Versi / Cache Terdeteksi',
    'error.title': 'Terjadi Kendala pada Tampilan UI',
    'error.chunk_sub': 'Browser masih menyimpan file aset versi lama. Muat ulang untuk memperbarui.',
    'error.sub': 'Komponen antarmuka mengalami kendala saat merender data.',
    'error.reload': 'Muat Ulang Halaman',
    'error.reset': 'Reset Sesi & Cache',
  },
}

const I18nCtx = createContext({
  lang: 'en',
  setLang: () => {},
  t: (k) => k,
})

export function I18nProvider({ children }) {
  const [lang, setLangState] = useState(() => {
    try {
      const saved = localStorage.getItem(LANG_KEY)
      if (saved === 'id' || saved === 'en') return saved
    } catch {
      /* ignore */
    }
    return 'en'
  })

  const setLang = (next) => {
    const val = next === 'id' ? 'id' : 'en'
    setLangState(val)
    try {
      localStorage.setItem(LANG_KEY, val)
    } catch {
      /* ignore */
    }
  }

  const t = (key) => dict[lang]?.[key] || dict.en[key] || key

  return <I18nCtx.Provider value={{ lang, setLang, t }}>{children}</I18nCtx.Provider>
}

export function useI18n() {
  return useContext(I18nCtx)
}
