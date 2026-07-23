import { createContext, useContext } from 'react'

export const AuthCtx = createContext({
  me: null,
  refresh: async () => {},
  canWrite: true,
  isAdmin: true,
  loading: false,
})

export function useAuth() {
  return useContext(AuthCtx)
}
