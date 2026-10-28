package api

import (
	"net/http"
	"strings"

	"github.com/powersvx/powersvx/internal/apiauth"
	"github.com/powersvx/powersvx/internal/terminal"
)

func (a *API) handleTerminalWS(w http.ResponseWriter, r *http.Request) {
	authType := strings.ToLower(strings.TrimSpace(a.cfg.API.AuthType))
	if authType == "token" || authType == "local" {
		p, ok := a.resolvePrincipal(r)
		if !ok || p.Role != apiauth.RoleAdmin {
			http.Error(w, "unauthorized: admin role required for live terminal", http.StatusUnauthorized)
			return
		}
	}

	h := terminal.NewHandler()
	h.ServeHTTP(w, r)
}
