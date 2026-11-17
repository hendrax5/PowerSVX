package api

import (
	"net/http"
	"strings"

	"github.com/powersvx/powersvx/internal/apiauth"
	"github.com/powersvx/powersvx/internal/audit"
	"github.com/powersvx/powersvx/internal/terminal"
)

func (a *API) handleTerminalWS(w http.ResponseWriter, r *http.Request) {
	actor, role := "anonymous", ""
	authType := strings.ToLower(strings.TrimSpace(a.cfg.API.AuthType))
	if authType == "token" || authType == "local" {
		p, ok := a.resolvePrincipal(r)
		if !ok {
			if a.audit != nil {
				a.audit.Record(audit.Event{Actor: "unknown", Action: "auth_fail", Path: r.URL.Path, Status: http.StatusUnauthorized})
			}
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		actor, role = p.Name, p.Role
		if p.Role != apiauth.RoleAdmin {
			if a.audit != nil {
				a.audit.Record(audit.Event{Actor: actor, Role: role, Action: "forbidden", Path: r.URL.Path, Status: http.StatusForbidden})
			}
			http.Error(w, "forbidden: admin role required for live terminal", http.StatusForbidden)
			return
		}
	}

	if a.audit != nil {
		a.audit.Record(audit.Event{Actor: actor, Role: role, Action: "TERMINAL_OPEN", Path: r.URL.Path, Status: http.StatusSwitchingProtocols})
	}
	h := terminal.NewHandler()
	h.ServeHTTP(w, r)
}
