package apiauth

import (
	"context"
	"net/http"
	"strings"

	"github.com/powersvx/powersvx/internal/config"
)

const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleReadonly = "readonly"
)

type Principal struct {
	Name string
	Role string
}

type ctxKey int

const principalKey ctxKey = 1

func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey, p)
}

func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey).(Principal)
	return p, ok
}

// ResolveToken maps a bearer token to a principal using multi-token table or legacy api_token (admin).
func ResolveToken(cfg config.APIConfig, token string) (Principal, bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		return Principal{}, false
	}
	for _, t := range cfg.Tokens {
		if t.Token != "" && subtleEqual(t.Token, token) {
			role := strings.ToLower(strings.TrimSpace(t.Role))
			if role == "" {
				role = RoleAdmin
			}
			name := t.Name
			if name == "" {
				name = "token"
			}
			return Principal{Name: name, Role: role}, true
		}
	}
	if cfg.APIToken != "" && subtleEqual(cfg.APIToken, token) {
		return Principal{Name: "default", Role: RoleAdmin}, true
	}
	return Principal{}, false
}

func subtleEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func AllowMethod(role, method string) bool {
	role = strings.ToLower(role)
	switch role {
	case RoleAdmin:
		return true
	case RoleOperator:
		return method == http.MethodGet || method == http.MethodHead ||
			method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch
	case RoleReadonly:
		return method == http.MethodGet || method == http.MethodHead
	default:
		return false
	}
}

// AllowPath further restricts operator (no settings write / no backup restore / no user mgmt).
func AllowPath(role, method, path string) bool {
	if !AllowMethod(role, method) {
		return false
	}
	role = strings.ToLower(role)
	if role == RoleAdmin {
		return true
	}
	if role == RoleReadonly {
		return method == http.MethodGet || method == http.MethodHead
	}
	// operator
	if method == http.MethodGet || method == http.MethodHead {
		return true
	}
	if strings.HasPrefix(path, "/api/v1/settings") {
		return false
	}
	if strings.HasPrefix(path, "/api/v1/conntrack") {
		return false
	}
	if strings.HasPrefix(path, "/api/v1/host/network") {
		return false
	}
	if strings.HasPrefix(path, "/api/v1/terminal") {
		return false
	}
	if strings.HasPrefix(path, "/api/v1/system") {
		return false
	}
	if path == "/api/v1/backup" && method != http.MethodGet {
		return false
	}
	if strings.HasPrefix(path, "/api/v1/auth/users") || strings.HasPrefix(path, "/api/v1/auth/tokens") {
		return false
	}
	return true
}

// AuthRequired reports whether API calls need credentials.
func AuthRequired(authType string) bool {
	switch strings.ToLower(strings.TrimSpace(authType)) {
	case "token", "local":
		return true
	default:
		return false
	}
}
