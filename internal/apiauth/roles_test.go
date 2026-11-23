package apiauth

import (
	"net/http"
	"testing"

	"github.com/powersvx/powersvx/internal/config"
)

func TestResolveAndRBAC(t *testing.T) {
	cfg := config.APIConfig{
		APIToken: "admin-secret",
		Tokens: []config.APITokenTOML{
			{Name: "ro", Token: "ro-secret", Role: RoleReadonly},
			{Name: "op", Token: "op-secret", Role: RoleOperator},
		},
	}
	p, ok := ResolveToken(cfg, "ro-secret")
	if !ok || p.Role != RoleReadonly {
		t.Fatalf("%v %v", p, ok)
	}
	if AllowPath(RoleReadonly, http.MethodPut, "/api/v1/zones") {
		t.Fatal("readonly must not PUT")
	}
	if AllowPath(RoleOperator, http.MethodPut, "/api/v1/settings") {
		t.Fatal("operator must not change settings")
	}
	if AllowPath(RoleOperator, http.MethodPut, "/api/v1/conntrack") {
		t.Fatal("operator must not change conntrack")
	}
	if !AllowPath(RoleOperator, http.MethodGet, "/api/v1/conntrack") {
		t.Fatal("operator may read conntrack status")
	}
	if AllowPath(RoleOperator, http.MethodPost, "/api/v1/backup") {
		t.Fatal("operator must not restore backup")
	}
	if AllowPath(RoleOperator, http.MethodPost, "/api/v1/auth/users") {
		t.Fatal("operator must not manage users")
	}
	if AllowPath(RoleOperator, http.MethodPost, "/api/v1/auth/tokens") {
		t.Fatal("operator must not manage api tokens")
	}
	if AllowPath(RoleOperator, http.MethodPost, "/api/v1/host/network/apply") {
		t.Fatal("operator must not modify host network")
	}
	if AllowPath(RoleOperator, http.MethodPost, "/api/v1/terminal/ws") {
		t.Fatal("operator must not open terminal")
	}
	if AllowPath(RoleOperator, http.MethodPost, "/api/v1/system/restart") {
		t.Fatal("operator must not hit system control")
	}
	if !AllowPath(RoleAdmin, http.MethodDelete, "/api/v1/backup") {
		t.Fatal("admin full access")
	}
	if !AllowPath(RoleOperator, http.MethodPost, "/api/v1/zones") {
		t.Fatal("operator may mutate zones")
	}
}

func TestPasswordRoundTrip(t *testing.T) {
	h, err := HashPassword("s3cret!")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(h, "s3cret!") {
		t.Fatal("check failed")
	}
	if CheckPassword(h, "wrong") {
		t.Fatal("wrong password accepted")
	}
}
