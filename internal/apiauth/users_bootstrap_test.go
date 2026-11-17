package apiauth

import "testing"

func TestEnsureBootstrapCreatesAndSyncs(t *testing.T) {
	dir := t.TempDir()
	s, err := NewUserStore(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	created, err := s.EnsureBootstrap("first-pass")
	if err != nil || !created {
		t.Fatalf("create: created=%v err=%v", created, err)
	}
	if _, ok := s.Authenticate("admin", "first-pass"); !ok {
		t.Fatal("first password should work")
	}
	created, err = s.EnsureBootstrap("second-pass")
	if err != nil || created {
		t.Fatalf("sync: created=%v err=%v", created, err)
	}
	if _, ok := s.Authenticate("admin", "first-pass"); ok {
		t.Fatal("old password should not work via env")
	}
	if _, ok := s.Authenticate("admin", "second-pass"); !ok {
		t.Fatal("synced password should work")
	}
}

func TestEnvAdminPasswordIgnoresCRLF(t *testing.T) {
	dir := t.TempDir()
	s, err := NewUserStore(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.SetEnvAdminPassword("live-from-env\r")
	if _, ok := s.Authenticate("admin", "live-from-env"); !ok {
		t.Fatal("env password must work for admin login")
	}
}

func TestNormalizePasswordStripsCR(t *testing.T) {
	if NormalizePassword("secret\r\n") != "secret" {
		t.Fatal(NormalizePassword("secret\r\n"))
	}
}
