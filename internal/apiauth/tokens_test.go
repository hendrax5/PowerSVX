package apiauth

import "testing"

func TestTokenStoreLifecycle(t *testing.T) {
	dir := t.TempDir()
	st, err := NewTokenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	meta, plain, err := st.Create("ci-deploy", "operator", 30)
	if err != nil || plain == "" || meta.ID == "" {
		t.Fatalf("Create failed: meta=%+v err=%v", meta, err)
	}
	p, ok := st.Resolve(plain)
	if !ok || p.Role != RoleOperator {
		t.Fatalf("Resolve failed: ok=%v p=%+v", ok, p)
	}
	if _, ok := st.Resolve("psvx_wrong"); ok {
		t.Fatal("wrong token accepted")
	}
	// Reload from disk and verify hash persistence (no plaintext saved)
	st2, err := NewTokenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if p2, ok := st2.Resolve(plain); !ok || p2.Role != RoleOperator {
		t.Fatalf("Reloaded TokenStore failed resolve: ok=%v p=%+v", ok, p2)
	}
	if err := st2.Revoke(meta.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := st2.Resolve(plain); ok {
		t.Fatal("revoked token still accepted")
	}
}
