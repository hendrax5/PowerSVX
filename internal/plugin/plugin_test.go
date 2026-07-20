package plugin

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLuaOnQuery(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "block.lua")
	src := `
function on_query(name, qtype, client_ip)
  if name == "evil.test." then
    return "nxdomain"
  end
  return "continue"
end
`
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := LoadLua(path)
	if err != nil {
		t.Fatal(err)
	}
	if d := h.OnQuery(QueryCtx{Name: "evil.test."}); d != DecisionNXDOMAIN {
		t.Fatalf("want nxdomain got %v", d)
	}
	if d := h.OnQuery(QueryCtx{Name: "ok.test."}); d != DecisionContinue {
		t.Fatalf("want continue got %v", d)
	}
}

func TestLoadDirEmpty(t *testing.T) {
	reg, err := LoadDir(filepath.Join(t.TempDir(), "missing"))
	if err != nil || reg.Len() != 0 {
		t.Fatalf("%v len=%d", err, reg.Len())
	}
}
