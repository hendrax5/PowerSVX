package secondary

import (
	"path/filepath"
	"testing"

	"github.com/powersvx/powersvx/internal/authoritative"
)

func TestUpsertListDeletePersist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secondary-zones.json")
	auth := authoritative.NewStore()
	m := New(path, auth, nil)

	if err := m.Upsert(Zone{Name: "Slave.Example.com", Masters: []string{"10.0.0.1"}}); err != nil {
		t.Fatal(err)
	}
	list := m.List()
	if len(list) != 1 || list[0].Name != "slave.example.com." || list[0].Masters[0] != "10.0.0.1:53" {
		t.Fatalf("list=%+v", list)
	}
	if !m.Has("slave.example.com") {
		t.Fatal("Has expected true")
	}

	m2 := New(path, auth, nil)
	if err := m2.Load(); err != nil {
		t.Fatal(err)
	}
	if len(m2.List()) != 1 {
		t.Fatalf("reload got %d", len(m2.List()))
	}
	if !m2.Delete("slave.example.com") {
		t.Fatal("delete failed")
	}
	if m2.Has("slave.example.com") {
		t.Fatal("still present")
	}
}

func TestNormalizeRejectsEmptyMasters(t *testing.T) {
	_, err := normalizeZones([]Zone{{Name: "a.example", Masters: nil}})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestHandleNotifyUnknown(t *testing.T) {
	m := New("", authoritative.NewStore(), nil)
	if m.HandleNotify("unknown.example") {
		t.Fatal("unknown should not trigger")
	}
}
