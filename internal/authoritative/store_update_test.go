package authoritative

import "testing"

func TestUpdateRecord(t *testing.T) {
	s := NewStore()
	s.UpsertZone("example.com")
	s.AddRecord("example.com", Record{Name: "www.example.com", Type: TypeFromString("A"), Content: "1.2.3.4", TTL: 60})
	ok := s.UpdateRecord("example.com", "www.example.com", TypeFromString("A"), Record{
		Name: "www.example.com", Type: TypeFromString("A"), Content: "5.6.7.8", TTL: 120,
	})
	if !ok {
		t.Fatal("update failed")
	}
	recs, _ := s.GetRecords("example.com")
	if len(recs) != 1 || recs[0].Content != "5.6.7.8" || recs[0].TTL != 120 {
		t.Fatalf("%+v", recs)
	}
}
