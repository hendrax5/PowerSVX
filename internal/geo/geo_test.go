package geo

import "testing"

func TestOverride(t *testing.T) {
	r, err := New(true, "", "default")
	if err != nil {
		// open error only when path set
		t.Fatal(err)
	}
	r.SetOverride("1.2.3.4", Info{Country: "ID", Continent: "AS"})
	info := r.Lookup("1.2.3.4")
	if info.Tag != "ID" || info.Country != "ID" {
		t.Fatalf("%+v", info)
	}
	unk := r.Lookup("8.8.8.8")
	if unk.Tag != "default" {
		t.Fatalf("%+v", unk)
	}
}

func TestDisabled(t *testing.T) {
	r, _ := New(false, "", "default")
	if r.Lookup("1.2.3.4").Tag != "default" {
		t.Fatal("expected default")
	}
}
