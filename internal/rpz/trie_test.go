package rpz

import "testing"

func TestTrieExactAndWildcard(t *testing.T) {
	tr := newTrie()
	tr.insert("bad.example.com.", ActionNXDOMAIN)
	tr.insert("*.ads.test.", ActionNXDOMAIN)

	if a, ok := tr.lookup("bad.example.com."); !ok || a != ActionNXDOMAIN {
		t.Fatalf("exact: %v %v", a, ok)
	}
	if a, ok := tr.lookup("tracker.ads.test."); !ok || a != ActionNXDOMAIN {
		t.Fatalf("wild: %v %v", a, ok)
	}
	if a, ok := tr.lookup("a.b.ads.test."); !ok || a != ActionNXDOMAIN {
		t.Fatalf("nested wild: %v %v", a, ok)
	}
	if _, ok := tr.lookup("ads.test."); ok {
		t.Fatal("bare suffix should not match *.")
	}
	if _, ok := tr.lookup("good.example.com."); ok {
		t.Fatal("should miss")
	}
}

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	tr := newTrie()
	tr.insert("youporn.com.", ActionNXDOMAIN)
	tr.insert("*.blocked.test.", ActionNODATA)
	pols := []PolicyConfig{{Name: "t", Source: "https://example/list", Format: "hosts", Action: ActionNXDOMAIN}}
	fp := PoliciesFingerprint(pols)
	if err := s.ReplaceAll(tr, fp); err != nil {
		t.Fatal(err)
	}
	got, err := s.Fingerprint()
	if err != nil || got != fp {
		t.Fatalf("fp %q %v", got, err)
	}
	loaded, n, err := s.LoadTrie()
	if err != nil {
		t.Fatal(err)
	}
	if n < 2 {
		t.Fatalf("count %d", n)
	}
	if a, ok := loaded.lookup("youporn.com."); !ok || a != ActionNXDOMAIN {
		t.Fatalf("youporn: %v %v", a, ok)
	}
	if a, ok := loaded.lookup("x.blocked.test."); !ok || a != ActionNODATA {
		t.Fatalf("wild: %v %v", a, ok)
	}
}
