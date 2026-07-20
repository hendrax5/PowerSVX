package rpz

import "testing"

func TestTrieExactAndWildcard(t *testing.T) {
	tr := newTrie()
	tr.insert("bad.example.com.", ActionNXDOMAIN)
	tr.insert("*.ads.test.", ActionNXDOMAIN)

	if h, ok := tr.lookup("bad.example.com."); !ok || h.Action != ActionNXDOMAIN {
		t.Fatalf("exact: %v %v", h, ok)
	}
	if h, ok := tr.lookup("tracker.ads.test."); !ok || h.Action != ActionNXDOMAIN {
		t.Fatalf("wild: %v %v", h, ok)
	}
	if h, ok := tr.lookup("a.b.ads.test."); !ok || h.Action != ActionNXDOMAIN {
		t.Fatalf("nested wild: %v %v", h, ok)
	}
	if _, ok := tr.lookup("ads.test."); ok {
		t.Fatal("bare suffix should not match *.")
	}
	if _, ok := tr.lookup("good.example.com."); ok {
		t.Fatal("should miss")
	}
}

func TestTrieRedirectAndCNAME(t *testing.T) {
	tr := newTrie()
	tr.insertHit("sink.example.", Hit{Action: ActionRedirect, Target: "10.0.0.9"})
	tr.insertHit("*.ads.block.", Hit{Action: ActionCNAME, Target: "landing.corp.local"})

	h, ok := tr.lookup("sink.example.")
	if !ok || h.Action != ActionRedirect || h.Target != "10.0.0.9" {
		t.Fatalf("redirect: %+v %v", h, ok)
	}
	h, ok = tr.lookup("x.ads.block.")
	if !ok || h.Action != ActionCNAME || h.Target != "landing.corp.local" {
		t.Fatalf("cname: %+v %v", h, ok)
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
	tr.insertHit("land.me.", Hit{Action: ActionRedirect, Target: "192.0.2.1"})
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
	if n < 3 {
		t.Fatalf("count %d", n)
	}
	if h, ok := loaded.lookup("youporn.com."); !ok || h.Action != ActionNXDOMAIN {
		t.Fatalf("youporn: %v %v", h, ok)
	}
	if h, ok := loaded.lookup("x.blocked.test."); !ok || h.Action != ActionNODATA {
		t.Fatalf("wild: %v %v", h, ok)
	}
	if h, ok := loaded.lookup("land.me."); !ok || h.Action != ActionRedirect || h.Target != "192.0.2.1" {
		t.Fatalf("redirect: %+v %v", h, ok)
	}
}
