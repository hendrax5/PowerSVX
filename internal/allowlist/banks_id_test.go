package allowlist

import "testing"

func TestOfficialBankName(t *testing.T) {
	if !OfficialBankName("www.bca.co.id") || !OfficialBankName("bca.co.id.") {
		t.Fatal("bca")
	}
	if !OfficialBankName("brimo.bri.co.id") {
		t.Fatal("official brimo host")
	}
	if OfficialBankName("brimo.id") {
		t.Fatal("brimo.id is Komdigi-listed phishing, not official")
	}
	if OfficialBankName("bca.co.id.layanan.promo-upgrade.info") {
		t.Fatal("phishing must not inherit bca.co.id")
	}
	// Sample across BUKU / digital / BPD — not BCA-only.
	for _, n := range []string{
		"ib.bri.co.id", "livin.mandiri.co.id", "www.bni.co.id", "www.btn.co.id",
		"www.bsi.co.id", "www.bankbjb.co.id", "www.bankdki.co.id", "www.bankjatim.co.id",
		"www.seabank.co.id", "www.jago.com", "www.aladinbank.id", "www.digibank.co.id",
		"www.nobubank.com", "www.bankraya.co.id", "api.blubybcai.com",
	} {
		if !OfficialBankName(n) {
			t.Fatalf("expected official: %s", n)
		}
	}
}

func TestOfficialBankApexesCoverage(t *testing.T) {
	if len(OfficialBankApexes()) < 80 {
		t.Fatalf("expected broad ID bank list, got %d", len(OfficialBankApexes()))
	}
}

func TestBankSafeRPZAction(t *testing.T) {
	if BankSafeRPZAction("judi.example", "redirect") != "redirect" {
		t.Fatal("generic redirect stays")
	}
	if BankSafeRPZAction("brimo.id", "redirect") != "nxdomain" {
		t.Fatal("bank-like sinkhole must become nxdomain")
	}
	if BankSafeRPZAction("www.bca.co.id", "redirect") != "pass" {
		t.Fatal("official bank must pass")
	}
}

func TestBankLikeName(t *testing.T) {
	if !BankLikeName("brimo.id") || !BankLikeName("bca.co.id.prioritas.aktivasi.net") {
		t.Fatal("lookalikes")
	}
	if BankLikeName("google.com") {
		t.Fatal("unrelated")
	}
}

func TestAllowsBuiltinOfficial(t *testing.T) {
	var l *List
	if !l.Allows("api.livin.co.id") {
		t.Fatal("nil list still allows official banks")
	}
	l = New("")
	if !l.Allows("ib.bri.co.id") {
		t.Fatal("empty list still allows official banks")
	}
	if l.Allows("brimo.id") {
		t.Fatal("must not allow phishing apex")
	}
}
