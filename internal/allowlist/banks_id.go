package allowlist

import "strings"

// Official Indonesian bank / e-channel apexes (commercial, syariah, BPD, digital).
// Subdomains inherit via suffix match.
// Intentionally excludes brand-only phishing hosts (e.g. brimo.id) that Komdigi lists.
var officialBankApexes = []string{
	// Big-4 + common e-channels
	"bca.co.id",
	"klikbca.com",
	"blubybcai.com",
	"mybca.com",
	"bankmandiri.co.id",
	"mandiri.co.id",
	"livin.co.id",
	"bri.co.id",
	"bni.co.id",
	"btn.co.id",
	"btpn.com",
	"jenius.co.id",
	"smbc.co.id",

	// Foreign / JV retail in Indonesia
	"cimb.co.id",
	"cimbniaga.co.id",
	"permata.co.id",
	"danamon.co.id",
	"ocbc.id",
	"ocbcnisp.co.id",
	"maybank.co.id",
	"uob.co.id",
	"hsbc.co.id",
	"standardchartered.co.id",
	"sc.com",
	"dbs.com",
	"digibank.co.id",
	"citibank.co.id",
	"panin.co.id",
	"paninbanksyariah.co.id",
	"mega.co.id",
	"bankmega.com",
	"allobank.com",
	"allobank.co.id",
	"muamalat.co.id",
	"bsi.co.id",
	"bankbsi.co.id",
	"bukopin.co.id",
	"kbbukopin.com",
	"banksinarmas.com",
	"bankmayapada.com",
	"commbank.co.id",
	"qnb.co.id",
	"ctbcbank.co.id",
	"bankofchina.co.id",
	"mizuhobank.co.id",
	"bankmufg.co.id",
	"bankwoorisaudara.co.id",
	"shinhan.co.id",
	"icbc.co.id",
	"hanabank.co.id",
	"linebank.co.id",
	"bankbba.co.id",
	"arthagraha.com",
	"bankvictoria.co.id",
	"bankmas.co.id",
	"mncbank.co.id",
	"bankganesha.co.id",
	"bankina.co.id",
	"bjj.co.id",
	"bankharda.co.id",
	"banksampoerna.com",
	"nobubank.com",
	"amarbank.co.id",
	"aladinbank.id",
	"bankraya.co.id",
	"krom.id",
	"hibank.co.id",
	"bankmantap.co.id",
	"sbiindo.com",
	"resonaperdania.com",
	"bnpparibas.co.id",
	"jtrustbank.co.id",
	"bankindex.co.id",
	"bankfama.co.id",
	"banksaqu.com",
	"seabank.co.id",
	"bankjago.com",
	"jago.com",
	"superbank.id",
	"neobank.co.id",
	"bankneo.co.id",
	"bankneocommerce.co.id",

	// BPD / regional development banks
	"bankbjb.co.id",
	"bankdki.co.id",
	"bankjatim.co.id",
	"bankjateng.co.id",
	"bpddiy.co.id",
	"bpdbali.co.id",
	"banknagari.co.id",
	"banksumut.co.id",
	"banksumut.com",
	"banksumselbabel.com",
	"banklampung.co.id",
	"bankbengkulu.co.id",
	"bankjambi.co.id",
	"bankriau.co.id",
	"bankkepri.co.id",
	"bankkalsel.co.id",
	"bankkalbar.co.id",
	"bankkalteng.co.id",
	"bankaltimtara.co.id",
	"banksulselbar.co.id",
	"banksulutgo.co.id",
	"banksulteng.co.id",
	"banksultra.co.id",
	"bankntbsyariah.co.id",
	"bankntb.co.id",
	"bankntt.co.id",
	"bankmalukumalut.co.id",
	"bankpapua.co.id",
	"bankaceh.co.id",
}

// Bank-brand tokens used by mobile apps as DNS-hijack probes (often in TrustPositif).
// A sinkhole A-record (Komdigi landing IP) makes the app refuse while the website still works.
// Keep tokens specific enough to avoid unrelated domains.
var bankLikeTokens = []string{
	"bca.co.id",
	"klikbca.",
	"blubybcai.",
	"mybca.",
	"mandiri.co.id",
	"livin.co.id",
	"bri.co.id",
	"brimo.",
	"bni.co.id",
	"btn.co.id",
	"jenius.",
	"permata.co.id",
	"danamon.co.id",
	"cimb.co.id",
	"cimbniaga.",
	"ocbc.id",
	"ocbcnisp.",
	"seabank.",
	"superbank.id",
	"bankjago.",
	"jago.com",
	"digibank.",
	"allobank.",
	"aladinbank.",
	"nobubank.",
	"krom.id",
	"bankraya.",
	"bsi.co.id",
	"muamalat.",
	"maybank.co.id",
	"uob.co.id",
	"hsbc.co.id",
	"panin.co.id",
	"mega.co.id",
	"bukopin.",
	"banksinarmas.",
	"neobank.",
	"bankneo.",
	"linebank.",
	"hanabank.",
	"smbc.co.id",
	"btpn.com",
}

// OfficialBankApexes returns a copy of official Indonesian bank apex names.
func OfficialBankApexes() []string {
	out := make([]string, len(officialBankApexes))
	copy(out, officialBankApexes)
	return out
}

// OfficialBankName reports whether qname is an official bank host (or subdomain).
func OfficialBankName(qname string) bool {
	n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(qname), "."))
	if n == "" {
		return false
	}
	for _, apex := range officialBankApexes {
		if n == apex || strings.HasSuffix(n, "."+apex) {
			return true
		}
	}
	return false
}

// BankLikeName reports names that look like Indonesian banking (official or phishing lookalikes).
func BankLikeName(qname string) bool {
	n := strings.ToLower(qname)
	for _, k := range bankLikeTokens {
		if strings.Contains(n, k) {
			return true
		}
	}
	return false
}

// BankSafeRPZAction keeps Komdigi redirect for generic blocks, but never
// synthesizes a sinkhole A-record for bank-branded names (apps treat that as hijack).
func BankSafeRPZAction(qname, action string) string {
	if action != "redirect" {
		return action
	}
	if OfficialBankName(qname) {
		return "pass"
	}
	if BankLikeName(qname) {
		return "nxdomain"
	}
	return action
}
