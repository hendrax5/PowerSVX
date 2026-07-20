package dnssec

import (
	"crypto"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/config"
)

// Signer signs authoritative answers for zones with on-disk KSK/ZSK (ECDSAP256SHA256).
type Signer struct {
	dir   string
	mu    sync.RWMutex
	cache map[string]*zoneKeys
}

type zoneKeys struct {
	ZSK     *dns.DNSKEY
	ZSKPriv crypto.Signer
	KSK     *dns.DNSKEY
	KSKPriv crypto.Signer
}

type keyFile struct {
	Role      string `json:"role"` // zsk|ksk
	Flags     uint16 `json:"flags"`
	Algorithm uint8  `json:"algorithm"`
	Public    string `json:"public"`  // DNSKEY.PublicKey
	Private   string `json:"private"` // miekg PrivateKeyString
}

func NewSigner(dir string) *Signer {
	if dir == "" {
		dir = "./data/dnssec"
	}
	return &Signer{dir: dir, cache: map[string]*zoneKeys{}}
}

func (s *Signer) Enabled(zone string) bool {
	if s == nil {
		return false
	}
	zone = config.NormalizeName(zone)
	_, err := s.load(zone)
	return err == nil
}

func (s *Signer) Ensure(zone string) error {
	if s == nil {
		return fmt.Errorf("signer nil")
	}
	zone = config.NormalizeName(zone)
	if _, err := s.load(zone); err == nil {
		return nil
	}
	return s.generate(zone)
}

func (s *Signer) DS(zone string) (*dns.DS, error) {
	zk, err := s.load(config.NormalizeName(zone))
	if err != nil {
		return nil, err
	}
	return zk.KSK.ToDS(dns.SHA256), nil
}

func (s *Signer) DNSKEYs(zone string) []dns.RR {
	zk, err := s.load(config.NormalizeName(zone))
	if err != nil {
		return nil
	}
	return []dns.RR{zk.ZSK, zk.KSK}
}

// SignResponse adds RRSIGs (and DNSKEY answers) when DO is set or qtype is DNSKEY.
func (s *Signer) SignResponse(zone string, req, resp *dns.Msg) {
	if s == nil || resp == nil {
		return
	}
	zone = config.NormalizeName(zone)
	zk, err := s.load(zone)
	if err != nil {
		return
	}
	wantDO := false
	if req != nil {
		if opt := req.IsEdns0(); opt != nil && opt.Do() {
			wantDO = true
		}
		if len(req.Question) > 0 && req.Question[0].Qtype == dns.TypeDNSKEY {
			wantDO = true
			resp.Answer = s.DNSKEYs(zone)
			resp.Rcode = dns.RcodeSuccess
		}
	}
	if !wantDO {
		return
	}
	now := time.Now().UTC()
	inc := now.Add(30 * 24 * time.Hour)

	signSet := func(rrs []dns.RR, priv crypto.Signer, key *dns.DNSKEY) {
		if len(rrs) == 0 || priv == nil || key == nil {
			return
		}
		sig := &dns.RRSIG{
			Hdr: dns.RR_Header{
				Name:   rrs[0].Header().Name,
				Rrtype: dns.TypeRRSIG,
				Class:  dns.ClassINET,
				Ttl:    rrs[0].Header().Ttl,
			},
			TypeCovered: rrs[0].Header().Rrtype,
			Algorithm:   key.Algorithm,
			Labels:      uint8(dns.CountLabel(rrs[0].Header().Name)),
			OrigTtl:     rrs[0].Header().Ttl,
			Expiration:  uint32(inc.Unix()),
			Inception:   uint32(now.Unix()),
			KeyTag:      key.KeyTag(),
			SignerName:  zone,
		}
		if err := sig.Sign(priv, rrs); err != nil {
			return
		}
		resp.Answer = append(resp.Answer, sig)
	}

	if len(req.Question) > 0 && req.Question[0].Qtype == dns.TypeDNSKEY {
		keys := []dns.RR{zk.ZSK, zk.KSK}
		resp.Answer = keys
		signSet(keys, zk.KSKPriv, zk.KSK)
		return
	}

	sets := groupAuthAnswers(resp.Answer)
	for _, set := range sets {
		signSet(set, zk.ZSKPriv, zk.ZSK)
	}
}

func groupAuthAnswers(rrs []dns.RR) [][]dns.RR {
	order := []string{}
	m := map[string][]dns.RR{}
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			continue
		}
		k := dns.CanonicalName(rr.Header().Name) + "/" + dns.TypeToString[rr.Header().Rrtype]
		if _, ok := m[k]; !ok {
			order = append(order, k)
		}
		m[k] = append(m[k], rr)
	}
	out := make([][]dns.RR, 0, len(order))
	for _, k := range order {
		out = append(out, m[k])
	}
	return out
}

func (s *Signer) zoneDir(zone string) string {
	safe := strings.TrimSuffix(zone, ".")
	return filepath.Join(s.dir, safe)
}

func (s *Signer) load(zone string) (*zoneKeys, error) {
	s.mu.RLock()
	if zk, ok := s.cache[zone]; ok {
		s.mu.RUnlock()
		return zk, nil
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	if zk, ok := s.cache[zone]; ok {
		return zk, nil
	}
	dir := s.zoneDir(zone)
	zsk, zpriv, err := readKey(filepath.Join(dir, "zsk.json"), zone)
	if err != nil {
		return nil, err
	}
	ksk, kpriv, err := readKey(filepath.Join(dir, "ksk.json"), zone)
	if err != nil {
		return nil, err
	}
	zk := &zoneKeys{ZSK: zsk, ZSKPriv: zpriv, KSK: ksk, KSKPriv: kpriv}
	s.cache[zone] = zk
	return zk, nil
}

func (s *Signer) generate(zone string) error {
	dir := s.zoneDir(zone)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	zsk, zpriv, err := makeKey(zone, 256)
	if err != nil {
		return err
	}
	ksk, kpriv, err := makeKey(zone, 257)
	if err != nil {
		return err
	}
	if err := writeKey(filepath.Join(dir, "zsk.json"), "zsk", zsk, zpriv); err != nil {
		return err
	}
	if err := writeKey(filepath.Join(dir, "ksk.json"), "ksk", ksk, kpriv); err != nil {
		return err
	}
	s.mu.Lock()
	s.cache[zone] = &zoneKeys{ZSK: zsk, ZSKPriv: zpriv, KSK: ksk, KSKPriv: kpriv}
	s.mu.Unlock()
	return nil
}

func makeKey(zone string, flags uint16) (*dns.DNSKEY, crypto.Signer, error) {
	key := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   zone,
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Flags:     flags,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	priv, err := key.Generate(256)
	if err != nil {
		return nil, nil, err
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("private key is not crypto.Signer")
	}
	return key, signer, nil
}

func writeKey(path string, role string, key *dns.DNSKEY, priv crypto.Signer) error {
	kf := keyFile{
		Role:      role,
		Flags:     key.Flags,
		Algorithm: key.Algorithm,
		Public:    key.PublicKey,
		Private:   key.PrivateKeyString(priv),
	}
	b, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func readKey(path, zone string) (*dns.DNSKEY, crypto.Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var kf keyFile
	if err := json.Unmarshal(b, &kf); err != nil {
		return nil, nil, err
	}
	key := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   zone,
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Flags:     kf.Flags,
		Protocol:  3,
		Algorithm: kf.Algorithm,
		PublicKey: kf.Public,
	}
	priv, err := key.NewPrivateKey(kf.Private)
	if err != nil {
		return nil, nil, err
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("private key is not crypto.Signer")
	}
	return key, signer, nil
}
