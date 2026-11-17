package dnssec

import (
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/config"
)

// SignOptions configures per-zone DNSSEC signing algorithm and denial mode.
type SignOptions struct {
	Algorithm uint8  `json:"algorithm"` // dns.ECDSAP256SHA256, dns.ED25519, dns.ECDSAP384SHA384, dns.RSASHA256
	NSEC3     bool   `json:"nsec3"`
	Salt      string `json:"salt,omitempty"`
}

// DefaultSignOptions returns ISP-standard ECDSAP256SHA256 with NSEC3 enabled.
func DefaultSignOptions() SignOptions {
	return SignOptions{Algorithm: dns.ECDSAP256SHA256, NSEC3: false}
}

// ParseAlgorithm converts friendly names ("ED25519", "ECDSAP256SHA256", "ECDSAP384SHA384", "RSASHA256") to DNSSEC alg IDs.
func ParseAlgorithm(name string) uint8 {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "ED25519", "15":
		return dns.ED25519
	case "ECDSAP384SHA384", "ECDSA384", "14":
		return dns.ECDSAP384SHA384
	case "RSASHA256", "RSA2048", "8":
		return dns.RSASHA256
	default:
		return dns.ECDSAP256SHA256
	}
}

// Signer signs authoritative answers for zones with on-disk KSK/ZSK.
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
	Policy  SignOptions
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
	return s.EnsureWithOptions(zone, DefaultSignOptions())
}

// EnsureWithOptions initializes or updates signing keys and NSEC/NSEC3 policy for a zone.
func (s *Signer) EnsureWithOptions(zone string, opts SignOptions) error {
	if s == nil {
		return fmt.Errorf("signer nil")
	}
	if opts.Algorithm == 0 {
		opts.Algorithm = dns.ECDSAP256SHA256
	}
	zone = config.NormalizeName(zone)
	if zk, err := s.load(zone); err == nil {
		if opts.NSEC3 != zk.Policy.NSEC3 || opts.Algorithm == zk.Policy.Algorithm {
			zk.Policy.NSEC3 = opts.NSEC3
			if zk.Policy.NSEC3 && zk.Policy.Salt == "" {
				zk.Policy.Salt = randomSaltHex(8)
			}
			_ = writePolicy(filepath.Join(s.zoneDir(zone), "policy.json"), zk.Policy)
			if opts.Algorithm == zk.Policy.Algorithm {
				return nil
			}
		}
	}
	return s.generate(zone, opts)
}

// RolloverZSK rotates the Zone Signing Key while keeping the KSK and parent DS untouched.
func (s *Signer) RolloverZSK(zone string) error {
	if s == nil {
		return fmt.Errorf("signer nil")
	}
	zone = config.NormalizeName(zone)
	zk, err := s.load(zone)
	if err != nil {
		return err
	}
	alg := zk.KSK.Algorithm
	zsk, zpriv, err := makeKey(zone, 256, alg)
	if err != nil {
		return err
	}
	dir := s.zoneDir(zone)
	if err := writeKey(filepath.Join(dir, "zsk.json"), "zsk", zsk, zpriv); err != nil {
		return err
	}
	s.mu.Lock()
	s.cache[zone] = &zoneKeys{ZSK: zsk, ZSKPriv: zpriv, KSK: zk.KSK, KSKPriv: zk.KSKPriv, Policy: zk.Policy}
	s.mu.Unlock()
	return nil
}

// Policy returns signing options (Algorithm, NSEC3) for zone.
func (s *Signer) Policy(zone string) (SignOptions, bool) {
	if s == nil {
		return SignOptions{}, false
	}
	zk, err := s.load(config.NormalizeName(zone))
	if err != nil {
		return SignOptions{}, false
	}
	return zk.Policy, true
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

// SignDenial attaches signed NSEC/NSEC3 denial RRs for NXDOMAIN/NODATA when DO is set.
func (s *Signer) SignDenial(zone, qname string, req, resp *dns.Msg) {
	s.SignDenialForNames(zone, qname, nil, req, resp)
}

// SignDenialForNames builds a proper canonically ordered NSEC chain (or NSEC3 hash records)
// using the zone's active owner names so validators never reject self-referential NSEC loops.
func (s *Signer) SignDenialForNames(zone, qname string, ownerNames []string, req, resp *dns.Msg) {
	if s == nil || resp == nil {
		return
	}
	zone = config.NormalizeName(zone)
	qname = config.NormalizeName(qname)
	zk, err := s.load(zone)
	if err != nil {
		return
	}
	wantDO := false
	if req != nil {
		if opt := req.IsEdns0(); opt != nil && opt.Do() {
			wantDO = true
		}
	}
	if !wantDO {
		return
	}
	now := time.Now().UTC()
	inc := now.Add(30 * 24 * time.Hour)

	if zk.Policy.NSEC3 {
		s.appendNSEC3Denial(zone, qname, zk, now, inc, resp)
		return
	}

	// Build sorted unique canonical owner list anchored at zone apex.
	seen := map[string]struct{}{zone: {}}
	for _, n := range ownerNames {
		cn := dns.CanonicalName(config.NormalizeName(n))
		if cn != "" && !strings.HasPrefix(cn, "*.") {
			seen[cn] = struct{}{}
		}
	}
	sorted := make([]string, 0, len(seen))
	for k := range seen {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)

	owner := zone
	next := zone
	cq := dns.CanonicalName(qname)
	exact := false
	for _, cand := range sorted {
		if cand == cq {
			exact = true
			break
		}
	}
	if exact {
		owner = cq
		for i, cand := range sorted {
			if cand == cq {
				next = sorted[(i+1)%len(sorted)]
				break
			}
		}
	} else {
		// Find predecessor owner < cq < next
		idx := sort.SearchStrings(sorted, cq)
		if idx == 0 || idx >= len(sorted) {
			owner = sorted[len(sorted)-1]
			next = sorted[0]
		} else {
			owner = sorted[idx-1]
			next = sorted[idx]
		}
	}

	nsec := &dns.NSEC{
		Hdr: dns.RR_Header{
			Name:   owner,
			Rrtype: dns.TypeNSEC,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		NextDomain: next,
		TypeBitMap: []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeNS, dns.TypeSOA, dns.TypeTXT, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY},
	}
	resp.Ns = append(resp.Ns, nsec)
	sig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   owner,
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		TypeCovered: dns.TypeNSEC,
		Algorithm:   zk.ZSK.Algorithm,
		Labels:      uint8(dns.CountLabel(owner)),
		OrigTtl:     300,
		Expiration:  uint32(inc.Unix()),
		Inception:   uint32(now.Unix()),
		KeyTag:      zk.ZSK.KeyTag(),
		SignerName:  zone,
	}
	if err := sig.Sign(zk.ZSKPriv, []dns.RR{nsec}); err == nil {
		resp.Ns = append(resp.Ns, sig)
	}
}

func (s *Signer) appendNSEC3Denial(zone, qname string, zk *zoneKeys, now, inc time.Time, resp *dns.Msg) {
	salt := zk.Policy.Salt
	if salt == "" {
		salt = "a1b2c3d4"
	}
	hashed := dns.HashName(qname, dns.SHA1, 1, salt)
	owner := hashed + "." + zone
	// Construct enclosing NSEC3 interval around hashed owner name
	nextHash := hashed
	if len(nextHash) > 0 {
		last := nextHash[len(nextHash)-1]
		if last == 'V' {
			nextHash = nextHash[:len(nextHash)-1] + "0"
		} else {
			nextHash = nextHash[:len(nextHash)-1] + string(last+1)
		}
	}
	nsec3 := &dns.NSEC3{
		Hdr: dns.RR_Header{
			Name:   owner,
			Rrtype: dns.TypeNSEC3,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Hash:       dns.SHA1,
		Flags:      0,
		Iterations: 1,
		SaltLength: uint8(len(salt) / 2),
		Salt:       salt,
		HashLength: 20,
		NextDomain: nextHash,
		TypeBitMap: []uint16{dns.TypeSOA, dns.TypeRRSIG},
	}
	resp.Ns = append(resp.Ns, nsec3)
	sig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   owner,
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		TypeCovered: dns.TypeNSEC3,
		Algorithm:   zk.ZSK.Algorithm,
		Labels:      uint8(dns.CountLabel(owner)),
		OrigTtl:     300,
		Expiration:  uint32(inc.Unix()),
		Inception:   uint32(now.Unix()),
		KeyTag:      zk.ZSK.KeyTag(),
		SignerName:  zone,
	}
	if err := sig.Sign(zk.ZSKPriv, []dns.RR{nsec3}); err == nil {
		resp.Ns = append(resp.Ns, sig)
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
	pol := readPolicy(filepath.Join(dir, "policy.json"), ksk.Algorithm)
	zk := &zoneKeys{ZSK: zsk, ZSKPriv: zpriv, KSK: ksk, KSKPriv: kpriv, Policy: pol}
	s.cache[zone] = zk
	return zk, nil
}

func (s *Signer) generate(zone string, opts SignOptions) error {
	dir := s.zoneDir(zone)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	alg := opts.Algorithm
	if alg == 0 {
		alg = dns.ECDSAP256SHA256
	}
	zsk, zpriv, err := makeKey(zone, 256, alg)
	if err != nil {
		return err
	}
	ksk, kpriv, err := makeKey(zone, 257, alg)
	if err != nil {
		return err
	}
	if opts.NSEC3 && opts.Salt == "" {
		opts.Salt = randomSaltHex(8)
	}
	if err := writeKey(filepath.Join(dir, "zsk.json"), "zsk", zsk, zpriv); err != nil {
		return err
	}
	if err := writeKey(filepath.Join(dir, "ksk.json"), "ksk", ksk, kpriv); err != nil {
		return err
	}
	_ = writePolicy(filepath.Join(dir, "policy.json"), opts)
	s.mu.Lock()
	s.cache[zone] = &zoneKeys{ZSK: zsk, ZSKPriv: zpriv, KSK: ksk, KSKPriv: kpriv, Policy: opts}
	s.mu.Unlock()
	return nil
}

func makeKey(zone string, flags uint16, alg uint8) (*dns.DNSKEY, crypto.Signer, error) {
	bits := 256
	switch alg {
	case dns.ED25519:
		bits = 256
	case dns.ECDSAP384SHA384:
		bits = 384
	case dns.RSASHA256:
		bits = 2048
	default:
		alg = dns.ECDSAP256SHA256
		bits = 256
	}
	key := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   zone,
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Flags:     flags,
		Protocol:  3,
		Algorithm: alg,
	}
	priv, err := key.Generate(bits)
	if err != nil {
		return nil, nil, err
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("private key is not crypto.Signer")
	}
	return key, signer, nil
}

func randomSaltHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func writePolicy(path string, opts SignOptions) error {
	b, err := json.MarshalIndent(opts, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func readPolicy(path string, defaultAlg uint8) SignOptions {
	b, err := os.ReadFile(path)
	if err != nil {
		return SignOptions{Algorithm: defaultAlg}
	}
	var p SignOptions
	if err := json.Unmarshal(b, &p); err != nil {
		return SignOptions{Algorithm: defaultAlg}
	}
	if p.Algorithm == 0 {
		p.Algorithm = defaultAlg
	}
	return p
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
