package dnssec

import (
	"crypto"
	"crypto/rand"
	"encoding/hex"
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
	zsk, zpriv, err := newKey(zone, 256, alg, zk.KSK.KeyTag(), zk.ZSK.KeyTag())
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
	s.signResponse(zone, "", req, resp)
}

// SignWildcardResponse signs an answer that was synthesized from the wildcard
// record owned by wildcard ("*.example.com."): the signature is made over the
// wildcard-owned RRset, its labels field shows the expansion (RFC 4035 section
// 5.3.4), and the RRSIG is sent with the query name as owner.
func (s *Signer) SignWildcardResponse(zone, wildcard string, req, resp *dns.Msg) {
	s.signResponse(zone, wildcard, req, resp)
}

func (s *Signer) signResponse(zone, wildcard string, req, resp *dns.Msg) {
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

	signSet := func(rrs []dns.RR, priv crypto.Signer, key *dns.DNSKEY) {
		if len(rrs) == 0 || priv == nil || key == nil {
			return
		}
		toSign := rrs
		if wildcard != "" {
			toSign = make([]dns.RR, len(rrs))
			for i, rr := range rrs {
				cp := dns.Copy(rr)
				cp.Header().Name = wildcard
				toSign[i] = cp
			}
		}
		sig, err := signRRset(zone, toSign, key, priv, now)
		if err != nil {
			return
		}
		sig.Hdr.Name = rrs[0].Header().Name
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
func (s *Signer) SignDenial(zone, qname string, req, resp *dns.Msg) error {
	return s.SignDenialForNames(zone, qname, nil, req, resp)
}

// SignDenialForNames adds the signed proof that qname (NXDOMAIN) or its type
// (NODATA) does not exist, when the request has DO set. resp.Rcode says which
// of the two it is. names maps every owner name of the zone, in the view being
// answered, to the record types it has; it is what the NSEC chain is built from.
func (s *Signer) SignDenialForNames(zone, qname string, names map[string][]uint16, req, resp *dns.Msg) error {
	if s == nil || resp == nil {
		return nil
	}
	zone = config.NormalizeName(zone)
	qname = config.NormalizeName(qname)
	zk, err := s.load(zone)
	if err != nil {
		return nil
	}
	wantDO := false
	if req != nil {
		if opt := req.IsEdns0(); opt != nil && opt.Do() {
			wantDO = true
		}
	}
	if !wantDO {
		return nil
	}
	now := time.Now().UTC()

	if zk.Policy.NSEC3 {
		return s.signNSEC3Denial(zone, qname, zk, names, now, resp)
	}
	return s.signNSECDenial(zone, qname, zk, names, now, resp)
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
	ksk, kpriv, err := newKey(zone, 257, alg)
	if err != nil {
		return err
	}
	zsk, zpriv, err := newKey(zone, 256, alg, ksk.KeyTag())
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

// makeKeyFn generates zone keys; tests replace it to hand out chosen keys.
var makeKeyFn = makeKey

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

// newKey generates a key whose key tag is usable. The tag is a 16-bit checksum,
// so about one key in 65,536 has tag 0, which the signing library refuses to sign
// with, and about as many ZSKs would share the KSK's tag (a legal but needless
// ambiguity for validators). Such a key is discarded and another is drawn.
func newKey(zone string, flags uint16, alg uint8, avoidTags ...uint16) (*dns.DNSKEY, crypto.Signer, error) {
	for attempt := 0; attempt < 32; attempt++ {
		key, priv, err := makeKeyFn(zone, flags, alg)
		if err != nil {
			return nil, nil, err
		}
		tag := key.KeyTag()
		bad := tag == 0
		for _, a := range avoidTags {
			if tag == a {
				bad = true
			}
		}
		if !bad {
			return key, priv, nil
		}
	}
	return nil, nil, fmt.Errorf("no usable key tag for %s after 32 keys", zone)
}
