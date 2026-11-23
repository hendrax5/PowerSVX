package dnssec

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/powersvx/powersvx/internal/config"
)

// Signed zone transfer (docs/adr/0004). A secondary serves what it receives, so
// a transfer of a signed zone carries the signatures and the denial chain the
// primary would answer with. Signatures made for a transfer are not made "now"
// like the ones in query answers: a secondary keeps its copy until the serial
// changes, so the window must stay valid for a long time and must change only
// when the primary bumps the serial.

const (
	// DefaultTransferValidity is how long a signature made for a transfer is valid.
	DefaultTransferValidity = 30 * 24 * time.Hour
	// DefaultTransferRefresh is how often the signatures made for transfers are
	// renewed (and the SOA serial bumped so secondaries pull them).
	DefaultTransferRefresh = 7 * 24 * time.Hour
)

// SigPolicy is the timing of the signatures in a zone transfer.
//
// Time is cut into refresh intervals counted from the Unix epoch. Every
// signature made in one interval has the same window: it starts one signing
// skew before the interval does and ends Validity after the interval starts.
// A secondary that pulls at any moment of an interval therefore holds
// signatures with at least Validity-Refresh left, and the primary bumps the
// serial when a new interval begins so that secondaries pull the next window.
type SigPolicy struct {
	Validity time.Duration
	Refresh  time.Duration
}

// Normalized fills in defaults and keeps the refresh interval at no more than
// half of the validity, so a secondary always has at least half of the validity
// left to notice the new serial.
func (p SigPolicy) Normalized() SigPolicy {
	if p.Validity <= 0 {
		p.Validity = DefaultTransferValidity
	}
	if p.Refresh <= 0 {
		p.Refresh = DefaultTransferRefresh
	}
	if p.Refresh > p.Validity/2 {
		p.Refresh = p.Validity / 2
	}
	if p.Refresh < time.Second {
		p.Refresh = time.Second
	}
	return p
}

// Epoch numbers the refresh interval that now falls in.
func (p SigPolicy) Epoch(now time.Time) int64 {
	p = p.Normalized()
	return now.Unix() / int64(p.Refresh/time.Second)
}

// Window is the inception and expiration of signatures made at now.
func (p SigPolicy) Window(now time.Time) (inception, expiration uint32) {
	p = p.Normalized()
	start := time.Unix(p.Epoch(now)*int64(p.Refresh/time.Second), 0).UTC()
	return uint32(start.Add(-signInceptionSkew).Unix()), uint32(start.Add(p.Validity).Unix())
}

// ZoneSigner signs the contents of one zone for a transfer, with the zone's own
// keys and the validity window of one refresh interval.
type ZoneSigner struct {
	zone                  string
	zk                    *zoneKeys
	inception, expiration uint32
}

// ForTransfer returns the signer for a transfer of zone made at now. It fails
// when the zone has no keys.
func (s *Signer) ForTransfer(zone string, p SigPolicy, now time.Time) (*ZoneSigner, error) {
	if s == nil {
		return nil, fmt.Errorf("signer nil")
	}
	zone = config.NormalizeName(zone)
	zk, err := s.load(zone)
	if err != nil {
		return nil, err
	}
	in, ex := p.Window(now)
	return &ZoneSigner{zone: zone, zk: zk, inception: in, expiration: ex}, nil
}

// Keys is the DNSKEY RRset of the zone: the zone signing key and the key signing key.
func (z *ZoneSigner) Keys() []dns.RR { return []dns.RR{z.zk.ZSK, z.zk.KSK} }

// Sign signs one RRset: the DNSKEY RRset with the key signing key, any other
// with the zone signing key, as the query answers do.
func (z *ZoneSigner) Sign(rrs []dns.RR) (*dns.RRSIG, error) {
	key, priv := z.zk.ZSK, z.zk.ZSKPriv
	if rrs[0].Header().Rrtype == dns.TypeDNSKEY {
		key, priv = z.zk.KSK, z.zk.KSKPriv
	}
	return signRRsetWindow(z.zone, rrs, key, priv, z.inception, z.expiration)
}

// NSEC3PARAM is the apex record of an NSEC3 zone, or nil for an NSEC zone.
func (z *ZoneSigner) NSEC3PARAM(ttl uint32) *dns.NSEC3PARAM {
	if !z.zk.Policy.NSEC3 {
		return nil
	}
	salt := z.zk.Policy.nsec3Salt()
	return &dns.NSEC3PARAM{
		Hdr:        dns.RR_Header{Name: z.zone, Rrtype: dns.TypeNSEC3PARAM, Class: dns.ClassINET, Ttl: ttl},
		Hash:       dns.SHA1,
		Iterations: nsec3Iterations,
		SaltLength: uint8(len(salt) / 2),
		Salt:       salt,
	}
}

// Chain returns the whole denial chain of the zone, NSEC or NSEC3 as its policy
// says. names maps every owner name of the zone to its record types (the SOA
// included); the DNSKEY type of the apex and NSEC3PARAM are added here.
func (z *ZoneSigner) Chain(names map[string][]uint16, ttl uint32) []dns.RR {
	dz := newDenialZone(z.zone, names)
	if z.zk.Policy.NSEC3 {
		c := dz.nsec3Chain(z.zk.Policy.nsec3Salt())
		out := make([]dns.RR, 0, len(c.entries))
		for i := range c.entries {
			out = append(out, c.record(i, ttl))
		}
		return out
	}
	out := make([]dns.RR, 0, len(dz.chain))
	for i := range dz.chain {
		out = append(out, dz.nsecAt(i, ttl))
	}
	return out
}

// NegativeTTL is the TTL of denial records and NSEC3PARAM for a zone whose SOA
// is soa: the smaller of the SOA TTL and its minimum field (RFC 2308 section 5).
func NegativeTTL(soa *dns.SOA) uint32 {
	if soa.Minttl < soa.Hdr.Ttl {
		return soa.Minttl
	}
	return soa.Hdr.Ttl
}

// What a secondary holds is only as good as the serial it holds it under, so
// the serial must move whenever the signatures a transfer would carry change:
// a new refresh interval, a rolled key, a changed NSEC or NSEC3 policy. The
// fingerprint below names those inputs; the last one a serial was bumped for is
// kept next to the zone's keys.

func (s *Signer) transferStatePath(zone string) string {
	return filepath.Join(s.zoneDir(zone), "transfer-state")
}

func (s *Signer) transferFingerprint(zone string, p SigPolicy, now time.Time) (string, error) {
	zk, err := s.load(zone)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256([]byte(zk.ZSK.PublicKey + "|" + zk.KSK.PublicKey))
	fp := fmt.Sprintf("epoch=%d keys=%s alg=%d nsec3=%t", p.Epoch(now), hex.EncodeToString(h[:8]), zk.KSK.Algorithm, zk.Policy.NSEC3)
	if zk.Policy.NSEC3 {
		fp += " salt=" + zk.Policy.nsec3Salt()
	}
	return fp, nil
}

// TransferRefreshDue reports whether the signatures a transfer of zone would
// carry differ from those the zone's current serial was last bumped for. fp is
// to be handed to MarkTransferRefreshed after the serial has been bumped.
func (s *Signer) TransferRefreshDue(zone string, p SigPolicy, now time.Time) (fp string, due bool) {
	if s == nil {
		return "", false
	}
	zone = config.NormalizeName(zone)
	fp, err := s.transferFingerprint(zone, p, now)
	if err != nil {
		return "", false
	}
	b, err := os.ReadFile(s.transferStatePath(zone))
	return fp, err != nil || strings.TrimSpace(string(b)) != fp
}

// MarkTransferRefreshed records that the serial of zone has been bumped for fp.
func (s *Signer) MarkTransferRefreshed(zone, fp string) error {
	if s == nil {
		return fmt.Errorf("signer nil")
	}
	return os.WriteFile(s.transferStatePath(config.NormalizeName(zone)), []byte(fp+"\n"), 0o600)
}
