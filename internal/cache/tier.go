package cache

import (
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"github.com/dgraph-io/badger/v4"
)

const (
	metaLen = 12 // expiry unix nano (8) + rcode (4)
)

// L2 is a persistent BadgerDB cache of pre-encoded responses.
type L2 struct {
	db *badger.DB
}

func NewL2(path string) (*L2, error) {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return nil, fmt.Errorf("cache path: %w", err)
	}
	opts := badger.DefaultOptions(path).
		WithLogger(nil).
		WithValueLogFileSize(64 << 20)
	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("open badger: %w", err)
	}
	return &L2{db: db}, nil
}

func encodeValue(wire []byte, expiry time.Time, rcode int) []byte {
	buf := make([]byte, metaLen+len(wire))
	binary.BigEndian.PutUint64(buf[0:8], uint64(expiry.UnixNano()))
	binary.BigEndian.PutUint32(buf[8:12], uint32(rcode))
	copy(buf[metaLen:], wire)
	return buf
}

func decodeValue(raw []byte) (*Entry, bool) {
	if len(raw) < metaLen {
		return nil, false
	}
	exp := time.Unix(0, int64(binary.BigEndian.Uint64(raw[0:8])))
	if time.Now().After(exp) {
		return nil, false
	}
	rcode := int(binary.BigEndian.Uint32(raw[8:12]))
	wire := make([]byte, len(raw)-metaLen)
	copy(wire, raw[metaLen:])
	return &Entry{Wire: wire, Expiry: exp, Rcode: rcode}, true
}

func keyBytes(key uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, key)
	return b
}

func (c *L2) Get(key uint64) (*Entry, bool) {
	var entry *Entry
	err := c.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(keyBytes(key))
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			e, ok := decodeValue(val)
			if ok {
				entry = e
			}
			return nil
		})
	})
	if err != nil || entry == nil {
		return nil, false
	}
	return entry, true
}

func (c *L2) Set(key uint64, wire []byte, ttl time.Duration, rcode int) error {
	if ttl <= 0 {
		ttl = time.Second
	}
	expiry := time.Now().Add(ttl)
	val := encodeValue(wire, expiry, rcode)
	return c.db.Update(func(txn *badger.Txn) error {
		e := badger.NewEntry(keyBytes(key), val).WithTTL(ttl)
		return txn.SetEntry(e)
	})
}

func (c *L2) Close() error {
	if c.db == nil {
		return nil
	}
	return c.db.Close()
}

func (c *L2) Ping() error {
	return c.db.View(func(txn *badger.Txn) error { return nil })
}

// Tier combines L1 + L2 with promote-on-hit.
type Tier struct {
	L1          *L1
	L2          *L2
	DefaultTTL  time.Duration // max positive cache TTL
	MinTTL      time.Duration // floor for positive answers (0 = off)
	NegativeTTL time.Duration
}

func NewTier(l1 *L1, l2 *L2, defaultTTL, negativeTTL time.Duration) *Tier {
	if defaultTTL <= 0 {
		defaultTTL = 5 * time.Minute
	}
	if negativeTTL <= 0 {
		negativeTTL = time.Minute
	}
	return &Tier{L1: l1, L2: l2, DefaultTTL: defaultTTL, NegativeTTL: negativeTTL}
}

func (t *Tier) Get(name string, qtype uint16) (*Entry, bool) {
	return t.GetScoped(name, qtype, "", "", "")
}

func (t *Tier) GetScoped(name string, qtype uint16, ecsSubnet, viewName, geoTag string) (*Entry, bool) {
	k := KeyScoped(name, qtype, ecsSubnet, viewName, geoTag)
	if e, ok := t.L1.Get(k); ok {
		return e, true
	}
	if t.L2 == nil {
		return nil, false
	}
	e, ok := t.L2.Get(k)
	if !ok {
		return nil, false
	}
	ttl := time.Until(e.Expiry)
	t.L1.Set(k, e.Wire, ttl, e.Rcode)
	return e, true
}

func (t *Tier) Set(name string, qtype uint16, wire []byte, rcode int, msgTTL uint32) {
	t.SetScoped(name, qtype, "", "", "", wire, rcode, msgTTL)
}

func (t *Tier) SetScoped(name string, qtype uint16, ecsSubnet, viewName, geoTag string, wire []byte, rcode int, msgTTL uint32) {
	k := KeyScoped(name, qtype, ecsSubnet, viewName, geoTag)
	ttl := t.DefaultTTL
	if rcode != 0 {
		ttl = t.NegativeTTL
	} else if msgTTL > 0 {
		d := time.Duration(msgTTL) * time.Second
		if d < ttl {
			ttl = d
		}
	}
	// Floor short CDN TTLs so repeated queries within min_ttl hit cache.
	if rcode == 0 && t.MinTTL > 0 && ttl < t.MinTTL {
		ttl = t.MinTTL
	}
	if t.DefaultTTL > 0 && ttl > t.DefaultTTL {
		ttl = t.DefaultTTL
	}
	t.L1.Set(k, wire, ttl, rcode)
	if t.L2 != nil {
		_ = t.L2.Set(k, wire, ttl, rcode)
	}
}

func (t *Tier) Close() error {
	var err error
	if t.L1 != nil {
		_ = t.L1.Close()
	}
	if t.L2 != nil {
		err = t.L2.Close()
	}
	return err
}
