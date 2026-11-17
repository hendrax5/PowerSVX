package cache

import (
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"github.com/dgraph-io/badger/v4"
)

const (
	metaLenV1 = 12 // expiry(8) + rcode(4)
	metaLenV2 = 20 // expiry(8) + rcode(4) + staleUntil(8)
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

func encodeValue(wire []byte, expiry, staleUntil time.Time, rcode int) []byte {
	buf := make([]byte, metaLenV2+len(wire))
	binary.BigEndian.PutUint64(buf[0:8], uint64(expiry.UnixNano()))
	binary.BigEndian.PutUint32(buf[8:12], uint32(rcode))
	binary.BigEndian.PutUint64(buf[12:20], uint64(staleUntil.UnixNano()))
	copy(buf[metaLenV2:], wire)
	return buf
}

func decodeValue(raw []byte, allowStale bool) (*Entry, HitState) {
	if len(raw) < metaLenV1 {
		return nil, Miss
	}
	exp := time.Unix(0, int64(binary.BigEndian.Uint64(raw[0:8])))
	rcode := int(binary.BigEndian.Uint32(raw[8:12]))
	staleUntil := exp
	wireOff := metaLenV1
	if len(raw) >= metaLenV2 {
		staleUntil = time.Unix(0, int64(binary.BigEndian.Uint64(raw[12:20])))
		wireOff = metaLenV2
	}
	now := time.Now()
	wire := make([]byte, len(raw)-wireOff)
	copy(wire, raw[wireOff:])
	e := &Entry{Wire: wire, Expiry: exp, StaleUntil: staleUntil, Rcode: rcode}
	if now.Before(exp) {
		e.StoredTTL = time.Until(exp) // approximate; prefetch still works directionally
		return e, HitFresh
	}
	if allowStale && now.Before(staleUntil) {
		return e, HitStale
	}
	return nil, Miss
}

func keyBytes(key uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, key)
	return b
}

func (c *L2) Get(key uint64) (*Entry, bool) {
	e, st := c.GetEx(key, false)
	return e, st == HitFresh
}

func (c *L2) GetEx(key uint64, allowStale bool) (*Entry, HitState) {
	var entry *Entry
	var state HitState = Miss
	err := c.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(keyBytes(key))
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			e, st := decodeValue(val, allowStale)
			if st != Miss {
				entry = e
				state = st
			}
			return nil
		})
	})
	if err != nil || entry == nil {
		return nil, Miss
	}
	return entry, state
}

func (c *L2) Set(key uint64, wire []byte, ttl time.Duration, rcode int) error {
	return c.SetStale(key, wire, ttl, 0, rcode)
}

func (c *L2) SetStale(key uint64, wire []byte, ttl, staleTTL time.Duration, rcode int) error {
	if ttl <= 0 {
		ttl = time.Second
	}
	expiry := time.Now().Add(ttl)
	staleUntil := expiry
	keep := ttl
	if staleTTL > 0 {
		staleUntil = expiry.Add(staleTTL)
		keep = ttl + staleTTL
	}
	val := encodeValue(wire, expiry, staleUntil, rcode)
	return c.db.Update(func(txn *badger.Txn) error {
		e := badger.NewEntry(keyBytes(key), val).WithTTL(keep)
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
	ServeStale  bool
	StaleTTL    time.Duration
	PrefetchPct int
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
	e, st := t.GetScopedEx(name, qtype, ecsSubnet, viewName, geoTag)
	return e, st == HitFresh
}

func (t *Tier) GetScopedEx(name string, qtype uint16, ecsSubnet, viewName, geoTag string) (*Entry, HitState) {
	k := KeyScoped(name, qtype, ecsSubnet, viewName, geoTag)
	allowStale := t != nil && t.ServeStale
	if e, st := t.L1.GetEx(k, allowStale); st != Miss {
		return e, st
	}
	if t.L2 == nil {
		return nil, Miss
	}
	e, st := t.L2.GetEx(k, allowStale)
	if st == Miss {
		return nil, Miss
	}
	// Promote into L1 with remaining windows.
	now := time.Now()
	freshLeft := e.Expiry.Sub(now)
	staleExtra := e.StaleUntil.Sub(e.Expiry)
	if freshLeft < 0 {
		freshLeft = time.Second // keep in L1 briefly as stale carrier
		if staleExtra < time.Second {
			staleExtra = time.Until(e.StaleUntil)
		}
	}
	if staleExtra < 0 {
		staleExtra = 0
	}
	t.L1.SetStale(k, e.Wire, freshLeft, staleExtra, e.Rcode)
	if pe, _ := t.L1.GetEx(k, allowStale); pe != nil {
		pe.StoredTTL = e.StoredTTL
		if pe.StoredTTL <= 0 && !e.Expiry.IsZero() {
			pe.StoredTTL = t.DefaultTTL
		}
	}
	return e, st
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
	if rcode == 0 && t.MinTTL > 0 && ttl < t.MinTTL {
		ttl = t.MinTTL
	}
	if t.DefaultTTL > 0 && ttl > t.DefaultTTL {
		ttl = t.DefaultTTL
	}
	staleTTL := time.Duration(0)
	if rcode == 0 && t.ServeStale {
		staleTTL = t.StaleTTL
		if staleTTL <= 0 {
			staleTTL = time.Minute
		}
	}
	t.L1.SetStale(k, wire, ttl, staleTTL, rcode)
	if t.L2 != nil {
		_ = t.L2.SetStale(k, wire, ttl, staleTTL, rcode)
	}
}

// Delete removes one key from L2 BadgerDB.
func (c *L2) Delete(key uint64) error {
	if c == nil || c.db == nil {
		return nil
	}
	return c.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(keyBytes(key))
	})
}

// Clear drops all keys from L2 BadgerDB.
func (c *L2) Clear() error {
	if c == nil || c.db == nil {
		return nil
	}
	return c.db.DropAll()
}

// Clear flushes all L1 and L2 entries.
func (t *Tier) Clear() error {
	if t == nil {
		return nil
	}
	if t.L1 != nil {
		t.L1.Clear()
	}
	if t.L2 != nil {
		return t.L2.Clear()
	}
	return nil
}

// FlushName removes common qtype keys (or specified qtype) from L1 and L2 for default scope.
func (t *Tier) FlushName(name string, qtype uint16) {
	if t == nil {
		return
	}
	types := []uint16{qtype}
	if qtype == 0 {
		types = []uint16{1, 2, 5, 6, 12, 15, 16, 28, 33, 46, 48, 64, 65, 257}
	}
	for _, qt := range types {
		k := KeyScoped(name, qt, "", "", "")
		if t.L1 != nil {
			t.L1.Delete(k)
		}
		if t.L2 != nil {
			_ = t.L2.Delete(k)
		}
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
