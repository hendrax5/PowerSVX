package rpz

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/dgraph-io/badger/v4"
	"github.com/powersvx/powersvx/internal/bloom"
	"github.com/powersvx/powersvx/internal/config"
)

const (
	metaFPKey    = "meta\x00fp"
	metaCountKey = "meta\x00count"
	domPrefix    = "d\x00"
	feedPrefix   = "f\x00" // f\x00policy\x00name → membership for AXFR feed replace/IXFR
)

// Store persists the compact RPZ set so restarts skip re-downloading large HTTP feeds.
type Store struct {
	path string
	db   *badger.DB
}

func OpenStore(path string) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("rpz store path empty")
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		return nil, err
	}
	opts := badger.DefaultOptions(path).
		WithLogger(nil).
		WithNumVersionsToKeep(1)
	db, err := badger.Open(opts)
	if err != nil {
		return nil, err
	}
	return &Store{path: path, db: db}, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

func PoliciesFingerprint(policies []PolicyConfig) string {
	b, _ := json.Marshal(policies)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:16])
}

func (s *Store) Fingerprint() (string, error) {
	if s == nil || s.db == nil {
		return "", fmt.Errorf("store closed")
	}
	var fp string
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(metaFPKey))
		if err != nil {
			return err
		}
		return item.Value(func(v []byte) error {
			fp = string(v)
			return nil
		})
	})
	return fp, err
}

// LoadTrie rebuilds an in-memory radix from Badger (tests / migration only).
// Prefer BuildColdIndex for production — keeps exact domains on disk.
func (s *Store) LoadTrie() (*trie, int, error) {
	t := newTrie()
	if s == nil || s.db == nil {
		return t, 0, fmt.Errorf("store closed")
	}
	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = []byte(domPrefix)
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			key := item.Key()
			name := string(key[len(domPrefix):])
			var hit Hit
			_ = item.Value(func(v []byte) error {
				if len(v) == 0 {
					hit = Hit{Action: ActionNXDOMAIN}
					return nil
				}
				hit = Hit{Action: codeAction(v[0])}
				if len(v) > 1 {
					hit.Target = string(v[1:])
				}
				return nil
			})
			t.insertHit(name, hit)
		}
		return nil
	})
	return t, t.count, err
}

// Get returns an exact-name hit from Badger.
func (s *Store) Get(name string) (Hit, bool, error) {
	if s == nil || s.db == nil {
		return Hit{}, false, fmt.Errorf("store closed")
	}
	name = config.NormalizeName(name)
	key := append([]byte(domPrefix), []byte(name)...)
	var hit Hit
	found := false
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err == badger.ErrKeyNotFound {
			return nil
		}
		if err != nil {
			return err
		}
		found = true
		return item.Value(func(v []byte) error {
			if len(v) == 0 {
				hit = Hit{Action: ActionNXDOMAIN}
				return nil
			}
			hit = Hit{Action: codeAction(v[0])}
			if len(v) > 1 {
				hit.Target = string(v[1:])
			}
			return nil
		})
	})
	return hit, found, err
}

// Put upserts one exact or wild domain into Badger.
func (s *Store) Put(name string, hit Hit) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("store closed")
	}
	name = config.NormalizeName(name)
	key := append([]byte(domPrefix), []byte(name)...)
	val := append([]byte{actionCode(hit.Action)}, []byte(strings.TrimSpace(hit.Target))...)
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(key, val)
	})
}

// Delete removes one domain from Badger (no-op if missing).
func (s *Store) Delete(name string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("store closed")
	}
	name = config.NormalizeName(name)
	key := append([]byte(domPrefix), []byte(name)...)
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(key)
	})
}

func feedKey(policy, name string) []byte {
	return []byte(feedPrefix + policy + "\x00" + config.NormalizeName(name))
}

func feedPolicyPrefix(policy string) []byte {
	return []byte(feedPrefix + policy + "\x00")
}

// ClearFeed removes all domains belonging to an AXFR policy (membership index).
func (s *Store) ClearFeed(policy string) (int, error) {
	if s == nil || s.db == nil {
		return 0, fmt.Errorf("store closed")
	}
	policy = strings.TrimSpace(policy)
	if policy == "" {
		return 0, fmt.Errorf("feed policy required")
	}
	prefix := feedPolicyPrefix(policy)
	var names []string
	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		opts.Prefix = prefix
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			key := it.Item().Key()
			name := string(key[len(prefix):])
			names = append(names, name)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	wb := s.db.NewWriteBatch()
	for i, name := range names {
		if err := wb.Delete(append([]byte(domPrefix), []byte(name)...)); err != nil {
			wb.Cancel()
			return 0, err
		}
		if err := wb.Delete(feedKey(policy, name)); err != nil {
			wb.Cancel()
			return 0, err
		}
		if (i+1)%100_000 == 0 {
			if err := wb.Flush(); err != nil {
				return 0, err
			}
			wb = s.db.NewWriteBatch()
		}
	}
	if err := wb.Flush(); err != nil {
		return 0, err
	}
	if err := s.recount(); err != nil {
		return len(names), err
	}
	return len(names), nil
}

// ReplaceFeed clears prior membership for policy then writes names with feed tags.
func (s *Store) ReplaceFeed(policy string, names []string, hit Hit) error {
	if _, err := s.ClearFeed(policy); err != nil {
		return err
	}
	return s.applyFeedWrites(policy, names, nil, hit)
}

// ApplyFeedDelta applies IXFR add/remove for one policy.
func (s *Store) ApplyFeedDelta(policy string, added, removed []string, hit Hit) error {
	return s.applyFeedWrites(policy, added, removed, hit)
}

func (s *Store) applyFeedWrites(policy string, added, removed []string, hit Hit) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("store closed")
	}
	policy = strings.TrimSpace(policy)
	if policy == "" {
		return fmt.Errorf("feed policy required")
	}
	if hit.Action == "" {
		hit.Action = ActionNXDOMAIN
	}
	hit.Target = strings.TrimSpace(hit.Target)
	val := append([]byte{actionCode(hit.Action)}, []byte(hit.Target)...)

	wb := s.db.NewWriteBatch()
	n := 0
	flush := func() error {
		if err := wb.Flush(); err != nil {
			return err
		}
		wb = s.db.NewWriteBatch()
		return nil
	}
	for _, name := range removed {
		name = config.NormalizeName(name)
		if name == "" {
			continue
		}
		if err := wb.Delete(append([]byte(domPrefix), []byte(name)...)); err != nil {
			wb.Cancel()
			return err
		}
		if err := wb.Delete(feedKey(policy, name)); err != nil {
			wb.Cancel()
			return err
		}
		n++
		if n%100_000 == 0 {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	for _, name := range added {
		name = config.NormalizeName(name)
		if name == "" {
			continue
		}
		if err := wb.Set(append([]byte(domPrefix), []byte(name)...), val); err != nil {
			wb.Cancel()
			return err
		}
		if err := wb.Set(feedKey(policy, name), []byte{1}); err != nil {
			wb.Cancel()
			return err
		}
		n++
		if n%100_000 == 0 {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if err := wb.Flush(); err != nil {
		return err
	}
	return s.recount()
}

// TagFeed writes membership keys for names already present (after full ReplaceAll).
func (s *Store) TagFeed(policy string, names []string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("store closed")
	}
	policy = strings.TrimSpace(policy)
	if policy == "" {
		return fmt.Errorf("feed policy required")
	}
	wb := s.db.NewWriteBatch()
	n := 0
	for _, name := range names {
		name = config.NormalizeName(name)
		if name == "" {
			continue
		}
		if err := wb.Set(feedKey(policy, name), []byte{1}); err != nil {
			wb.Cancel()
			return err
		}
		n++
		if n%100_000 == 0 {
			if err := wb.Flush(); err != nil {
				return err
			}
			wb = s.db.NewWriteBatch()
		}
	}
	return wb.Flush()
}

func (s *Store) recount() error {
	count := 0
	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		opts.Prefix = []byte(domPrefix)
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			count++
		}
		return nil
	})
	if err != nil {
		return err
	}
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(metaCountKey), []byte(fmt.Sprintf("%d", count)))
	})
}

// SetFingerprint updates the policies fingerprint without rewriting domains.
func (s *Store) SetFingerprint(fp string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("store closed")
	}
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(metaFPKey), []byte(fp))
	})
}

// BuildColdIndex walks Badger once: exact names → Bloom, *.rules → wild trie.
// Exact domains stay on disk (no full RAM trie).
func (s *Store) BuildColdIndex() (bf *bloom.Filter, wild *trie, count int, err error) {
	if s == nil || s.db == nil {
		return nil, nil, 0, fmt.Errorf("store closed")
	}
	expected := 1024
	_ = s.db.View(func(txn *badger.Txn) error {
		item, e := txn.Get([]byte(metaCountKey))
		if e != nil {
			return nil
		}
		return item.Value(func(v []byte) error {
			var n int
			_, _ = fmt.Sscanf(string(v), "%d", &n)
			if n > 0 {
				expected = n
			}
			return nil
		})
	})
	bf = bloom.New(expected*2, 0.001)
	wild = newTrie()
	err = s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = []byte(domPrefix)
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			name := string(item.Key()[len(domPrefix):])
			var hit Hit
			_ = item.Value(func(v []byte) error {
				if len(v) == 0 {
					hit = Hit{Action: ActionNXDOMAIN}
					return nil
				}
				hit = Hit{Action: codeAction(v[0])}
				if len(v) > 1 {
					hit.Target = string(v[1:])
				}
				return nil
			})
			count++
			if strings.HasPrefix(name, "*.") {
				wild.insertHit(name, hit)
				bf.Add(config.NormalizeName(name))
				continue
			}
			bf.Add(config.NormalizeName(name))
		}
		return nil
	})
	return bf, wild, count, err
}

// ReplaceAll drops previous domains and writes the trie snapshot.
func (s *Store) ReplaceAll(t *trie, fingerprint string) error {
	if s == nil {
		return fmt.Errorf("store closed")
	}
	if s.db != nil {
		_ = s.db.Close()
		s.db = nil
	}
	if err := os.RemoveAll(s.path); err != nil {
		return err
	}
	if err := os.MkdirAll(s.path, 0o755); err != nil {
		return err
	}
	opts := badger.DefaultOptions(s.path).
		WithLogger(nil).
		WithNumVersionsToKeep(1)
	db, err := badger.Open(opts)
	if err != nil {
		return err
	}
	s.db = db

	wb := s.db.NewWriteBatch()
	n := 0
	var flushErr error
	t.walk(func(name string, hit Hit) {
		if flushErr != nil {
			return
		}
		key := append([]byte(domPrefix), []byte(name)...)
		val := append([]byte{actionCode(hit.Action)}, []byte(hit.Target)...)
		flushErr = wb.Set(key, val)
		n++
		if n%100_000 == 0 {
			if flushErr = wb.Flush(); flushErr != nil {
				return
			}
			wb = s.db.NewWriteBatch()
		}
	})
	if flushErr != nil {
		wb.Cancel()
		return flushErr
	}
	if err := wb.Set([]byte(metaFPKey), []byte(fingerprint)); err != nil {
		wb.Cancel()
		return err
	}
	if err := wb.Set([]byte(metaCountKey), []byte(fmt.Sprintf("%d", t.count))); err != nil {
		wb.Cancel()
		return err
	}
	return wb.Flush()
}

// ReplaceBuilder recreates the Badger store and streams domains without a full RAM trie.
type ReplaceBuilder struct {
	s      *Store
	wb     *badger.WriteBatch
	n      int // approximate unique domain count
	writes int
	bf     *bloom.Filter
	wild   *trie
}

// BeginReplace clears the on-disk store and returns a streaming writer.
func (s *Store) BeginReplace(expected int) (*ReplaceBuilder, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("store closed")
	}
	// DropAll clears keys without deleting the directory (safe if other files share the path).
	if err := s.db.DropAll(); err != nil {
		return nil, err
	}
	if expected < 1_000_000 {
		expected = 10_000_000
	}
	return &ReplaceBuilder{
		s:    s,
		wb:   s.db.NewWriteBatch(),
		bf:   bloom.New(expected*2, 0.001),
		wild: newTrie(),
	}, nil
}

func (b *ReplaceBuilder) Put(name string, hit Hit) error {
	return b.put(name, hit, "")
}

// PutFeed writes a domain and AXFR membership tag for policy.
func (b *ReplaceBuilder) PutFeed(policy, name string, hit Hit) error {
	return b.put(name, hit, policy)
}

func (b *ReplaceBuilder) put(name string, hit Hit, policy string) error {
	if b == nil || b.s == nil || b.s.db == nil {
		return fmt.Errorf("store closed")
	}
	name = config.NormalizeName(name)
	if name == "" {
		return nil
	}
	if hit.Action == "" {
		hit.Action = ActionNXDOMAIN
	}
	hit.Target = strings.TrimSpace(hit.Target)
	key := append([]byte(domPrefix), []byte(name)...)
	val := append([]byte{actionCode(hit.Action)}, []byte(hit.Target)...)
	if err := b.wb.Set(key, val); err != nil {
		return err
	}
	if policy != "" {
		if err := b.wb.Set(feedKey(policy, name), []byte{1}); err != nil {
			return err
		}
	}
	norm := config.NormalizeName(name)
	// Approximate unique count: bloom FPs may under-count slightly (metrics only).
	existed := b.bf.MightContain(norm)
	b.bf.Add(norm)
	if strings.HasPrefix(norm, "*.") {
		b.wild.insertHit(norm, hit)
	}
	if !existed {
		b.n++
	}
	b.writes++
	if b.writes%100_000 == 0 {
		if err := b.wb.Flush(); err != nil {
			return err
		}
		b.wb = b.s.db.NewWriteBatch()
	}
	return nil
}

// Finish writes metadata and returns cold-index pieces.
func (b *ReplaceBuilder) Finish(fingerprint string) (bf *bloom.Filter, wild *trie, count int, err error) {
	if b == nil || b.s == nil || b.s.db == nil {
		return nil, nil, 0, fmt.Errorf("store closed")
	}
	if err := b.wb.Set([]byte(metaFPKey), []byte(fingerprint)); err != nil {
		b.wb.Cancel()
		return nil, nil, 0, err
	}
	if err := b.wb.Set([]byte(metaCountKey), []byte(fmt.Sprintf("%d", b.n))); err != nil {
		b.wb.Cancel()
		return nil, nil, 0, err
	}
	if err := b.wb.Flush(); err != nil {
		return nil, nil, 0, err
	}
	return b.bf, b.wild, b.n, nil
}

func (b *ReplaceBuilder) Cancel() {
	if b == nil || b.wb == nil {
		return
	}
	b.wb.Cancel()
}
