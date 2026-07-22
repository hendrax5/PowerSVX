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
	bf = bloom.New(expected*2, 0.01)
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
