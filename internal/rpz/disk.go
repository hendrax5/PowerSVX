package rpz

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/dgraph-io/badger/v4"
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

// LoadTrie rebuilds an in-memory radix from Badger.
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
			var code uint8 = 1
			_ = item.Value(func(v []byte) error {
				if len(v) > 0 {
					code = v[0]
				}
				return nil
			})
			t.insert(name, codeAction(code))
		}
		return nil
	})
	return t, t.count, err
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
	t.walk(func(name string, action Action) {
		if flushErr != nil {
			return
		}
		key := append([]byte(domPrefix), []byte(name)...)
		flushErr = wb.Set(key, []byte{actionCode(action)})
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
