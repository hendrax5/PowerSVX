package apiauth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/powersvx/powersvx/internal/config"
)

// UserStore merges TOML-configured users with optional data/users.json overrides.
type UserStore struct {
	mu       sync.RWMutex
	path     string
	base     map[string]User // from TOML (immutable base)
	override map[string]User // from disk (CRUD)
}

type User struct {
	Name         string `json:"name"`
	PasswordHash string `json:"password_hash"`
	Role         string `json:"role"`
}

type usersFile struct {
	Users []User `json:"users"`
}

func NewUserStore(dataDir string, cfgUsers []config.APIUserTOML) (*UserStore, error) {
	s := &UserStore{
		path:     filepath.Join(dataDir, "users.json"),
		base:     map[string]User{},
		override: map[string]User{},
	}
	for _, u := range cfgUsers {
		name := strings.TrimSpace(u.Name)
		if name == "" {
			continue
		}
		role := normalizeRole(u.Role)
		s.base[strings.ToLower(name)] = User{Name: name, PasswordHash: u.PasswordHash, Role: role}
	}
	if err := s.loadDisk(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

func normalizeRole(role string) string {
	role = strings.ToLower(strings.TrimSpace(role))
	switch role {
	case RoleAdmin, RoleOperator, RoleReadonly:
		return role
	case "":
		return RoleAdmin
	default:
		return RoleReadonly
	}
}

func (s *UserStore) loadDisk() error {
	b, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var f usersFile
	if err := json.Unmarshal(b, &f); err != nil {
		return err
	}
	s.override = map[string]User{}
	for _, u := range f.Users {
		name := strings.TrimSpace(u.Name)
		if name == "" {
			continue
		}
		u.Role = normalizeRole(u.Role)
		s.override[strings.ToLower(name)] = u
	}
	return nil
}

func (s *UserStore) saveDiskLocked() error {
	list := make([]User, 0, len(s.override))
	for _, u := range s.override {
		list = append(list, u)
	}
	b, err := json.MarshalIndent(usersFile{Users: list}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *UserStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.mergedLocked())
}

func (s *UserStore) mergedLocked() map[string]User {
	out := map[string]User{}
	for k, v := range s.base {
		out[k] = v
	}
	for k, v := range s.override {
		out[k] = v
	}
	return out
}

func (s *UserStore) Authenticate(username, password string) (Principal, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.mergedLocked()[strings.ToLower(strings.TrimSpace(username))]
	if !ok || !CheckPassword(u.PasswordHash, password) {
		return Principal{}, false
	}
	return Principal{Name: u.Name, Role: u.Role}, true
}

func (s *UserStore) List() []User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := s.mergedLocked()
	out := make([]User, 0, len(m))
	for _, u := range m {
		out = append(out, User{Name: u.Name, Role: u.Role})
	}
	return out
}

func (s *UserStore) Upsert(name, password, role string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("name required")
	}
	role = normalizeRole(role)
	hash := ""
	if password != "" {
		var err error
		hash, err = HashPassword(password)
		if err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := strings.ToLower(name)
	existing, ok := s.mergedLocked()[key]
	if password == "" {
		if !ok {
			return fmt.Errorf("password required for new user")
		}
		hash = existing.PasswordHash
	}
	s.override[key] = User{Name: name, PasswordHash: hash, Role: role}
	return s.saveDiskLocked()
}

func (s *UserStore) Delete(name string) error {
	key := strings.ToLower(strings.TrimSpace(name))
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, inBase := s.base[key]; inBase {
		return fmt.Errorf("cannot delete TOML-configured user %q (remove from config)", name)
	}
	if _, ok := s.override[key]; !ok {
		return fmt.Errorf("user not found")
	}
	delete(s.override, key)
	return s.saveDiskLocked()
}

// EnsureBootstrap creates or updates the admin account from ADMIN_PASSWORD.
// When the store is empty it creates admin; when admin already exists it syncs
// the password so changing .env + restart actually works for Docker deploys.
func (s *UserStore) EnsureBootstrap(adminPassword string) (created bool, err error) {
	if strings.TrimSpace(adminPassword) == "" {
		return false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := "admin"
	if existing, ok := s.mergedLocked()[key]; ok {
		if CheckPassword(existing.PasswordHash, adminPassword) {
			return false, nil
		}
		hash, err := HashPassword(adminPassword)
		if err != nil {
			return false, err
		}
		s.override[key] = User{Name: "admin", PasswordHash: hash, Role: RoleAdmin}
		return false, s.saveDiskLocked()
	}
	if len(s.mergedLocked()) > 0 {
		// Other users exist but no admin — still create admin from env.
	}
	hash, err := HashPassword(adminPassword)
	if err != nil {
		return false, err
	}
	s.override[key] = User{Name: "admin", PasswordHash: hash, Role: RoleAdmin}
	if err := s.saveDiskLocked(); err != nil {
		return false, err
	}
	return true, nil
}
