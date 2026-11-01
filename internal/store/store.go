// Package store persists the app's configuration and keeps the access
// points' secrets, in the system's credential store where there is one and
// in a file of the data directory otherwise.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/qy/easyconnect/internal/model"
)

// ErrSecretNotFound is what a SecretStore's Get returns for a key that
// holds no secret.
var ErrSecretNotFound = errors.New("secret not found")

// SecretStore keeps small secrets by key.
type SecretStore interface {
	Get(key string) (string, error)
	Set(key, value string) error
	Delete(key string) error
}

// Store is the configuration in the data directory, with the secrets of
// its access points.
type Store struct {
	dir string
	sec SecretStore

	mu  sync.Mutex
	cfg model.Config
}

// PasswordKey is the secret key of an access point's cred.
func PasswordKey(id string) string { return "atrust.pw." + id }

// TOTPKey is the secret key of an access point's TOTP secret.
func TOTPKey(id string) string { return "atrust.totp." + id }

// Open loads the configuration of dir, creating the directory when it does
// not exist. secrets is where the creds go; nil keeps them only in
// memory, which tests use.
func Open(dir string, secrets SecretStore) (*Store, error) {
	if dir == "" {
		return nil, errors.New("empty data directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	s := &Store{dir: dir, sec: secrets}
	if s.sec == nil {
		s.sec = NewMemorySecrets()
	}
	cfg, err := loadConfig(filepath.Join(dir, "config.json"))
	if err != nil {
		return nil, err
	}
	s.cfg = cfg
	return s, nil
}

func loadConfig(path string) (model.Config, error) {
	cfg := model.Config{
		Version:  model.CurrentVersion,
		Settings: model.DefaultSettings(),
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return cfg, fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) == 0 {
		return cfg, nil
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse %s: %w", path, err)
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(data, &raw) == nil {
		if _, ok := raw["settings"]; !ok {
			cfg.Settings = model.DefaultSettings()
		} else {
			var settings map[string]json.RawMessage
			if json.Unmarshal(raw["settings"], &settings) == nil {
				if _, ok := settings["aggregateEnabled"]; !ok {
					cfg.Settings.AggregateEnabled = true
				}
			}
		}
	}
	cfg.Normalize()
	// Auto-login is opt-in. Earlier builds switched it on for every access
	// point, so clear it once here and remember that we did.
	if !cfg.Settings.AutoLoginOptIn {
		cfg.Settings.AutoLoginOptIn = true
		for i := range cfg.Points {
			cfg.Points[i].AutoConnect = false
		}
		_ = saveJSON(path, cfg)
	}
	return cfg, nil
}

// Dir returns the data directory.
func (s *Store) Dir() string { return s.dir }

// Config returns a copy of the configuration.
func (s *Store) Config() model.Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneConfig(s.cfg)
}

// Update changes the configuration under the lock and returns a copy.
func (s *Store) Update(fn func(*model.Config) error) (model.Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(&s.cfg); err != nil {
		return cloneConfig(s.cfg), err
	}
	s.cfg.Normalize()
	return cloneConfig(s.cfg), nil
}

// Save writes the configuration to disk, atomically and readable only by
// the user.
func (s *Store) Save() error {
	s.mu.Lock()
	cfg := cloneConfig(s.cfg)
	s.mu.Unlock()
	return saveJSON(filepath.Join(s.dir, "config.json"), cfg)
}

// Password returns the cred of an access point.
func (s *Store) Password(id string) (string, error) { return s.sec.Get(PasswordKey(id)) }

// SetPassword stores the cred of an access point; an empty cred
// deletes it.
func (s *Store) SetPassword(id, cred string) error {
	if cred == "" {
		return s.sec.Delete(PasswordKey(id))
	}
	return s.sec.Set(PasswordKey(id), cred)
}

// TOTP returns the TOTP secret of an access point.
func (s *Store) TOTP(id string) (string, error) { return s.sec.Get(TOTPKey(id)) }

// SetTOTP stores the TOTP secret of an access point; empty deletes it.
func (s *Store) SetTOTP(id, secret string) error {
	if secret == "" {
		return s.sec.Delete(TOTPKey(id))
	}
	return s.sec.Set(TOTPKey(id), secret)
}

// DeleteSecrets removes both secrets of an access point.
func (s *Store) DeleteSecrets(id string) error {
	pErr := s.sec.Delete(PasswordKey(id))
	tErr := s.sec.Delete(TOTPKey(id))
	if pErr != nil && !errors.Is(pErr, ErrSecretNotFound) {
		return pErr
	}
	if tErr != nil && !errors.Is(tErr, ErrSecretNotFound) {
		return tErr
	}
	return nil
}

func cloneConfig(c model.Config) model.Config {
	out := c
	out.Points = append([]model.AccessPoint(nil), c.Points...)
	return out
}

func saveJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writeFileAtomic(path, data, 0o600)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// MemorySecrets is a SecretStore that keeps its secrets in memory.
type MemorySecrets struct {
	mu   sync.Mutex
	data map[string]string
}

// NewMemorySecrets returns an empty in-memory store.
func NewMemorySecrets() *MemorySecrets {
	return &MemorySecrets{data: map[string]string{}}
}

func (m *MemorySecrets) Get(key string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[key]
	if !ok {
		return "", ErrSecretNotFound
	}
	return v, nil
}

func (m *MemorySecrets) Set(key, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = value
	return nil
}

func (m *MemorySecrets) Delete(key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

// FileSecrets is a SecretStore for machines without a credential store.
// It keeps the secrets in secrets.json, readable only by the user, and is
// a fallback, not a substitute for the keychain.
type FileSecrets struct {
	path string
	mu   sync.Mutex
	data map[string]string
}

// NewFileSecrets opens the secrets file in dir.
func NewFileSecrets(dir string) (*FileSecrets, error) {
	f := &FileSecrets{path: filepath.Join(dir, "secrets.json"), data: map[string]string{}}
	data, err := os.ReadFile(f.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(data, &f.data); err != nil {
			return nil, fmt.Errorf("parse %s: %w", f.path, err)
		}
		if f.data == nil {
			f.data = map[string]string{}
		}
	}
	return f, nil
}

func (f *FileSecrets) Get(key string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.data[key]
	if !ok {
		return "", ErrSecretNotFound
	}
	return v, nil
}

func (f *FileSecrets) Set(key, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.data[key] = value
	return f.saveLocked()
}

func (f *FileSecrets) Delete(key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.data[key]; !ok {
		return nil
	}
	delete(f.data, key)
	return f.saveLocked()
}

func (f *FileSecrets) saveLocked() error {
	data, err := json.MarshalIndent(f.data, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(f.path, append(data, '\n'), 0o600)
}

// FallbackSecrets reads and writes primary, and keeps what primary refuses
// in fallback. A value in primary wins, so a machine that gains a keychain
// later starts using it as new secrets are written.
type FallbackSecrets struct {
	Primary  SecretStore
	Fallback SecretStore
}

func (f FallbackSecrets) Get(key string) (string, error) {
	if f.Primary != nil {
		if v, err := f.Primary.Get(key); err == nil {
			return v, nil
		} else if !errors.Is(err, ErrSecretNotFound) {
			// The store is unavailable, not empty: try the fallback.
			if f.Fallback != nil {
				if v, ferr := f.Fallback.Get(key); ferr == nil {
					return v, nil
				}
			}
			return "", err
		}
	}
	if f.Fallback != nil {
		return f.Fallback.Get(key)
	}
	return "", ErrSecretNotFound
}

func (f FallbackSecrets) Set(key, value string) error {
	var primaryErr, fallbackErr error
	if f.Primary != nil {
		primaryErr = f.Primary.Set(key, value)
	}
	if f.Fallback != nil {
		fallbackErr = f.Fallback.Set(key, value)
	}
	if primaryErr == nil || fallbackErr == nil {
		return nil
	}
	if primaryErr != nil {
		return primaryErr
	}
	return fallbackErr
}

func (f FallbackSecrets) Delete(key string) error {
	var first error
	if f.Primary != nil {
		if err := f.Primary.Delete(key); err != nil {
			first = err
		}
	}
	if f.Fallback != nil {
		if err := f.Fallback.Delete(key); err != nil && first == nil {
			first = err
		}
	}
	return first
}
