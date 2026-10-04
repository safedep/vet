package credentials

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/safedep/dry/keychain"
)

// fileKeychain keeps secrets in a plaintext JSON file with mode 0600. It is
// the cloud.keychain_file key: it never reads the OS keychain, so a test
// or a CI job cannot touch the keychain of the host.
type fileKeychain struct {
	mu   sync.Mutex
	path string
}

func newFileKeychain(path string) *fileKeychain { return &fileKeychain{path: path} }

func (k *fileKeychain) read() (map[string]string, error) {
	b, err := os.ReadFile(k.path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("keychain file %s: %w", k.path, err)
	}
	return m, nil
}

func (k *fileKeychain) write(m map[string]string) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(k.path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(k.path, b, 0o600)
}

func (k *fileKeychain) Get(_ context.Context, key string) (*keychain.Secret, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	m, err := k.read()
	if err != nil {
		return nil, err
	}
	v, ok := m[key]
	if !ok {
		return nil, keychain.ErrNotFound
	}
	return &keychain.Secret{Value: v}, nil
}

func (k *fileKeychain) Set(_ context.Context, key string, s *keychain.Secret) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	m, err := k.read()
	if err != nil {
		return err
	}
	m[key] = s.Value
	return k.write(m)
}

func (k *fileKeychain) Delete(_ context.Context, key string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	m, err := k.read()
	if err != nil {
		return err
	}
	if _, ok := m[key]; !ok {
		return keychain.ErrNotFound
	}
	delete(m, key)
	return k.write(m)
}

func (k *fileKeychain) Close() error { return nil }

var _ keychain.Keychain = (*fileKeychain)(nil)
