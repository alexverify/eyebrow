// Package lockstore reads and writes agentlock.json. It keeps the file
// human-diffable (indented JSON, trailing newline) and writes atomically so a
// crash mid-write never corrupts an existing lockfile.
package lockstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/agentguard/agentguard/internal/app/ports"
	"github.com/agentguard/agentguard/internal/domain/lockfile"
)

// Store is a filesystem-backed ports.LockStore.
type Store struct{}

// New returns a filesystem lock store.
func New() Store { return Store{} }

// Read loads and parses a lockfile. It returns ports.ErrNoLockfile (wrapped)
// when the path does not exist, so callers can distinguish "nothing locked
// yet" from a real IO/parse error.
func (Store) Read(_ context.Context, path string) (lockfile.Lockfile, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return lockfile.Lockfile{}, fmt.Errorf("%s: %w", path, ports.ErrNoLockfile)
	}
	if err != nil {
		return lockfile.Lockfile{}, err
	}
	var lf lockfile.Lockfile
	if err := json.Unmarshal(b, &lf); err != nil {
		return lockfile.Lockfile{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return lf, nil
}

// Write serializes the lockfile deterministically and writes it atomically
// (temp file + rename within the same directory).
func (Store) Write(_ context.Context, path string, lf lockfile.Lockfile) error {
	b, err := json.MarshalIndent(lf, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".agentlock-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename

	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// Exists reports whether a lockfile is present at path.
func (Store) Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
