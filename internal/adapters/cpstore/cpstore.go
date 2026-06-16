// Package cpstore is a file-backed store for the control-plane server: one JSON
// snapshot per owner under <dir>/<org>/<owner>.json. It is the zero-dependency
// default persistence for a self-hosted `assay serve`, in the same spirit as the
// rest of assay's "files are the backend" storage. It structurally satisfies
// controlplane.Store; a Postgres adapter can replace it for scale without
// touching the service or handlers.
package cpstore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/alexverify/assay/internal/domain/fleet"
)

// Store roots a file store at a directory.
type Store struct{ dir string }

// New returns a Store rooted at dir (created on first write).
func New(dir string) *Store { return &Store{dir: dir} }

// PutSnapshot writes (or replaces) one owner's snapshot under an org. The owner
// and org are sanitized into safe path segments so neither can escape the store.
func (s *Store) PutSnapshot(org string, snap fleet.Snapshot) error {
	orgDir := filepath.Join(s.dir, safeName(org))
	if err := os.MkdirAll(orgDir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(orgDir, safeName(snap.Owner)+".json"), append(b, '\n'), 0o644)
}

// Snapshots returns every owner's snapshot for an org, sorted by file name. A
// missing org directory yields no snapshots and no error; a corrupt or
// ownerless file is skipped so one bad submission never hides the rest.
func (s *Store) Snapshots(org string) ([]fleet.Snapshot, error) {
	orgDir := filepath.Join(s.dir, safeName(org))
	entries, err := os.ReadDir(orgDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		names = append(names, ent.Name())
	}
	sort.Strings(names)

	var out []fleet.Snapshot
	for _, name := range names {
		b, err := os.ReadFile(filepath.Join(orgDir, name))
		if err != nil {
			return nil, err
		}
		var snap fleet.Snapshot
		if json.Unmarshal(b, &snap) != nil || snap.Owner == "" {
			continue
		}
		out = append(out, snap)
	}
	return out, nil
}

// safeName reduces a label to a filesystem-safe slug so it cannot escape the
// store directory, mirroring fleetstore's sanitizing.
func safeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), ".-")
	if out == "" {
		return "default"
	}
	return out
}
