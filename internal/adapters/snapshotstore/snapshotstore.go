// Package snapshotstore is a content-addressed blob store for the *approved*
// bytes of an artifact's files. It backs the line-level rug-pull diff (H1b):
// the signed lockfile holds only per-file hashes (bytes would bloat it and
// churn signatures), so the literal approved lines live here instead, keyed by
// the artifact's content hash.
//
// It is deliberately *outside* the lockfile and its signature: this is a local
// cache of baselines, not part of the integrity anchor. A missing store is a
// silent no-op — the dashboard degrades to the file-name list — so the diff is
// an enhancement, never a dependency. Each artifact's files are kept in one
// JSON manifest (path → base64 bytes) under <dir>/<contentHash>/, so a blob can
// hold binary content and can never escape the store directory.
package snapshotstore

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

const manifestName = "files.json"

// Store roots a blob store at a directory (e.g. .assay/snapshots).
type Store struct{ dir string }

// New returns a Store rooted at dir (created on first Put).
func New(dir string) *Store { return &Store{dir: dir} }

// Put records the bytes of an artifact's files under its content hash. Writing
// the same hash again is a harmless overwrite (content-addressed: same hash
// means same bytes).
func (s *Store) Put(contentHash string, files map[string][]byte) error {
	dir := s.blobDir(contentHash)
	if dir == "" {
		return nil // an empty hash is not addressable; skip silently
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	enc := make(map[string]string, len(files))
	for path, b := range files {
		enc[path] = base64.StdEncoding.EncodeToString(b)
	}
	body, err := json.MarshalIndent(enc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, manifestName), append(body, '\n'), 0o644)
}

// Get returns the stored files for a content hash. A hash that was never stored
// (or an absent store) yields nil with no error — the opt-in, degrade-quietly
// contract.
func (s *Store) Get(contentHash string) (map[string][]byte, error) {
	dir := s.blobDir(contentHash)
	if dir == "" {
		return nil, nil
	}
	body, err := os.ReadFile(filepath.Join(dir, manifestName))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var enc map[string]string
	if err := json.Unmarshal(body, &enc); err != nil {
		return nil, err
	}
	out := make(map[string][]byte, len(enc))
	for path, s64 := range enc {
		b, err := base64.StdEncoding.DecodeString(s64)
		if err != nil {
			return nil, err
		}
		out[path] = b
	}
	return out, nil
}

// Has reports whether a content hash has a stored blob.
func (s *Store) Has(contentHash string) bool {
	dir := s.blobDir(contentHash)
	if dir == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(dir, manifestName))
	return err == nil
}

// Prune removes every stored blob whose content hash is not in keep, returning
// how many were removed. It is the GC for baselines orphaned by re-approval, so
// the store does not grow without bound. A missing store is a no-op.
func (s *Store) Prune(keep map[string]bool) (int, error) {
	entries, err := os.ReadDir(s.dir)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	wanted := make(map[string]bool, len(keep))
	for h := range keep {
		if safe := safeHash(h); safe != "" {
			wanted[safe] = true
		}
	}
	removed := 0
	for _, ent := range entries {
		if !ent.IsDir() || wanted[ent.Name()] {
			continue
		}
		if err := os.RemoveAll(filepath.Join(s.dir, ent.Name())); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

// blobDir is the directory holding one content hash's manifest, or "" for an
// unaddressable (empty) hash.
func (s *Store) blobDir(contentHash string) string {
	safe := safeHash(contentHash)
	if safe == "" {
		return ""
	}
	return filepath.Join(s.dir, safe)
}

// safeHash reduces a content hash to a filesystem-safe directory name so it can
// never escape the store directory, mirroring fleetstore's owner sanitizing.
func safeHash(h string) string {
	var b strings.Builder
	for _, r := range h {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), ".-")
}
