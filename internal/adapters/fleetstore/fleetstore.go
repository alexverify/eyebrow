// Package fleetstore reads and writes fleet snapshots as one JSON file per
// owner under a shared directory (the "git is the backend" path, e.g.
// .assay/fleet/). Each file is a counts-and-hashes Snapshot — no code, no
// secrets — so the directory is safe to commit and share. The dashboard reads
// every snapshot it finds and aggregates them; no server required.
package fleetstore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/alexverify/assay/internal/domain/fleet"
)

// Read loads every *.json snapshot under dir, sorted by file name for a stable
// order. A missing directory yields no snapshots and no error; an unparseable
// file is skipped so one bad export never hides the rest of the fleet.
func Read(dir string) ([]fleet.Snapshot, error) {
	entries, err := os.ReadDir(dir)
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
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		var s fleet.Snapshot
		if json.Unmarshal(b, &s) != nil || s.Owner == "" {
			continue // skip a corrupt or ownerless snapshot, keep the rest
		}
		out = append(out, s)
	}
	return out, nil
}

// Write persists one snapshot as <owner>.json under dir, creating the directory
// as needed. The owner is sanitized into a safe file name so it can never
// escape the directory or collide with path separators.
func Write(dir string, s fleet.Snapshot) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dir, safeName(s.Owner)+".json")
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// safeName reduces an owner label to a filesystem-safe slug: anything that is
// not an unreserved file-name char becomes '-'. Keeps the snapshot file inside
// the fleet directory regardless of the owner string.
func safeName(owner string) string {
	var b strings.Builder
	for _, r := range owner {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), ".-")
	if out == "" {
		return "snapshot"
	}
	return out
}
