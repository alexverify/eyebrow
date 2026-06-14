// Package policystore loads a policy file (assay.policy.json) from disk.
// Policy is optional: a missing file yields the default policy.
package policystore

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/alexverify/assay/internal/domain/policy"
)

// Load reads and parses a policy file. If the path does not exist it returns
// the default policy and present=false (no file), with a nil error. A malformed
// file is a real error.
func Load(path string) (p policy.Policy, present bool, err error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return policy.Default(), false, nil
	}
	if err != nil {
		return policy.Policy{}, false, err
	}
	var loaded policy.Policy
	if err := json.Unmarshal(b, &loaded); err != nil {
		return policy.Policy{}, false, fmt.Errorf("parse %s: %w", path, err)
	}
	return loaded.Normalize(), true, nil
}

// Save writes the policy to path as pretty JSON, atomically (temp file + rename
// within the same directory), so the committed policy file stays a clean,
// reviewable diff. It mirrors lockstore.Write.
func Save(path string, p policy.Policy) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".assaypolicy-*.tmp")
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
