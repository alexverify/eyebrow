// Package policystore loads a policy file (assay.policy.json) from disk.
// Policy is optional: a missing file yields the default policy.
package policystore

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"

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
