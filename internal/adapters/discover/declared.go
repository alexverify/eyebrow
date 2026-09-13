package discover

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// ManifestFile is the committed layout manifest a repo places at its root to
// declare where its skills live. Ten of the first fourteen partner audits
// needed a bespoke Go adapter for exactly this; the manifest lets a repo
// integrate in one PR to itself instead of waiting on an eyebrow release.
const ManifestFile = "eyebrow.discover.json"

// manifest is the parsed eyebrow.discover.json.
type manifest struct {
	// Version is the schema version. Only 1 exists.
	Version int `json:"version"`
	// Name becomes Artifact.Tool for every skill the manifest declares, and so
	// is part of each artifact's ID. A repo migrating off a built-in catalog
	// adapter keeps its lockfile IDs by reusing that adapter's tool id.
	Name string `json:"name"`
	// Skills are globs relative to the repo root. A match is a skill when it
	// is a directory holding SKILL.md. "." declares the whole repo as one skill.
	Skills []string `json:"skills"`
	// Harvest are globs relative to each skill directory. Every URL host in a
	// matched file joins the skill's network capability.
	Harvest []string `json:"harvest"`
}

var manifestName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// loadManifest reads and validates <root>/eyebrow.discover.json. present is
// false only when the file does not exist. Any other failure, including a
// file that exists but is invalid, returns an error naming the file and the
// offending field, so a broken committed manifest fails the scan instead of
// reading as "zero artifacts".
func loadManifest(root string) (m manifest, present bool, err error) {
	f, err := os.Open(filepath.Join(root, ManifestFile))
	if errors.Is(err, os.ErrNotExist) {
		return manifest{}, false, nil
	}
	if err != nil {
		return manifest{}, true, fmt.Errorf("%s: %w", ManifestFile, err)
	}
	defer func() { _ = f.Close() }()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return manifest{}, true, fmt.Errorf("%s: %w", ManifestFile, err)
	}
	if err := m.validate(); err != nil {
		return manifest{}, true, fmt.Errorf("%s: %w", ManifestFile, err)
	}
	return m, true, nil
}

func (m manifest) validate() error {
	if m.Version != 1 {
		return fmt.Errorf(`"version" must be 1, got %d`, m.Version)
	}
	if m.Name == "" {
		return errors.New(`"name" is required`)
	}
	if !manifestName.MatchString(m.Name) {
		return fmt.Errorf(`"name" %q must match %s`, m.Name, manifestName)
	}
	if len(m.Skills) == 0 {
		return errors.New(`"skills" must not be empty`)
	}
	if err := validGlobs("skills", m.Skills); err != nil {
		return err
	}
	return validGlobs("harvest", m.Harvest)
}

// validGlobs rejects absolute, empty, and malformed patterns up front so
// discovery never has to handle a glob error mid-walk.
func validGlobs(field string, globs []string) error {
	for _, g := range globs {
		if g == "" || filepath.IsAbs(g) {
			return fmt.Errorf(`"%s" entry %q must be a relative glob`, field, g)
		}
		if _, err := filepath.Match(g, ""); err != nil {
			return fmt.Errorf(`"%s" entry %q: %w`, field, g, err)
		}
	}
	return nil
}
