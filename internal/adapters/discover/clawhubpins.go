package discover

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/finding"
)

// clawHubOrigin is the part of <skill>/.clawhub/origin.json that pins content.
// The ClawHub CLI writes fingerprint at install and consults it only to decide
// whether a local copy was edited before an update; OpenClaw does not re-check
// it when it loads the skill.
type clawHubOrigin struct {
	Fingerprint string `json:"fingerprint"`
}

// clawHubIgnoreFiles are the ignore files ClawHub applies when it lists a
// skill's files. eyebrow does not evaluate gitignore patterns, so a skill
// carrying one is left unpinned rather than risk a false mismatch.
var clawHubIgnoreFiles = []string{".gitignore", ".clawhubignore", ".clawdhubignore"}

// readClawHubFingerprint returns the fingerprint recorded in the skill's
// origin.json (or the legacy .clawdhub one). A missing, malformed or non-hex
// value pins nothing.
func readClawHubFingerprint(dir string) (string, bool) {
	for _, dot := range []string{".clawhub", ".clawdhub"} {
		raw, err := os.ReadFile(filepath.Join(dir, dot, "origin.json"))
		if err != nil {
			continue
		}
		var o clawHubOrigin
		if err := json.Unmarshal(raw, &o); err != nil {
			return "", false
		}
		fp := strings.ToLower(o.Fingerprint)
		return fp, sha256Hex.MatchString(fp)
	}
	return "", false
}

// applyClawHubPins gives every skill installed from ClawHub its origin
// fingerprint as integrity anchor, and raises a finding when the folder on
// disk no longer hashes to it under ClawHub's own algorithm. The anchor is
// kept even on mismatch so verify also sees origin.json itself change.
func applyClawHubPins(arts []artifact.Artifact) {
	for i := range arts {
		a := &arts[i]
		if a.Type != artifact.TypeSkill {
			continue
		}
		dir := filepath.Dir(a.DiscoveredFrom)
		recorded, ok := readClawHubFingerprint(dir)
		if !ok || hasClawHubIgnoreFile(dir) {
			continue
		}
		a.Source.Integrity = "sha256-" + recorded
		actual, err := clawHubFingerprint(dir)
		if err != nil || actual == recorded {
			continue
		}
		a.Findings = append(a.Findings, finding.ClawHubFingerprintMismatch(recorded, actual))
	}
}

func hasClawHubIgnoreFile(dir string) bool {
	for _, name := range clawHubIgnoreFiles {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return true
		}
	}
	return false
}

// clawHubFingerprint reproduces ClawHub's listSkillFiles + buildSkillFingerprint:
// regular files under dir (symlinks skipped; any dot-prefixed entry and
// node_modules pruned), sorted by slash-separated relative path with
// JavaScript localeCompare, then sha256 over the lines "path:sha256hex"
// joined by "\n".
func clawHubFingerprint(dir string) (string, error) {
	type entry struct{ rel, sum string }
	var files []entry
	var walk func(cur string) error
	walk = func(cur string) error {
		entries, err := os.ReadDir(cur)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".") || e.Name() == "node_modules" {
				continue
			}
			full := filepath.Join(cur, e.Name())
			switch {
			case e.IsDir():
				if err := walk(full); err != nil {
					return err
				}
			case e.Type().IsRegular():
				content, err := os.ReadFile(full)
				if err != nil {
					return err
				}
				rel, err := filepath.Rel(dir, full)
				if err != nil {
					return err
				}
				sum := sha256.Sum256(content)
				files = append(files, entry{rel: filepath.ToSlash(rel), sum: hex.EncodeToString(sum[:])})
			}
		}
		return nil
	}
	if err := walk(dir); err != nil {
		return "", err
	}
	sort.Slice(files, func(i, j int) bool { return skillsCLILess(files[i].rel, files[j].rel) })
	lines := make([]string, len(files))
	for i, f := range files {
		lines[i] = f.rel + ":" + f.sum
	}
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:]), nil
}
