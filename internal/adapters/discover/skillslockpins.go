package discover

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/finding"
)

// skillsLockFile is the lock the Vercel skills CLI (npx skills add) writes at a
// project root. Each entry records where a skill came from and computedHash, a
// sha256 over the installed folder. The CLI consults the hash only to decide
// whether an update is available; no agent re-checks it at load time.
const skillsLockFile = "skills-lock.json"

type skillsLockEntry struct {
	Source       string `json:"source"`
	SourceType   string `json:"sourceType"`
	SkillPath    string `json:"skillPath"`
	ComputedHash string `json:"computedHash"`
}

type skillsLock struct {
	Version int                        `json:"version"`
	Skills  map[string]skillsLockEntry `json:"skills"`
}

// readSkillsLock parses <root>/skills-lock.json. A missing or malformed lock
// pins nothing; discovery must not fail because a partner's lock is broken.
func readSkillsLock(root string) (skillsLock, bool) {
	raw, err := os.ReadFile(filepath.Join(root, skillsLockFile))
	if err != nil {
		return skillsLock{}, false
	}
	var lock skillsLock
	if err := json.Unmarshal(raw, &lock); err != nil || len(lock.Skills) == 0 {
		return skillsLock{}, false
	}
	return lock, true
}

// applySkillsLockPins gives every skill artifact named in <root>/skills-lock.json
// the lock's computedHash as its integrity anchor, and raises a finding when the
// folder on disk no longer hashes to that value under the CLI's own algorithm.
// The anchor is kept even on mismatch so verify also sees the lock itself change.
func applySkillsLockPins(root string, arts []artifact.Artifact) {
	lock, ok := readSkillsLock(root)
	if !ok {
		return
	}
	for i := range arts {
		a := &arts[i]
		if a.Type != artifact.TypeSkill {
			continue
		}
		e, ok := lock.Skills[a.Name]
		if !ok {
			continue
		}
		recorded := strings.ToLower(e.ComputedHash)
		if !sha256Hex.MatchString(recorded) {
			continue
		}
		a.Source.Integrity = "sha256-" + recorded
		actual, err := skillsCLIFolderHash(filepath.Dir(a.DiscoveredFrom))
		if err != nil || actual == recorded {
			continue
		}
		a.Findings = append(a.Findings, finding.Finding{
			RuleID:   "SKILLS-LOCK-MISMATCH",
			Severity: finding.SeverityHigh,
			OWASP:    "ASK-02",
			File:     skillsLockFile,
			Explanation: fmt.Sprintf("skills-lock.json records sha256 %s for this skill but the folder hashes to %s under the skills CLI algorithm; the pinned content changed after the lock was written",
				recorded, actual),
		})
	}
}

// skillsCLIFolderHash reproduces the Vercel skills CLI's computeSkillFolderHash:
// regular files under dir (symlinks skipped, .git and node_modules pruned),
// sorted by slash-separated relative path with JavaScript localeCompare, then
// sha256 over each path immediately followed by its bytes.
func skillsCLIFolderHash(dir string) (string, error) {
	type entry struct {
		rel     string
		content []byte
	}
	var files []entry
	var walk func(cur string) error
	walk = func(cur string) error {
		entries, err := os.ReadDir(cur)
		if err != nil {
			return err
		}
		for _, e := range entries {
			full := filepath.Join(cur, e.Name())
			switch {
			case e.IsDir():
				if e.Name() == ".git" || e.Name() == "node_modules" {
					continue
				}
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
				files = append(files, entry{rel: filepath.ToSlash(rel), content: content})
			}
		}
		return nil
	}
	if err := walk(dir); err != nil {
		return "", err
	}
	sort.Slice(files, func(i, j int) bool { return skillsCLILess(files[i].rel, files[j].rel) })
	h := sha256.New()
	for _, f := range files {
		h.Write([]byte(f.rel))
		h.Write(f.content)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// skillsCLIPunctuation is the ICU root collation order of ASCII punctuation,
// which is what JavaScript's default localeCompare applies. Punctuation sorts
// before digits, digits before letters.
const skillsCLIPunctuation = " _-,;:!?.'\"()[]{}@*/\\&#%`^+<=>|~$"

// skillsCLILess orders two relative paths the way the CLI's
// a.localeCompare(b) does for the characters that appear in skill folders:
// the primary pass compares punctuation, digits and case-folded letters; a
// tie goes to the string whose first differing letter is lowercase. Runes
// outside ASCII fall back to code-point order after all ASCII, a
// simplification that leaves accented letters unsupported.
func skillsCLILess(a, b string) bool {
	ra, rb := []rune(a), []rune(b)
	for i := 0; i < len(ra) && i < len(rb); i++ {
		if pa, pb := skillsCLIPrimary(ra[i]), skillsCLIPrimary(rb[i]); pa != pb {
			return pa < pb
		}
	}
	if len(ra) != len(rb) {
		return len(ra) < len(rb)
	}
	for i := range ra {
		if ua, ub := unicode.IsUpper(ra[i]), unicode.IsUpper(rb[i]); ua != ub {
			return !ua
		}
	}
	return a < b
}

func skillsCLIPrimary(r rune) int {
	switch {
	case r < 128 && strings.ContainsRune(skillsCLIPunctuation, r):
		return strings.IndexRune(skillsCLIPunctuation, r)
	case r >= '0' && r <= '9':
		return 100 + int(r-'0')
	case r >= 'a' && r <= 'z':
		return 200 + int(r-'a')
	case r >= 'A' && r <= 'Z':
		return 200 + int(r-'A')
	}
	return 1000 + int(r)
}
