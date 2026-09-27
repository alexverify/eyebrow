package discover

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/finding"
)

// The Vercel skills CLI (npx skills add) records a whole-folder hash per
// installed skill in skills-lock.json: files sorted by relative path with
// JavaScript localeCompare, then sha256 over each path followed by its bytes,
// skipping .git and node_modules. These fixtures and expected values were
// produced by running that exact algorithm under node (skills@1.7.0's
// computeSkillFolderHash, unchanged since 1.4.6).
const (
	fixtureCLIHash        = "408c6d40678f9d0e79398993b0c0d507e0bd560d225894ac85e829a3b2764f01"
	fixtureCLIHashEditedA = "69a67f98f81bed716045027e8276543a922dd89d950d7cc3c932e4ddc8fa7372"
)

func writeSkillsCLIFixture(t *testing.T, dir string) {
	t.Helper()
	writeFile(t, filepath.Join(dir, "SKILL.md"), "---\nname: demo\ndescription: fixture\n---\nbody\n")
	writeFile(t, filepath.Join(dir, "references", "a.md"), "A\n")
	writeFile(t, filepath.Join(dir, "templates", "run.sh"), "#!/bin/sh\necho hi\n")
	writeFile(t, filepath.Join(dir, "node_modules", "x.js"), "ignored\n")
	writeFile(t, filepath.Join(dir, ".git", "HEAD"), "ref: refs/heads/main\n")
}

// localeCompare is not byte order: punctuation sorts before digits before
// letters, letters compare case-insensitively first, and lowercase wins a
// tie. SKILL.md therefore sorts after references/ and before templates/, and
// a hash computed in byte order would never match the CLI's. This corpus and
// its order come from node's String.prototype.localeCompare.
func TestSkillsCLIPathOrderMatchesLocaleCompare(t *testing.T) {
	want := []string{
		"_a.md", "-a.md", ".hidden", "1.md", "a_b.md", "a-b.md", "a.b.md", "a/b.md",
		"a10.md", "a2.md", "ab.md", "aB.md", "Ab.md", "AB.md", "agents/openai.yaml",
		"README", "readme.txt", "reference/x.md", "references.md",
		"references/authentication.md", "references/commands.md", "references/x.md",
		"scripts/run_all.sh", "scripts/run-all.sh", "scripts/run.all.sh",
		"scripts/run.sh", "scripts/Run.sh", "skill.md", "Skill.md", "SKILL.md",
		"templates/form-automation.sh", "u.md", "v.md", "z.md", "Z.md",
	}
	got := make([]string, len(want))
	copy(got, want)
	// Start from byte order so the test proves the comparator does the work.
	sort.Strings(got)
	sort.SliceStable(got, func(i, j int) bool { return skillsCLILess(got[i], got[j]) })
	if !reflect.DeepEqual(got, want) {
		t.Errorf("order mismatch\n got: %v\nwant: %v", got, want)
	}
}

func TestSkillsCLIFolderHashReproducesCLI(t *testing.T) {
	dir := t.TempDir()
	writeSkillsCLIFixture(t, dir)
	got, err := skillsCLIFolderHash(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != fixtureCLIHash {
		t.Errorf("hash = %s, want %s", got, fixtureCLIHash)
	}
}

func TestSkillsCLIFolderHashChangesWithOneByte(t *testing.T) {
	dir := t.TempDir()
	writeSkillsCLIFixture(t, dir)
	writeFile(t, filepath.Join(dir, "references", "a.md"), "B\n")
	got, err := skillsCLIFolderHash(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != fixtureCLIHashEditedA {
		t.Errorf("hash = %s, want %s", got, fixtureCLIHashEditedA)
	}
}

// The CLI skips symlinks (Dirent.isFile and isDirectory are both false for
// them), so a symlink inside a skill folder must not enter the hash.
func TestSkillsCLIFolderHashIgnoresSymlinks(t *testing.T) {
	dir := t.TempDir()
	writeSkillsCLIFixture(t, dir)
	if err := os.Symlink("SKILL.md", filepath.Join(dir, "link.md")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	got, err := skillsCLIFolderHash(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != fixtureCLIHash {
		t.Errorf("hash with symlink = %s, want %s (symlink must be ignored)", got, fixtureCLIHash)
	}
}

func lockJSON(name, hash string) string {
	return `{"version":1,"skills":{"` + name + `":{"source":"vercel-labs/agent-browser","sourceType":"github","computedHash":"` + hash + `"}}}` + "\n"
}

// inbox-zero: skills-lock.json at the root pins .claude/skills/agent-browser,
// which the Claude Code adapter already reports. The recorded hash becomes the
// artifact's integrity anchor, and a pin that matches disk raises nothing.
func TestClaudeCodeSkillCarriesSkillsLockPin(t *testing.T) {
	dir := t.TempDir()
	skill := filepath.Join(dir, ".claude", "skills", "agent-browser")
	writeSkillsCLIFixture(t, skill)
	writeFile(t, filepath.Join(dir, "skills-lock.json"), lockJSON("agent-browser", fixtureCLIHash))

	got, err := NewClaudeCode().Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatal(err)
	}
	a, ok := byName(got)["agent-browser"]
	if !ok {
		t.Fatalf("agent-browser not discovered: %+v", got)
	}
	if a.Source.Integrity != "sha256-"+fixtureCLIHash {
		t.Errorf("Integrity = %q, want the lock's computedHash", a.Source.Integrity)
	}
	if len(a.Findings) != 0 {
		t.Errorf("matching pin must raise no finding, got %+v", a.Findings)
	}
}

// When the folder no longer hashes to the recorded value, the disagreement is
// a high-severity finding on the artifact. The lock's value stays as the
// anchor so verify can also report the lock itself changing.
func TestClaudeCodeSkillReportsSkillsLockMismatch(t *testing.T) {
	dir := t.TempDir()
	skill := filepath.Join(dir, ".claude", "skills", "agent-browser")
	writeSkillsCLIFixture(t, skill)
	writeFile(t, filepath.Join(dir, "skills-lock.json"), lockJSON("agent-browser", fixtureCLIHash))
	writeFile(t, filepath.Join(skill, "references", "a.md"), "B\n")

	got, err := NewClaudeCode().Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatal(err)
	}
	a := byName(got)["agent-browser"]
	if a.Source.Integrity != "sha256-"+fixtureCLIHash {
		t.Errorf("Integrity = %q, want the recorded pin", a.Source.Integrity)
	}
	if len(a.Findings) != 1 {
		t.Fatalf("want exactly one finding, got %+v", a.Findings)
	}
	f := a.Findings[0]
	if f.RuleID != "SKILLS-LOCK-MISMATCH" {
		t.Errorf("RuleID = %q, want SKILLS-LOCK-MISMATCH", f.RuleID)
	}
	if f.Severity != finding.SeverityHigh {
		t.Errorf("Severity = %q, want high", f.Severity)
	}
	if f.File != "skills-lock.json" {
		t.Errorf("File = %q, want skills-lock.json", f.File)
	}
}

// Skills not named in the lock are plain Claude Code skills: no anchor, no
// finding. The lock must never be read as a claim about folders it does not
// list.
func TestClaudeCodeSkillWithoutLockEntryIsUntouched(t *testing.T) {
	dir := t.TempDir()
	writeSkillsCLIFixture(t, filepath.Join(dir, ".claude", "skills", "agent-browser"))
	writeFile(t, filepath.Join(dir, ".claude", "skills", "testing", "SKILL.md"), "---\nname: testing\n---\n")
	writeFile(t, filepath.Join(dir, "skills-lock.json"), lockJSON("agent-browser", fixtureCLIHash))

	got, err := NewClaudeCode().Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatal(err)
	}
	a := byName(got)["testing"]
	if a.Source.Integrity != "" || len(a.Findings) != 0 {
		t.Errorf("unlisted skill must be untouched, got integrity %q findings %+v", a.Source.Integrity, a.Findings)
	}
}

// A malformed lock cannot pin anything and must not break discovery.
func TestClaudeCodeSkillsSurviveMalformedSkillsLock(t *testing.T) {
	dir := t.TempDir()
	writeSkillsCLIFixture(t, filepath.Join(dir, ".claude", "skills", "agent-browser"))
	writeFile(t, filepath.Join(dir, "skills-lock.json"), "{not json")

	got, err := NewClaudeCode().Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatal(err)
	}
	a, ok := byName(got)["agent-browser"]
	if !ok {
		t.Fatalf("skill lost behind a malformed lock: %+v", got)
	}
	if a.Source.Integrity != "" || len(a.Findings) != 0 {
		t.Errorf("malformed lock must pin nothing, got integrity %q findings %+v", a.Source.Integrity, a.Findings)
	}
}

// dexter-mcp and solana-foundation/pay keep the catalog at skills/<slug> and
// the same lock at the root. Entries there get the same anchor treatment.
func TestSkillsLockCatalogCarriesPin(t *testing.T) {
	dir := t.TempDir()
	writeSkillsCLIFixture(t, filepath.Join(dir, "skills", "demo"))
	writeFile(t, filepath.Join(dir, "skills-lock.json"), lockJSON("demo", fixtureCLIHash))

	got, err := NewSkillsLock().Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatal(err)
	}
	a, ok := byName(got)["demo"]
	if !ok {
		t.Fatalf("demo not discovered: %+v", got)
	}
	if a.Source.Integrity != "sha256-"+fixtureCLIHash {
		t.Errorf("Integrity = %q, want the lock's computedHash", a.Source.Integrity)
	}
	if len(a.Findings) != 0 {
		t.Errorf("matching pin must raise no finding, got %+v", a.Findings)
	}
}
