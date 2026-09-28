package discover

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexverify/eyebrow/internal/domain/artifact"
	"github.com/alexverify/eyebrow/internal/domain/finding"
)

func TestDirReportsSkillFolder(t *testing.T) {
	root := filepath.Join(t.TempDir(), "demo")
	writeFile(t, filepath.Join(root, "SKILL.md"), "---\ndescription: staged skill\n---\n")
	d := NewDir(root)
	if d.Tool() != "check" {
		t.Fatalf("Tool() = %q", d.Tool())
	}
	arts, err := d.Discover(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(arts) != 1 {
		t.Fatalf("want one artifact, got %+v", arts)
	}
	a := arts[0]
	if a.Type != artifact.TypeSkill || a.Name != "demo" || a.Description != "staged skill" ||
		a.Source.Kind != artifact.SourceLocal || a.Source.Ref != root ||
		a.DiscoveredFrom != filepath.Join(root, "SKILL.md") || a.ID == "" {
		t.Errorf("unexpected artifact %+v", a)
	}
}

func TestDirReportsPluginFolder(t *testing.T) {
	root := filepath.Join(t.TempDir(), "voice-call")
	writeFile(t, filepath.Join(root, "openclaw.plugin.json"), `{"id":"voice-call"}`)
	arts, _ := NewDir(root).Discover(context.Background(), nil)
	if len(arts) != 1 || arts[0].Type != artifact.TypePlugin || arts[0].DiscoveredFrom != filepath.Join(root, "openclaw.plugin.json") {
		t.Fatalf("unexpected %+v", arts)
	}
}

// A folder with neither SKILL.md nor a manifest is still analyzed, as a plugin.
func TestDirFallsBackToPlugin(t *testing.T) {
	root := filepath.Join(t.TempDir(), "bare")
	writeFile(t, filepath.Join(root, "run.sh"), "echo hi\n")
	arts, _ := NewDir(root).Discover(context.Background(), nil)
	if len(arts) != 1 || arts[0].Type != artifact.TypePlugin || arts[0].DiscoveredFrom != root {
		t.Fatalf("unexpected %+v", arts)
	}
}

func dirArtifact(t *testing.T, root string) artifact.Artifact {
	t.Helper()
	arts, err := NewDir(root).Discover(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(arts) != 1 {
		t.Fatalf("want one artifact, got %+v", arts)
	}
	return arts[0]
}

func unsafeEntryOn(a artifact.Artifact, file string) bool {
	for _, f := range a.Findings {
		if f.RuleID == finding.RuleUnsafeEntry && f.File == file && f.Severity == finding.SeverityHigh {
			return true
		}
	}
	return false
}

// A symlinked SKILL.md is never followed: its target outside the folder is
// not read, and the entry is reported.
func TestDirDoesNotReadSymlinkedSkillMd(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "elsewhere.md")
	writeFile(t, outside, "---\nname: stolen\ndescription: read through the link\n---\n")
	root := filepath.Join(t.TempDir(), "demo")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "SKILL.md")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	a := dirArtifact(t, root)
	if a.Type != artifact.TypeSkill || a.Description != "" || a.Name != "demo" {
		t.Errorf("symlinked SKILL.md was read or mistyped: %+v", a)
	}
	if !unsafeEntryOn(a, "SKILL.md") {
		t.Errorf("want CHECK-UNSAFE-ENTRY on SKILL.md, got %+v", a.Findings)
	}
}

// A non-regular manifest is reported, not read; the folder stays a plugin.
func TestDirReportsNonRegularManifest(t *testing.T) {
	root := filepath.Join(t.TempDir(), "demo")
	if err := os.MkdirAll(filepath.Join(root, "openclaw.plugin.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	a := dirArtifact(t, root)
	if a.Type != artifact.TypePlugin || !unsafeEntryOn(a, "openclaw.plugin.json") {
		t.Errorf("want plugin with CHECK-UNSAFE-ENTRY on the manifest, got %+v", a)
	}
}

func TestDirNamesSkillFromFrontmatter(t *testing.T) {
	root := filepath.Join(t.TempDir(), "staging-123")
	writeFile(t, filepath.Join(root, "SKILL.md"), "---\nname: web-search\ndescription: d\n---\n")
	writeFile(t, filepath.Join(root, "package.json"), `{"name":"not-this"}`)
	if a := dirArtifact(t, root); a.Name != "web-search" || len(a.Findings) != 0 {
		t.Errorf("want name from SKILL.md frontmatter, got %+v", a)
	}
}

func TestDirNamesPackageFromPackageJSON(t *testing.T) {
	root := filepath.Join(t.TempDir(), "staging-123")
	writeFile(t, filepath.Join(root, "package.json"), `{"name":"@acme/voice","version":"1.0.0"}`)
	a := dirArtifact(t, root)
	if a.Name != "@acme/voice" || a.Type != artifact.TypePlugin || a.DiscoveredFrom != filepath.Join(root, "package.json") {
		t.Errorf("want name and origin from package.json, got %+v", a)
	}
}

func TestDirNameFallsBackToFolderName(t *testing.T) {
	root := filepath.Join(t.TempDir(), "demo")
	writeFile(t, filepath.Join(root, "SKILL.md"), "---\ndescription: d\n---\n")
	writeFile(t, filepath.Join(root, "package.json"), `{"version":"1.0.0"}`)
	if a := dirArtifact(t, root); a.Name != "demo" {
		t.Errorf("want folder name, got %+v", a)
	}
}

// package.json over 1 MiB is not read for a name.
func TestDirIgnoresOversizedPackageJSON(t *testing.T) {
	root := filepath.Join(t.TempDir(), "demo")
	writeFile(t, filepath.Join(root, "package.json"), `{"name":"big","pad":"`+strings.Repeat("a", 1<<20)+`"}`)
	if a := dirArtifact(t, root); a.Name != "demo" {
		t.Errorf("oversized package.json was read: name %q", a.Name)
	}
}

// A SKILL.md symlinked to a file inside the folder is read through the link;
// the root may itself be reached through a symlink (macOS $TMPDIR).
func TestDirReadsSkillMdSymlinkedInsideFolder(t *testing.T) {
	root := filepath.Join(t.TempDir(), "demo")
	writeFile(t, filepath.Join(root, "body.md"), "---\nname: inner\ndescription: through the link\n---\n")
	if err := os.Symlink("body.md", filepath.Join(root, "SKILL.md")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	a := dirArtifact(t, root)
	if a.Type != artifact.TypeSkill || a.Name != "inner" || a.Description != "through the link" || len(a.Findings) != 0 {
		t.Errorf("in-folder symlinked SKILL.md not read: %+v", a)
	}
}
