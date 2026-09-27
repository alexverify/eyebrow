package discover

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/alexverify/eyebrow/internal/domain/artifact"
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
