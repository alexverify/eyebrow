package discover

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/alexverify/eyebrow/internal/app/ports"
	"github.com/alexverify/eyebrow/internal/domain/artifact"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func byName(arts []artifact.Artifact) map[string]artifact.Artifact {
	m := map[string]artifact.Artifact{}
	for _, a := range arts {
		m[a.Name] = a
	}
	return m
}

func TestClaudeCodeDiscoversMCPAndSkills(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".mcp.json"), `{
		"mcpServers": {
			"npm-srv":   { "command": "npx", "args": ["-y", "pkg@1.0.0"] },
			"local-srv": { "command": "./srv.sh" }
		}
	}`)
	writeFile(t, filepath.Join(dir, "srv.sh"), "#!/bin/sh\n")
	writeFile(t, filepath.Join(dir, ".claude", "skills", "demo", "SKILL.md"), "---\nname: demo\n---\nhi\n")

	c := NewClaudeCode()
	got, err := c.Discover(context.Background(), []ports.Scope{{Kind: "project", Path: dir}})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	m := byName(got)
	if len(got) != 3 {
		t.Fatalf("want 3 artifacts, got %d: %+v", len(got), got)
	}
	if m["npm-srv"].Source.Kind != artifact.SourceNPM || m["npm-srv"].Tool != "claude-code" {
		t.Errorf("npm-srv wrong: %+v", m["npm-srv"].Source)
	}
	if m["demo"].Type != artifact.TypeSkill {
		t.Errorf("demo should be a skill: %+v", m["demo"])
	}
}
